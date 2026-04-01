#include "client.h"
#include "login_server.h"
#include "encryption.h"
#include "account_management.h"
#include "common/http/httplib.h"
#include "common/json/json.h"

extern LoginServer server;

Client::Client(std::shared_ptr<EQStreamInterface> c, LSClientVersion v)
{
	m_connection              = c;
	m_client_version          = v;
	m_client_status           = cs_not_sent_session_ready;
	m_account_id              = 0;
	m_selected_play_server_id = 0;
	m_play_sequence_id        = 0;
}

bool Client::Process()
{
	EQApplicationPacket *app = m_connection->PopPacket();
	while (app) {
		auto o = m_connection->GetOpcodeManager();
		LogPacketClientServer(
			"[{}] [{:#06x}] Size [{}] {}",
			OpcodeManager::EmuToName(app->GetOpcode()),
			o->EmuToEQ(app->GetOpcode()) == 0 ? app->GetProtocolOpcode() : o->EmuToEQ(app->GetOpcode()),
			app->Size(),
			(EQEmuLogSys::Instance()->IsLogEnabled(Logs::Detail, Logs::PacketClientServer) ? DumpPacketToString(app) : "")
		);

		if (m_client_status == cs_failed_to_login) {
			delete app;
			app = m_connection->PopPacket();
			continue;
		}

		switch (app->GetOpcode()) {
			case OP_SessionReady: {
				LogInfo("Session ready received from client account {}", GetClientLoggingDescription());
				HandleSessionReady((const char *) app->pBuffer, app->Size());
				break;
			}
			case OP_Login: {
				if (app->Size() < 20) {
					LogError("Login received but it is too small, discarding");
					break;
				}

				LogInfo("Login received from client {}", GetClientLoggingDescription());

				HandleLogin((const char *) app->pBuffer, app->Size());
				break;
			}
			case OP_ServerListRequest: {
				if (app->Size() < 4) {
					LogError("Server List Request received but it is too small, discarding");
					break;
				}

				LogInfo("Server list request received from client {}", GetClientLoggingDescription());

				SendServerListPacket(*(uint32_t *) app->pBuffer);
				break;
			}
			case OP_PlayEverquestRequest: {
				if (app->Size() < sizeof(PlayEverquestRequest)) {
					LogError("Play received but it is too small, discarding");
					break;
				}

				SendPlayToWorld((const char *) app->pBuffer);
				break;
			}
		}

		delete app;
		app = m_connection->PopPacket();
	}

	return true;
}

void Client::HandleSessionReady(const char *data, unsigned int size)
{
	if (m_client_status != cs_not_sent_session_ready) {
		LogError("Session ready received again after already being received");
		return;
	}

	if (size < sizeof(unsigned int)) {
		LogError("Session ready was too small");
		return;
	}

	m_client_status = cs_waiting_for_login;

	auto *outapp = new EQApplicationPacket(OP_ChatMessage, sizeof(LoginHandShakeReply));
	auto buf     = reinterpret_cast<LoginHandShakeReply *>(outapp->pBuffer);
	buf->base_header.sequence    = 0x02;
	buf->base_reply.success      = true;
	buf->base_reply.error_str_id = 0x65; // 101 "No Error"

	m_connection->QueuePacket(outapp);
	delete outapp;
}

void Client::HandleLogin(const char *data, unsigned int size)
{
	if (m_client_status != cs_waiting_for_login) {
		LogError("Login received after already having logged in");
		return;
	}

	// login user/pass are variable length after unencrypted opcode and base message header (size includes opcode)
	constexpr int header_size = sizeof(uint16_t) + sizeof(LoginBaseMessage);
	int           data_size   = size - header_size;

	if (size <= header_size) {
		LogError("Login received packet of size: {}, this would cause a buffer overflow, discarding", size);

		return;
	}

	if (data_size % 8 != 0) {
		LogError("Login received packet of size: {}, this would cause a block corruption, discarding", size);

		return;
	}

	unsigned int db_account_id = 0;

	std::string db_loginserver = "local";
	if (std::getenv("LSPX")) {
		db_loginserver = "eqemu";
	}

	std::string outbuffer;
	outbuffer.resize(data_size);
	if (outbuffer.empty()) {
		LogError("Corrupt buffer sent to server, no length");
		return;
	}

	// data starts at base message header (opcode not included)
	auto r = eqcrypt_block(data + sizeof(LoginBaseMessage), data_size, &outbuffer[0], false);
	if (r == nullptr) {
		LogError("Failed to decrypt eqcrypt block");
		return;
	}

	std::string cred;

	std::string user(&outbuffer[0]);
	if (user.length() >= outbuffer.length()) {
		LogError("Corrupt buffer sent to server, preventing buffer overflow");
		return;
	}

//	std::cout << "User: " << user << std::endl;

	// only need to copy the base header for reply options, ignore login info
	memcpy(&m_login_base_message, data, sizeof(LoginBaseMessage));

//	std::cout << "Seq: " << m_login_base_message.sequence << std::endl;
//	std::cout << "compressed: " << m_login_base_message.compressed << std::endl;
//	std::cout << "encrypt_type: " << m_login_base_message.encrypt_type << std::endl;
//	std::cout << "unk3: " << m_login_base_message.unk3 << std::endl;

	bool login_success = false;
	bool token_login   = outbuffer[0] == 0 && outbuffer[1] == 0;
	if (token_login) {
		if (server.options.IsTokenLoginAllowed()) {
			cred          = (&outbuffer[2 + user.length()]);
			// todo: implement token login
			// SELECT login_server, username, account_id FROM login_tickets WHERE expires > NOW() AND id='{}' AND ip_address='{}' LIMIT 1
//			login_success ? DoSuccessfulLogin(user, db_account_id, db_loginserver) : SendFailedLogin();
			SendFailedLogin();
		}

		return;
	}

	// normal login
	cred = (&outbuffer[1 + user.length()]);
	auto components = Strings::Split(user, ':');
	if (components.size() == 2) {
		db_loginserver = components[0];
		user           = components[1];
	}

	// health checks
	if (ProcessHealthCheck(user)) {
		SendFailedLogin();
		return;
	}

	LogInfo(
		"Attempting password based login [{}] login [{}]",
		user,
		db_loginserver
	);

	ParseAccountString(user, user, db_loginserver);

	LoginAccountContext c = {};
	c.username           = user;
	c.password           = cred;
	c.source_loginserver = db_loginserver;

	auto a = LoginAccountsRepository::GetAccountFromContext(database, c);
	if (a.id > 0) {
		login_success = VerifyAndUpdateLoginHash(c, a);

		// if user updated their password on the login server, update it here by validating their credentials with the login server
		if (std::getenv("LSPX") && !login_success && db_loginserver == "eqemu") {
			LogInfo("LSPX | Attempting login account via [{}]", db_loginserver);
			uint32 account_id = AccountManagement::CheckExternalLoginserverUserCredentials(c);
			LogInfo("LSPX | External login account id [{}]", account_id);
			if (account_id > 0) {
				auto updated_account = LoginAccountsRepository::UpdateAccountPassword(database, a, cred);
				if (!updated_account.id) {
					LogError("Failed to update eqemu account [{}] password hash", account_id);
					SendFailedLogin();
					return;
				}

				LogInfo("Updating eqemu account [{}] password hash", account_id);
				DoSuccessfulLogin(updated_account);
				return;
			}
		}

		LogInfo("Successful login [{}]", (login_success ? "true" : "false"));
		login_success ? DoSuccessfulLogin(a) : SendFailedLogin();
		return;
	}

	// if we are here, the account does not exist
	m_client_status = cs_creating_account;
	AttemptLoginAccountCreation(c);
}

void Client::SendPlayToWorld(const char *data)
{
	if (m_client_status != cs_logged_in) {
		LogError("Client sent a play request when they were not logged in, discarding");
		return;
	}

	const auto *play        = (const PlayEverquestRequest *) data;
	auto       server_id_in = (unsigned int) play->server_number;
	auto       sequence_in  = (unsigned int) play->base_header.sequence;

	LogInfo(
		"[SendPlayToWorld] Play received from client [{}] server number [{}] sequence [{}]",
		GetAccountName(),
		server_id_in,
		sequence_in
	);

	m_selected_play_server_id = (unsigned int) play->server_number;
	m_play_sequence_id        = sequence_in;
	m_selected_play_server_id = server_id_in;

	// Check if this server is in our live connected list
	bool is_local = std::any_of(
		server.server_manager->GetWorldServers().begin(),
		server.server_manager->GetWorldServers().end(),
		[&](const std::unique_ptr<WorldServer> &s) {
			return s->GetServerId() == server_id_in;
		}
	);

	if (is_local) {
		server.server_manager->SendUserLoginToWorldRequest(server_id_in, m_account_id, m_loginserver_name);
		return;
	}

	// Server not connected locally — try federated auth forwarding
	LogInfo("[SendPlayToWorld] Server [{}] not local, attempting federation auth forward", server_id_in);
	HandleFederatedPlay(server_id_in);
}

void Client::HandleFederatedPlay(unsigned int server_id)
{
	// Look up the federation source node for this server
	auto results = database.QueryDatabase(fmt::format(
		"SELECT lws.federation_source_node_id, fn.endpoint_url "
		"FROM login_world_servers lws "
		"JOIN federation_nodes fn ON fn.id = lws.federation_source_node_id "
		"WHERE lws.id = {} AND lws.federation_source_node_id > 0 "
		"LIMIT 1",
		server_id
	));

	if (!results.Success() || results.RowCount() == 0) {
		LogError("Federation play: server [{}] not found as federated server", server_id);
		SendPlayFailed();
		return;
	}

	auto row = results.begin();
	std::string endpoint_url = row[1] ? row[1] : "";
	if (endpoint_url.empty()) {
		LogError("Federation play: no endpoint URL for server [{}]", server_id);
		SendPlayFailed();
		return;
	}

	// Get the master's original server ID for this server
	// The federated server's original ID on the master may differ from local ID
	// We need to find it by short_name on the master — but for now, use the
	// web app proxy which handles the mapping
	auto srv_results = database.QueryDatabase(fmt::format(
		"SELECT short_name FROM login_world_servers WHERE id = {} LIMIT 1", server_id
	));
	std::string short_name;
	if (srv_results.Success() && srv_results.RowCount() > 0) {
		auto srv_row = srv_results.begin();
		short_name = srv_row[0] ? srv_row[0] : "";
	}

	LogInfo(
		"Federation play: forwarding auth for account [{}] ({}) to master [{}] for server [{}] ({})",
		GetAccountName(), m_account_id, endpoint_url, short_name, server_id
	);

	// Build the auth request JSON
	Json::Value req_body;
	req_body["server_short_name"] = short_name;
	req_body["account_id"]        = m_account_id;
	req_body["account_name"]      = GetAccountName();
	req_body["login_key"]         = m_key;
	req_body["loginserver_name"]  = m_loginserver_name;

	in_addr client_in{};
	client_in.s_addr = m_connection->GetRemoteIP();
	req_body["client_ip"] = std::string(inet_ntoa(client_in));

	std::stringstream body_ss;
	body_ss << req_body;
	std::string body_str = body_ss.str();

	// Call the local web app to proxy the federation auth request
	std::string web_host = server.config.GetVariableString("federation", "web_host", "web");
	int         web_port = server.config.GetVariableInt("federation", "web_port", 3000);

	try {
		httplib::Client cli(web_host, web_port);
		cli.set_connection_timeout(5, 0);
		cli.set_read_timeout(10, 0);

		auto result = cli.Post(
			"/api/internal/federation-play",
			body_str,
			"application/json"
		);

		if (result && result->status == 200) {
			LogInfo("Federation play: auth forwarded successfully for account [{}]", GetAccountName());
			SendPlaySuccess();
		} else {
			int status = result ? result->status : 0;
			std::string err_body = result ? result->body : "no response";
			LogError("Federation play: forward failed status [{}] body [{}]", status, err_body);
			SendPlayFailed();
		}
	} catch (const std::exception &e) {
		LogError("Federation play: HTTP error: {}", e.what());
		SendPlayFailed();
	}
}

void Client::SendPlaySuccess()
{
	auto *outapp = new EQApplicationPacket(OP_PlayEverquestResponse, sizeof(PlayEverquestResponse));
	auto *play   = (PlayEverquestResponse *) outapp->pBuffer;
	play->base_header.sequence = m_play_sequence_id;
	play->server_number        = m_selected_play_server_id;
	play->base_reply.success      = true;
	play->base_reply.error_str_id = LS::ErrStr::ERROR_NONE;

	LogInfo("Sending federated play success for {}", GetClientLoggingDescription());
	m_connection->QueuePacket(outapp);
	delete outapp;
}

void Client::SendPlayFailed()
{
	auto *outapp = new EQApplicationPacket(OP_PlayEverquestResponse, sizeof(PlayEverquestResponse));
	auto *play   = (PlayEverquestResponse *) outapp->pBuffer;
	play->base_header.sequence = m_play_sequence_id;
	play->server_number        = m_selected_play_server_id;
	play->base_reply.success      = false;
	play->base_reply.error_str_id = LS::ErrStr::ERROR_SERVER_UNAVAILABLE;

	LogInfo("Sending federated play failed for {}", GetClientLoggingDescription());
	m_connection->QueuePacket(outapp);
	delete outapp;
}

void Client::SendServerListPacket(uint32 seq)
{
	auto app = server.server_manager->CreateServerListPacket(this, seq);

	m_connection->QueuePacket(app.get());
}

void Client::SendPlayResponse(EQApplicationPacket *outapp)
{
	LogInfo("Sending play response for {}", GetClientLoggingDescription());
	m_connection->QueuePacket(outapp);
}

void Client::GenerateRandomLoginKey()
{
	m_key.clear();
	int count = 0;
	while (count < 10) {
		static const char key_selection[] =
							  {
								  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								  'Y', 'Z', '0', '1', '2', '3', '4', '5',
								  '6', '7', '8', '9'
							  };

		m_key.append((const char *) &key_selection[m_random.Int(0, 35)], 1);
		count++;
	}
}

void Client::AttemptLoginAccountCreation(LoginAccountContext c)
{
	LogInfo("user [{}] loginserver [{}]", c.username, c.source_loginserver);

	if (std::getenv("LSPX") && c.source_loginserver == "eqemu") {
		LogInfo("LSPX | Attempting login account creation via [{}]", c.source_loginserver);

		uint32 account_id = AccountManagement::CheckExternalLoginserverUserCredentials(c);
		c.login_account_id = account_id;
		if (account_id > 0) {
			LogInfo("LSPX | Found and creating eqemu account [{}]", account_id);
			auto a = LoginAccountsRepository::CreateAccountFromContext(database, c);
			if (a.id > 0) {
				DoSuccessfulLogin(a);
				return;
			}
		}

		LogInfo("LSPX | External authentication failed for user [{}]", c.username);

		SendFailedLogin();
		return;
	}

	if (server.options.CanAutoCreateAccounts() && c.source_loginserver == "local") {
		LogInfo("CanAutoCreateAccounts enabled, attempting to crate account [{}]", c.username);
		auto a = LoginAccountsRepository::CreateAccountFromContext(database, c);
		if (a.id > 0) {
			DoSuccessfulLogin(a);
			return;
		}

		return;
	}

	SendFailedLogin();
}

void Client::SendFailedLogin()
{
	m_stored_username.clear();
	m_stored_password.clear();

	// unencrypted
	LoginBaseMessage h{};
	h.sequence     = m_login_base_message.sequence; // login (3)
	h.encrypt_type = m_login_base_message.encrypt_type;

	// encrypted
	PlayerLoginReply r{};
	r.base_reply.success      = false;
	r.base_reply.error_str_id = 105; // Error - The username and/or password were not valid

	char encrypted_buffer[80] = {0};
	auto rc                   = eqcrypt_block((const char *) &r, sizeof(r), encrypted_buffer, 1);
	if (rc == nullptr) {
		LogDebug("Failed to encrypt eqcrypt block for failed login");
	}

	constexpr int       outsize = sizeof(LoginBaseMessage) + sizeof(encrypted_buffer);
	EQApplicationPacket outapp(OP_LoginAccepted, outsize);
	outapp.WriteData(&h, sizeof(h));
	outapp.WriteData(&encrypted_buffer, sizeof(encrypted_buffer));

	m_connection->QueuePacket(&outapp);
	m_client_status = cs_failed_to_login;
}

bool Client::VerifyAndUpdateLoginHash(LoginAccountContext c, const LoginAccountsRepository::LoginAccounts &a)
{
	auto encryption_mode = server.options.GetEncryptionMode();
	if (eqcrypt_verify_hash(a.account_name, c.password, a.account_password, encryption_mode)) {
		return true;
	}

	if (encryption_mode < EncryptionModeArgon2) {
		encryption_mode = EncryptionModeArgon2;
	}

	uint32 insecure_source_encryption_mode = 0;

	auto verify_encryption_mode = [&](int start, int end) {
		for (int i = start; i <= end; ++i) {
			if (i != encryption_mode && eqcrypt_verify_hash(a.account_name, c.password, a.account_password, i)) {
				insecure_source_encryption_mode = i;
			}
		}
	};

	switch (a.account_password.length()) {
		case CryptoHash::md5_hash_length:
			verify_encryption_mode(EncryptionModeMD5, EncryptionModeMD5Triple);
			break;
		case CryptoHash::sha1_hash_length:
			if (insecure_source_encryption_mode == 0) {
				verify_encryption_mode(EncryptionModeSHA, EncryptionModeSHATriple);
			}
			break;
		case CryptoHash::sha512_hash_length:
			if (insecure_source_encryption_mode == 0) {
				verify_encryption_mode(EncryptionModeSHA512, EncryptionModeSHA512Triple);
			}
			break;
	}

	if (insecure_source_encryption_mode > 0) {
		LogInfo(
			"Updated insecure password user [{}] loginserver [{}] from mode [{}] ({}) to mode [{}] ({})",
			c.username,
			c.source_loginserver,
			GetEncryptionByModeId(insecure_source_encryption_mode),
			insecure_source_encryption_mode,
			GetEncryptionByModeId(encryption_mode),
			encryption_mode
		);

		LoginAccountsRepository::UpdateAccountPassword(database, a, c.password);

		return true;
	}

	return false;
}

void Client::DoSuccessfulLogin(LoginAccountsRepository::LoginAccounts &a)
{
	m_stored_username.clear();
	m_stored_password.clear();

	LogInfo(
		"Successful login for user id [{}] account name [{}] login server [{}]",
		a.id,
		a.account_name,
		a.source_loginserver
	);

	server.client_manager->RemoveExistingClient(a.id, a.source_loginserver);

	in_addr in{};
	in.s_addr = m_connection->GetRemoteIP();

	a.last_ip_address = std::string(inet_ntoa(in));
	LoginAccountsRepository::UpdateOne(database, a);

	GenerateRandomLoginKey();

	m_account_id       = a.id;
	m_account_name     = a.account_name;
	m_loginserver_name = a.source_loginserver;

	// unencrypted
	LoginBaseMessage h{};
	h.sequence     = m_login_base_message.sequence;
	h.compressed   = false;
	h.encrypt_type = m_login_base_message.encrypt_type;
	h.unk3         = m_login_base_message.unk3;

	// not serializing any of the variable length strings so just use struct directly
	PlayerLoginReply r{};
	r.base_reply.success         = true;
	r.base_reply.error_str_id    = 101; // No Error
	r.unk1                       = 0;
	r.unk2                       = 0;
	r.lsid                       = a.id;
	r.failed_attempts            = 0;
	r.show_player_count          = server.options.IsShowPlayerCountEnabled();
	r.offer_min_days             = 99;
	r.offer_min_views            = -1;
	r.offer_cooldown_minutes     = 0;
	r.web_offer_number           = 0;
	r.web_offer_min_days         = 99;
	r.web_offer_min_views        = -1;
	r.web_offer_cooldown_minutes = 0;
	memcpy(r.key, m_key.c_str(), m_key.size());

	SendExpansionPacketData(r);

	char encrypted_buffer[80] = {0};

	auto rc = eqcrypt_block((const char *) &r, sizeof(r), encrypted_buffer, 1);
	if (rc == nullptr) {
		LogDebug("Failed to encrypt eqcrypt block");
	}

	constexpr int outsize = sizeof(LoginBaseMessage) + sizeof(encrypted_buffer);
	auto          outapp  = std::make_unique<EQApplicationPacket>(OP_LoginAccepted, outsize);
	outapp->WriteData(&h, sizeof(h));
	outapp->WriteData(&encrypted_buffer, sizeof(encrypted_buffer));

	m_connection->QueuePacket(outapp.get());

	m_client_status = cs_logged_in;
}

void Client::SendExpansionPacketData(PlayerLoginReply &plrs)
{
	SerializeBuffer buf;
	//from eqlsstr_us.txt id of each expansion, excluding 'Everquest'

	int ExpansionLookup[20] = {
		3007, 3008, 3009, 3010, 3012,
		3014, 3031, 3033, 3036, 3040,
		3045, 3046, 3047, 3514, 3516,
		3518, 3520, 3522, 3524
	};

	if (server.options.IsDisplayExpansions()) {

		int32_t expansion       = server.options.GetMaxExpansions();
		int32_t owned_expansion = (expansion << 1) | 1;

		if (m_client_version == cv_sod) {

			// header info of packet.  Requires OP_LoginExpansionPacketData=0x0031 to be in login_opcodes_sod.conf
			buf.WriteInt32(0x00);
			buf.WriteInt32(0x01);
			buf.WriteInt16(0x00);
			buf.WriteInt32(19); //number of expansions to include in packet

			//generate expansion data
			for (int i = 0; i < 19; i++) {
				buf.WriteInt32(i);                                                    //sequenctial number
				buf.WriteInt32((expansion & (1 << i)) == (1 << i) ? 0x01 : 0x00);    //1 own 0 not own
				buf.WriteInt8(0x00);
				buf.WriteInt32(ExpansionLookup[i]);                                    //from eqlsstr_us.txt
				buf.WriteInt32(0x179E);                                                //from eqlsstr_us.txt for buttons/order
				buf.WriteInt32(0xFFFFFFFF);                                            //end identification
				buf.WriteInt8(0x0);                                                    //force order window to appear 1 appear 0 not appear
				buf.WriteInt8(0x0);
				buf.WriteInt32(0x0000);
				buf.WriteInt32(0x0000);
				buf.WriteInt32(0xFFFFFFFF);
			}

			auto out = std::make_unique<EQApplicationPacket>(OP_LoginExpansionPacketData, buf);
			m_connection->QueuePacket(out.get());

		}
		else if (m_client_version == cv_titanium) {
			if (expansion >= EQ::expansions::bitPoR) {
				// Titanium shipped with 10 expansions.  Set owned expansions to be max 10.
				plrs.offer_min_days = ((EQ::expansions::bitDoD << 2) | 1) - 2;
			}
			else {
				plrs.offer_min_days = owned_expansion;
			}
			// Titanium shipped with 10 expansions.  Set owned expansions to be max 10.
			plrs.web_offer_min_views = ((EQ::expansions::bitDoD << 2) | 1) - 2;
		}
	}
}

std::string Client::GetClientLoggingDescription()
{
	in_addr in{};
	in.s_addr = GetConnection()->GetRemoteIP();
	std::string client_ip = inet_ntoa(in);

	return fmt::format(
		"account_name [{}] account_id ({}) ip_address [{}]",
		GetAccountName(),
		GetAccountID(),
		client_ip
	);
}
