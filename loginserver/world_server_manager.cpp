/*	EQEmu: EQEmulator

	Copyright (C) 2001-2026 EQEmu Development Team

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
#include "world_server_manager.h"

#include "common/eqemu_logsys.h"
#include "common/ip_util.h"
#include "loginserver/login_server.h"
#include "loginserver/login_types.h"

#include <algorithm>
#include <utility>
#include <vector>
#include <arpa/inet.h>

extern LoginServer server;
extern Database    database;
extern bool        run_server;

WorldServerManager::WorldServerManager()
{
	int listen_port = server.config.GetVariableInt("general", "listen_port", 5998);

	m_server_connection = std::make_unique<EQ::Net::ServertalkServer>();
	EQ::Net::ServertalkServerOptions opts;
	opts.port = listen_port;
	opts.ipv6 = false;
	m_server_connection->Listen(opts);

	LogInfo("Loginserver now listening on port [{}]", listen_port);

	m_server_connection->OnConnectionIdentified(
		"World", [this](std::shared_ptr<EQ::Net::ServertalkServerConnection> c) {
			LogInfo(
				"New World Server connection from remote_ip [{}] port [{}]",
				c->Handle()->RemoteIP(),
				c->Handle()->RemotePort()
			);

			auto iter = std::find_if(
				m_world_servers.begin(), m_world_servers.end(),
				[&](const std::unique_ptr<WorldServer> &s) {
					return s->GetConnection()->Handle()->RemoteIP() == c->Handle()->RemoteIP() &&
						   s->GetConnection()->Handle()->RemotePort() == c->Handle()->RemotePort();
				}
			);

			if (iter != m_world_servers.end()) {
				LogInfo(
					"World server already existed for remote_ip [{}] port [{}] removing existing connection.",
					c->Handle()->RemoteIP(),
					c->Handle()->RemotePort()
				);

				m_world_servers.erase(iter);
			}

			m_world_servers.push_back(std::make_unique<WorldServer>(c));
		}
	);

	m_server_connection->OnConnectionRemoved(
		"World", [this](std::shared_ptr<EQ::Net::ServertalkServerConnection> c) {
			auto iter = std::find_if(
				m_world_servers.begin(), m_world_servers.end(),
				[&](const std::unique_ptr<WorldServer> &server) {
					return server->GetConnection()->GetUUID() == c->GetUUID();
				}
			);

			if (iter != m_world_servers.end()) {
				LogInfo(
					"World server ID [{}] long_name [{}] short_name [{}] has been disconnected, removing.",
					(*iter)->GetServerId(),
					(*iter)->GetServerLongName(),
					(*iter)->GetServerShortName()
				);
				m_world_servers.erase(iter);
			}
		}
	);

}

WorldServerManager::~WorldServerManager() = default;

std::unique_ptr<EQApplicationPacket> WorldServerManager::CreateServerListPacket(Client *client, uint32 sequence)
{
	unsigned int server_count = 0;
	in_addr      in{};
	in.s_addr = client->GetConnection()->GetRemoteIP();
	std::string client_ip = inet_ntoa(in);

	LogDebug("ServerManager::CreateServerListPacket via client address [{}]", client_ip);

	for (const auto &world_server: m_world_servers) {
		if (world_server->IsAuthorizedToList()) {
			++server_count;
		}
	}

	// Refresh federated servers from DB (cached with TTL)
	RefreshFederatedServers();
	server_count += static_cast<unsigned int>(m_federated_servers.size());

	SerializeBuffer buf;

	// LoginBaseMessage_Struct header
	buf.WriteInt32(sequence);
	buf.WriteInt8(0);
	buf.WriteInt8(0);
	buf.WriteInt32(0);

	// LoginBaseReplyMessage_Struct
	buf.WriteInt8(true);  // success (no error)
	buf.WriteInt32(0x65); // 101 "No Error" eqlsstr
	buf.WriteString("");

	// ServerListReply_Struct
	buf.WriteInt32(server_count);

	struct ListEntry {
		uint32                 players;
		const WorldServer     *world;
		bool                   use_local_ip;
		const FederatedServer *federated;
	};
	std::vector<ListEntry> entries;
	entries.reserve(server_count);

	for (const auto &s: m_world_servers) {
		if (!s->IsAuthorizedToList()) {
			LogDebug(
				"ServerManager::CreateServerListPacket | Server [{}] via IP [{}] is not authorized to be listed",
				s->GetServerLongName(),
				s->GetConnection()->Handle()->RemoteIP()
			);
			continue;
		}

		bool use_local_ip = false;

		std::string world_ip = s->GetConnection()->Handle()->RemoteIP();
		if (world_ip == client_ip || IpUtil::IsIpInPrivateRfc1918(client_ip)) {
			use_local_ip = true;
		}

		LogDebug(
			"CreateServerListPacket | Building list entry | Client [{}] IP [{}] Server Long Name [{}] Server IP [{}] ({})",
			client->GetAccountName(),
			client_ip,
			s->GetServerLongName(),
			use_local_ip ? s->GetLocalIP() : s->GetRemoteIP(),
			use_local_ip ? "Local" : "Remote"
		);

		entries.push_back({s->GetPlayersOnline(), s.get(), use_local_ip, nullptr});
	}

	// Federated servers (synced from federation peers, not directly connected)
	for (const auto &fs: m_federated_servers) {
		entries.push_back({fs.players_online, nullptr, false, &fs});
	}

	// The ToB server select has no Legends/Preferred grouping, so order it by population.
	// Older clients group by list type themselves and keep connection order.
	if (client->GetClientVersion() == cv_tob) {
		std::stable_sort(
			entries.begin(),
			entries.end(),
			[](const ListEntry &a, const ListEntry &b) { return a.players > b.players; }
		);
	}

	for (const auto &e: entries) {
		if (e.world) {
			e.world->SerializeForClientServerList(buf, e.use_local_ip, client->GetClientVersion());
			continue;
		}

		const auto &fs = *e.federated;
		LogDebug(
			"CreateServerListPacket | Federated server [{}] IP [{}] players [{}] from node [{}]",
			fs.long_name,
			fs.remote_ip,
			fs.players_online,
			fs.federation_source_node_id
		);

		// Must stay byte-compatible with WorldServer::SerializeForClientServerList
		if (client->GetClientVersion() == cv_tob) {
			buf.WriteString(fs.remote_ip);
			buf.WriteInt32(9000); // port, not currently settable in eqemu but needed for compat

			switch (fs.server_list_type_id) {
				case LS::ServerType::Legends:
					buf.WriteInt32(LS::ServerTypeFlags::Legends);
					break;
				case LS::ServerType::Preferred:
					buf.WriteInt32(LS::ServerTypeFlags::Preferred);
					break;
				default:
					buf.WriteInt32(LS::ServerTypeFlags::Standard);
					break;
			}

			buf.WriteInt32(289); // unknown, matches upstream
			buf.WriteUInt32(fs.id);

			buf.WriteString(fs.long_name);
			buf.WriteString("US"); // country code
			buf.WriteString("EN"); // language code
			buf.WriteString("Standard");
			buf.WriteString("This server has no description set currently.");

			if (fs.server_status < 0) {
				buf.WriteInt32(fs.zones_booted == 0 ? LS::ServerStatusFlags::Down : LS::ServerStatusFlags::Locked);
			} else {
				buf.WriteInt32(LS::ServerStatusFlags::Up);
			}

			buf.WriteUInt32(fs.players_online);
			buf.WriteInt32(31); // expansions
			buf.WriteInt32(0);  // truebox
		}
		else {
			buf.WriteString(fs.remote_ip);

			switch (fs.server_list_type_id) {
				case LS::ServerType::Legends:
					buf.WriteInt32(LS::ServerTypeFlags::Legends);
					break;
				case LS::ServerType::Preferred:
					buf.WriteInt32(LS::ServerTypeFlags::Preferred);
					break;
				default:
					buf.WriteInt32(LS::ServerTypeFlags::Standard);
					break;
			}

			buf.WriteUInt32(fs.id);

			buf.WriteString(fs.long_name);
			buf.WriteString("us");
			buf.WriteString("en");

			if (fs.server_status < 0) {
				buf.WriteInt32(fs.zones_booted == 0 ? LS::ServerStatusFlags::Down : LS::ServerStatusFlags::Locked);
			} else {
				buf.WriteInt32(LS::ServerStatusFlags::Up);
			}

			buf.WriteUInt32(fs.players_online);
		}
	}

	return std::make_unique<EQApplicationPacket>(OP_ServerListResponse, buf);
}

void WorldServerManager::SendUserLoginToWorldRequest(
	unsigned int server_id,
	unsigned int client_account_id,
	const std::string &client_loginserver
)
{
	auto iter = std::find_if(
		m_world_servers.begin(), m_world_servers.end(),
		[&](const std::unique_ptr<WorldServer> &server) {
			return server->GetServerId() == server_id;
		}
	);

	if (iter != m_world_servers.end()) {
		EQ::Net::DynamicPacket outapp;
		outapp.Resize(sizeof(UsertoWorldRequest));

		auto *r = reinterpret_cast<UsertoWorldRequest *>(outapp.Data());
		r->worldid     = server_id;
		r->lsaccountid = client_account_id;
		strncpy(r->login, client_loginserver.c_str(), 64);

		(*iter)->GetConnection()->Send(ServerOP_UsertoWorldReq, outapp);

		LogNetcode("[UsertoWorldRequest] [Size: {}]\n{}", outapp.Length(), outapp.ToString());
	}
	else {
		LogError("Client requested a user to world but supplied an invalid id of {}", server_id);
	}
}

bool WorldServerManager::DoesServerExist(
	const std::string &server_long_name,
	const std::string &server_short_name,
	WorldServer *ignore
)
{
	return std::any_of(
		m_world_servers.begin(), m_world_servers.end(), [&](const std::unique_ptr<WorldServer> &s) {
			return s.get() != ignore &&
				   s->GetServerLongName() == server_long_name &&
				   s->GetServerShortName() == server_short_name;
		}
	);
}

void WorldServerManager::DestroyServerByName(
	std::string server_long_name,
	std::string server_short_name,
	WorldServer *ignore
)
{
	std::erase_if(
		m_world_servers, [&](const std::unique_ptr<WorldServer> &s) {
			if (s.get() == ignore) {
				return false;
			}
			if (s->GetServerLongName() == server_long_name &&
				s->GetServerShortName() == server_short_name) {
				s->GetConnection()->Handle()->Disconnect();
				LogInfo(
					"Removing world server ID [{}] long name [{}] short name [{}]",
					s->GetServerId(),
					server_long_name,
					server_short_name
				);
				return true;
			}
			return false;
		}
	);
}

const std::list<std::unique_ptr<WorldServer>> &WorldServerManager::GetWorldServers() const
{
	return m_world_servers;
}

void WorldServerManager::RefreshFederatedServers()
{
	auto now = std::chrono::steady_clock::now();
	if (now - m_federated_servers_last_refresh < FEDERATED_CACHE_TTL) {
		return;
	}
	m_federated_servers_last_refresh = now;
	m_federated_servers.clear();

	try {
		auto results = database.QueryDatabase(
			"SELECT lws.id, lws.long_name, lws.short_name, lws.login_server_list_type_id, "
			"       lws.federation_source_node_id, "
			"       COALESCE(fss.remote_ip, lws.last_ip_address, '') AS remote_ip, "
			"       COALESCE(fss.players_online, 0) AS players_online, "
			"       COALESCE(fss.server_status, 0) AS server_status, "
			"       COALESCE(fss.zones_booted, 0) AS zones_booted "
			"FROM login_world_servers lws "
			"LEFT JOIN federation_server_status fss ON fss.world_server_id = lws.id "
			"WHERE lws.federation_source_node_id > 0"
		);

		if (!results.Success()) {
			LogError("Federation: failed to query federated servers: {}", results.ErrorMessage());
			return;
		}

		for (auto row = results.begin(); row != results.end(); ++row) {
			FederatedServer fs;
			fs.id                        = std::stoul(row[0]);
			fs.long_name                 = row[1] ? row[1] : "";
			fs.short_name                = row[2] ? row[2] : "";
			fs.server_list_type_id       = std::stoi(row[3] ? row[3] : "0");
			fs.federation_source_node_id = std::stoul(row[4] ? row[4] : "0");
			fs.remote_ip                 = row[5] ? row[5] : "";
			fs.players_online            = std::stoul(row[6] ? row[6] : "0");
			fs.server_status             = std::stoi(row[7] ? row[7] : "0");
			fs.zones_booted              = std::stoul(row[8] ? row[8] : "0");

			// Skip servers already connected directly (duplicate prevention)
			bool is_connected = std::any_of(
				m_world_servers.begin(), m_world_servers.end(),
				[&](const std::unique_ptr<WorldServer> &ws) {
					return ws->GetServerShortName() == fs.short_name;
				}
			);
			if (is_connected) continue;

			// Skip if no IP (can't connect without it)
			if (fs.remote_ip.empty()) continue;

			m_federated_servers.push_back(std::move(fs));
		}

		if (!m_federated_servers.empty()) {
			LogInfo("Federation: loaded [{}] federated servers from DB", m_federated_servers.size());
		}
	} catch (const std::exception &e) {
		LogError("Federation: exception querying federated servers: {}", e.what());
	}
}

bool WorldServerManager::QueueFederatedClientAuth(
	uint32_t server_id,
	uint32_t account_id,
	const std::string &account_name,
	const std::string &login_key,
	const std::string &loginserver_name,
	const std::string &client_ip
)
{
	// Verify the server exists before queuing (read-only check, safe from any thread)
	auto iter = std::find_if(
		m_world_servers.begin(), m_world_servers.end(),
		[&](const std::unique_ptr<WorldServer> &s) {
			return s->GetServerId() == server_id;
		}
	);

	if (iter == m_world_servers.end()) {
		LogError("Federation auth_client: server_id [{}] not found in live server list", server_id);
		return false;
	}

	LogInfo(
		"Federation auth_client: queuing ClientAuth for account [{}] ({}) to server [{}] ({})",
		account_name, account_id, (*iter)->GetServerLongName(), server_id
	);

	// Queue for the main event loop thread to send (Send() is not thread-safe)
	{
		std::lock_guard<std::mutex> lock(m_federated_auth_mutex);
		m_pending_federated_auths.push({server_id, account_id, account_name, login_key, loginserver_name, client_ip});
	}

	return true;
}

void WorldServerManager::ProcessPendingFederatedAuths()
{
	std::queue<PendingFederatedAuth> pending;
	{
		std::lock_guard<std::mutex> lock(m_federated_auth_mutex);
		std::swap(pending, m_pending_federated_auths);
	}

	while (!pending.empty()) {
		auto auth = std::move(pending.front());
		pending.pop();
		SendFederatedClientAuth(auth);
	}
}

bool WorldServerManager::SendFederatedClientAuth(const PendingFederatedAuth &auth)
{
	auto iter = std::find_if(
		m_world_servers.begin(), m_world_servers.end(),
		[&](const std::unique_ptr<WorldServer> &s) {
			return s->GetServerId() == auth.server_id;
		}
	);

	if (iter == m_world_servers.end()) {
		LogError("Federation auth_client: server_id [{}] no longer in live server list", auth.server_id);
		return false;
	}

	LogInfo(
		"Federation auth_client: sending ClientAuth for account [{}] ({}) to server [{}] ({})",
		auth.account_name, auth.account_id, (*iter)->GetServerLongName(), auth.server_id
	);

	// Build ClientAuth packet
	EQ::Net::DynamicPacket outapp;
	ClientAuth a{};

	a.loginserver_account_id = auth.account_id;
	strncpy(a.account_name, auth.account_name.c_str(), 30);
	strncpy(a.key, auth.login_key.c_str(), 30);
	a.lsadmin        = 0;
	a.is_world_admin = 0;
	a.ip_address     = inet_addr(auth.client_ip.c_str());
	strncpy(a.loginserver_name, auth.loginserver_name.c_str(), 64);
	a.is_client_from_local_network = 0;

	outapp.PutSerialize(0, a);
	(*iter)->GetConnection()->Send(ServerOP_LSClientAuth, outapp);

	LogInfo("Federation auth_client: ClientAuth sent successfully for account [{}]", auth.account_name);
	return true;
}
