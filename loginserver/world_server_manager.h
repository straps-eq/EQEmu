#pragma once

#include "common/net/servertalk_server.h"
#include "common/packet_dump.h"
#include "loginserver/client.h"
#include "loginserver/world_server.h"

#include <list>
#include <vector>
#include <chrono>

// Represents a world server synced from a federation peer (not directly connected)
struct FederatedServer {
	uint32_t    id;                    // login_world_servers.id (local copy)
	std::string long_name;
	std::string short_name;
	int32_t     server_list_type_id;
	std::string remote_ip;
	uint32_t    players_online;
	int         server_status;
	uint32_t    zones_booted;
	uint32_t    federation_source_node_id;
};

class WorldServerManager {
public:
	WorldServerManager();
	~WorldServerManager();
	void SendUserLoginToWorldRequest(
		unsigned int server_id,
		unsigned int client_account_id,
		const std::string &client_loginserver
	);
	std::unique_ptr<EQApplicationPacket> CreateServerListPacket(Client *client, uint32 sequence);
	bool DoesServerExist(const std::string &s, const std::string &server_short_name, WorldServer *ignore = nullptr);
	void DestroyServerByName(std::string s, std::string server_short_name, WorldServer *ignore = nullptr);
	const std::list<std::unique_ptr<WorldServer>> &GetWorldServers() const;

	// Federation: send ClientAuth to a world server on behalf of a remote mesh node
	bool SendFederatedClientAuth(
		uint32_t server_id,
		uint32_t account_id,
		const std::string &account_name,
		const std::string &login_key,
		const std::string &loginserver_name,
		const std::string &client_ip
	);

private:
	void RefreshFederatedServers();

	std::unique_ptr<EQ::Net::ServertalkServer> m_server_connection;
	std::list<std::unique_ptr<WorldServer>>    m_world_servers;

	// Cached federated servers from DB (refreshed periodically)
	std::vector<FederatedServer>                            m_federated_servers;
	std::chrono::steady_clock::time_point                   m_federated_servers_last_refresh;
	static constexpr std::chrono::seconds FEDERATED_CACHE_TTL{30};
};
