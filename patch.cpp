#include <unordered_map>
#include <subhook.h>

struct ssl_connection;

std::unordered_map<int, ssl_connection*> g_mapsslconn;

extern "C" ssl_connection *fd_to_sslconn(int fd)
{
	auto itr = g_mapsslconn.find(fd);
	if (itr == g_mapsslconn.end())
		return NULL;
	return itr->second;
}

extern "C" void set_sslconn(int fd, ssl_connection *conn)
{
	g_mapsslconn[fd] = conn;
}
