#include "ssl.h"
#include <unordered_map>

#define C_OK                    0
#define C_ERR                   -1

client* (*createClientHost)(int) = nullptr;

extern void freeClient(client *);



extern "C" client *createClientWrapper(int fd)
{
	client *c = createClientHost(fd);
	if (c != nullptr)
	{
		int res = setupSslOnClient(c, fd, SSL_PERFORMANCE_MODE_DEFAULT);
		if (res == C_ERR)
		{
			freeClient(c);
			return nullptr;
		}
	}
	return c;
}
