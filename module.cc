#include "ssl.h"
#define REDISMODULE_EXPERIMENTAL_API
#include "redismodule.h"
#include "release.h"
#include "hook.h"

#define REDISMODULE_OK 0
#define REDISMODULE_ERR 1

typedef client* (*t_createClient)(int);
extern ssl_t g_ssl_config;

#ifdef __cplusplus
extern "C" 
#endif

ssize_t sslRead(int fd, void *buffer, size_t nbytes);
ssize_t sslWrite(int fd, const void *buffer, size_t nbytes);
int sslClose(int fd);
void sslPing(int fd);
const char *sslStrerror(int err);

int readHandler(int fd, void *buf, size_t cb, ssize_t *pccbRead)
{
	if (isSSLFd(fd))
	{
		*pccbRead = sslRead(fd, buf, cb);
		return 1;
	}
	return 0;	// unhandled
}

int writeHandler(int fd, const void *buf, size_t cb, ssize_t *pccbWrite)
{
	if (isSSLFd(fd))
	{
		*pccbWrite = sslWrite(fd, buf, cb);
		return 1;
	}
	return 0;
}


int OnFDEvent(int fd, enum MODULE_FD_EVENT evt, void (*fnAfter)(int, uint64_t), uint64_t arg)
{
	switch (evt)
	{
		default:
			return 0;	// event not handled

		case MODULE_FD_CLOSE:
		{
			if (isSSLFd(fd))
			{
				sslClose(fd);
				return 1;
			}
			return 0;
		}

		case MODULE_FD_ACCEPT:
		{
			SslEventAfterHandler *after = malloc(sizeof(after));
			after->fn = fnAfter;
			after->arg = arg;
			if (setupSslOnFd(fd, SSL_PERFORMANCE_MODE_DEFAULT, after) == C_ERR)
			{
				close(fd);
			}
			else
			{
				RedisModule_RegisterFdRdFilter(fd, readHandler);
				RedisModule_RegisterFdWrFilter(fd, writeHandler);
			}
			return 1;
		}
	}
}

#if 0
client *createClientWrapper(int fd)
{
	client *c = ((t_createClient)subhook_get_trampoline(g_hookCreateClient))(fd);
	if (fd >= 0 && c != NULL)
	{
		if (isSSLFd(fd))
		{
			// SSL is already established, just setup the event to read from client
			aeDeleteFileEvent(server.el, fd, AE_READABLE|AE_WRITABLE);
			if (aeCreateFileEvent(server.el, fd, AE_READABLE|AE_READ_THREADSAFE, readQueryFromClient, c) == AE_ERR) {
				freeClient(c);
				return NULL;                        
			}
			return c;
		}
		aeDeleteFileEvent(server.el,fd,AE_READABLE);	// delete the default readQueryFromClient that is setup
		int res = setupSslOnClient(c, fd, SSL_PERFORMANCE_MODE_DEFAULT);
		if (res == C_ERR)
		{
			freeClient(c);
			return NULL;
		}
	}
	return c;
}
#endif

#include <sys/syscall.h>
#include <asm/unistd.h>
const char *__redis_wrap_strerror(int err) {
    if (isSSLEnabled()) {
        return sslStrerror(err);
    } else {
        return 
			((const char*(*)(int))subhook_get_trampoline(g_hookstrerr))(err);
    }
}

int FInitializeDetours()
{
#define SETHOOK(hook, src, dst) \
	do { \
		hook = subhook_new((void*)src, (void*)dst, SUBHOOK_64BIT_OFFSET); \
		if (hook == NULL) goto LFail; \
		if (subhook_install(hook) < 0) goto LFail; \
	} while(0)

	RedisModule_RegisterFdEventFilter(OnFDEvent);
	SETHOOK(g_hookstrerr, strerror, __redis_wrap_strerror);

	return 1;

#undef NEWHOOK
LFail:
	return 0;
}

int loadFile(const char *filePath, char **buffer) {
    serverLog(LL_VERBOSE, "Loading file: %s", filePath);
    FILE *fp;
    long lSize;

    fp = fopen(filePath, "rb");
    if (!fp) {
        serverLog(LL_WARNING, "Error opening file: %s", filePath);
        return C_ERR;
    }

    fseek(fp, 0L, SEEK_END);
    lSize = ftell(fp);
    rewind(fp);

    /* allocate memory for entire content */
    *buffer = (char*)malloc(lSize + 1);
    if (!*buffer) {
        fclose(fp);
        serverLog(LL_WARNING, "memory alloc fails while loading file: %s", filePath);
        return C_ERR;
    }

    /* copy the file into the buffer */
    if (1 != fread(*buffer, lSize, 1, fp)) {
        fclose(fp);
        free(*buffer);
        *buffer=NULL;
        serverLog(LL_WARNING, "entire read fails while loading file: %s", filePath);
        return C_ERR;
    }
    *(*buffer+lSize) = '\0';
    fclose(fp);
    return C_OK;
}

char *dupModuleString(RedisModuleString *str)
{
	size_t len;
	const char *src = RedisModule_StringPtrLen(str, &len);
	char *sz = (char*)malloc(len+1);
	memcpy(sz, src, len);
	sz[len] = '\0';
	return sz;
}

#ifdef __cplusplus
extern "C"
#endif
int RedisModule_OnLoad(RedisModuleCtx *ctx, RedisModuleString **argv, int argc)
{
	const char *err = NULL;
	size_t lenT;
	if (argc != 3)
	{
		serverLog(LL_WARNING, "modssl epected args: [certificate-file] [private-key-file] [dh-params-file]");
		return REDISMODULE_ERR;
	}
	if (strcmp(REDIS_GIT_SHA1, redisGitSHA1()) != 0)
	{
		serverLog(LL_WARNING, "modssl must be compiled with the exact redis headers for your version.");
		return REDISMODULE_ERR;
	}

	++fInSsl;
	RedisModule_Init(ctx, "modssl", 1, 1);

	initSslConfigDefaults(&g_ssl_config);
	/* Load Config Files */
	g_ssl_config.ssl_certificate_file = dupModuleString(argv[0]);
	if(loadFile(g_ssl_config.ssl_certificate_file, &g_ssl_config.ssl_certificate) == -1){
		err = "Error loading ssl certificate file";
		goto loaderr;
	}

	g_ssl_config.ssl_certificate_private_key_file = dupModuleString(argv[1]);
	if(loadFile(g_ssl_config.ssl_certificate_private_key_file, &g_ssl_config.ssl_certificate_private_key) == -1){
		err = "Error loading private key file";
		goto loaderr;
	}

	g_ssl_config.ssl_dh_params_file = dupModuleString(argv[2]);
	if(loadFile(g_ssl_config.ssl_dh_params_file, &g_ssl_config.ssl_dh_params) == -1){
		err = "Error loading Diffie Hellman parameters file";
		goto loaderr;
	}

	if (g_ssl_config.root_ca_certs_path == NULL) {
        /* Use default ca certs path if not specified */
        g_ssl_config.root_ca_certs_path = (char*)ROOT_CA_CERTS_PATH;
    }

	initSsl(&g_ssl_config);

	if (!FInitializeDetours())
	{
		serverLog(LL_WARNING, "modssl failed to install detours.");
		return REDISMODULE_ERR;
	}
	
	--fInSsl;
	return REDISMODULE_OK;

loaderr:
	serverLog(LL_WARNING, "%s", err);
	return REDISMODULE_ERR;
}

