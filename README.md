# modssl for [Redis](https://github.com/antirez/redis) and [KeyDB](https://github.com/JohnSully/KeyDB)
modssl is a demonstration of SSL support wrapped in a module.  Because Redis' module API is not quite powerful enough to support this it relies upon hot patching to replicate the missing APIs.
The goal of this project is to promote encryption and encourage expansion to the Redis module API.

modssl is based upon a PR by madolson for [adding SSL support to Redis](https://github.com/antirez/redis/pull/4855).

## Checkout and Compile
Compiling modssl requires the sources for the version of Redis or KeyDB which you intend to use it with.  Because modssl integrates more tightly than a regular module it may only be used with the exact version it was compiled with.

For Redis:

    git clone --recurse-submodules https://github.com/JohnSully/modssl.git 
    make REDIS_SRC=/path/to/redis/src
   
For KeyDB:

    git clone --recurse-submodules https://github.com/JohnSully/modssl.git 
    make REDIS_SRC=/path/to/redis/src KEYDB=1
    
# Running

Running modssl requires a certificate similar to what you would use with an HTTPS website.  For convenience a test certificate has been generated in the testcert folder.  You should generate your own before using modssl in production.

modssl is launched like any other module.  It requires 3 parameters: The certificate, the key, and the dh_params file.  For more information on generating these files see [SSL_README from the original patch](https://github.com/madolson/redis/blob/dev-unstable-ssl-original/SSL_README.md)

    ./keydb-server --loadmodule ~/repos/modssl/modssl.so \ 
        ~/repos/modssl/testcert/server.crt \
        ~/repos/modssl/testcert/server.key \
        ~/repos/modssl/testcert/dh_params.dh 
        
# SSL Client

The redis-cli client does not natively support SSL.  madolson has created a version in her repo which you can fetch here: https://github.com/madolson/redis/tree/dev-unstable-ssl-original

In order to compile this version follow the instructions here: https://github.com/madolson/redis/blob/dev-unstable-ssl-original/SSL_README.md

Once you have a client with SSL support built you can launch it with:

    ./redis-cli --ssl
