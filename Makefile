CXX_OBJS := patch.o
C_OR_CPP_OBJS := ssl.o module.o
C_OBS := adlist.o

default: modssl.so


.PHONY:nopatherr
ifeq ($(REDIS_SRC),)
nopatherr:
	$(error "make REDIS_SRC=/path/to/redis/src/")
else
nopatherr: ;
endif

FLAGS := -Isubmodules/s2n/api -g -fPIC -I$(REDIS_SRC)/src -I$(REDIS_SRC)/deps/lua/src -Wno-deprecated-declarations -DBUILD_SSL=1 -Isubmodules/subhook/

ifeq ($(KEYDB),)
	CC_BUILD_FLAGS := -x c
else
	FLAGS := $(FLAGS) -DKEYDB=1
endif


%.o: %.c
	gcc -c $< $(FLAGS) -std=c11

%.o: %.cc
	g++ $(CC_BUILD_FLAGS) -c $< $(FLAGS)

%.o: %.cpp
	g++ -c $< $(FLAGS) -std=c++14

modssl.so: nopatherr s2n.dummy $(CXX_OBJS) $(C_OR_CPP_OBJS) $(C_OBJS)
	cp submodules/subhook/build/libsubhook.a ./
	g++ -o $@ $(CXX_OBJS) $(C_OBJS) $(C_OR_CPP_OBJS) -shared -lssl -lcrypto -Lsubmodules/s2n/build/lib/ -l:libs2n.a -L./ -lsubhook

s2n.dummy: 
	mkdir submodules/s2n/build
	cd submodules/s2n/build && cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=NO && make
	mkdir submodules/subhook/build
	cd submodules/subhook/build/ && cmake .. -DSUBHOOK_STATIC=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo
	cd submodules/subhook/build && make
	touch s2n.dummy

depclean: clean
	rm -rf submodules/s2n/build
	rm -rf submodules/subhook/build
	rm -f s2n.dummy

clean:
	rm -f *.o
	rm -f *.so
	rm -f *.a


