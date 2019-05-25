CXX_OBJS := patch.o
C_OBJS := ssl.o adlist.o

FLAGS := -Isubmodules/s2n/api -fPIC

%.o: %.c
	gcc -c $< $(FLAGS)

%.o: %.cpp
	g++ -c $< $(FLAGS)

modssl.so: s2n.dummy $(CXX_OBJS) $(C_OBJS)
	g++ -o $@ $^ -shared

s2n.dummy: 
	cd submodules/s2n && make bin
	touch s2n.dummy

depclean: clean
	cd submodules/s2n && make clean
	rm -f s2n.dummy

clean:
	rm -f $(CXX_OBJS)
	rm -f $(C_OBJS)
	rm -f modssl.so


