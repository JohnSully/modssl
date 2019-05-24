CXX_OBJS := patch.o
C_OBJS := ssl.o adlist.o


%.o: %.c
	gcc -c $< -fPIC

%.o: %.cpp
	g++ -c $< -fPIC

modssl.so: $(CXX_OBJS) $(C_OBJS)
	g++ -o $@ $^ -shared

clean:
	rm -f $(CXX_OBJS)
	rm -f $(C_OBJS)
	rm modssl.so


