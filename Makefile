lsocket : connectionserver.c connectionclient.c encrypt.c lsocket.c lclient.c lserver.c
	gcc -fPIC --shared -o lsocket.so $^ -g -Wall -I/usr/local/include

sctest : connectionserver.c connectionclient.c encrypt.c test.c
	gcc -o $@ $^ -g -Wall
