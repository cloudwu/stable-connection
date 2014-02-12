sctest : connectionserver.c connectionclient.c encrypt.c test.c
	gcc -o $@ $^ -g -Wall
