#include "connectionserver.h"
#include "connectionclient.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static void
dump(const char * str, size_t sz, const char * buffer) {
	printf("%s (%d) ",str, (int)sz);
	size_t i;
	for (i=0;i<sz;i++) {
		uint8_t c = (uint8_t)(buffer[i]);
		printf("%02x ", c);
	}
	printf("\n");
}

static int
dispatch_client(struct connection_pool * server, struct connection * client) {
	int n = 0;
	for (;;) {
		struct connection_message m;
		int type = cc_poll(client, &m);
		if (type == MESSAGE_EMPTY)
			return n;
		if (type == MESSAGE_IN) {
			dump("C <-", m.sz, m.buffer);
		} else {
			cp_recv(server, 0, m.buffer, m.sz);
		}
		++n;
	}
}

static int
dispatch_server(struct connection_pool * server, struct connection * client) {
	int id = -1;
	int n = 0;
	for (;;) {
		struct pool_message m;
		int type = cp_poll(server, &m);
		if (type == POOL_EMPTY) {
			break;
		}
		if (type == POOL_IN) {
			printf("[%d] ", m.id);
			dump("S <-", m.sz, m.buffer);
			id = m.id;
		} else {
			cc_recv(client, m.buffer, m.sz);
		}
		++n;
	}
	if (id>=0) {
		cp_send(server, id, (const char *)&n , 4);
	}
	return n;
}

static void
dispatch(struct connection_pool * server, struct connection * client) {
	for (;;) {
		int n =	dispatch_client(server,client);
		n += dispatch_server(server,client);
		if (n==0)
			return;
	}
}

static void
send_client(struct connection *client, int n) {
	uint8_t *buffer = malloc(n);
	int i;
	for (i=0;i<n;i++) {
		buffer[i] = (uint8_t)i;
	}
	cc_send(client, (const char *)buffer, n);
	free(buffer);
}

static void
close_client(struct connection_pool *server, struct connection * client) {
	cc_handshake(client);
	cp_recv(server, 0, NULL, 0);
}

static void
test(struct connection_pool * server) {
	struct connection * client = cc_open();
	send_client(client, 10);
	dispatch(server, client);
	send_client(client, 400);
	dispatch(server, client);
	close_client(server, client);
	dispatch(server, client);
	send_client(client, 500);
	dispatch(server, client);

	cc_close(client);
}

int
main() {
	struct connection_pool * server = cp_new();

	test(server);

	cp_delete(server);

	return 0;
}
