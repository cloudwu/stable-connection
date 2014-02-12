#ifndef connection_server_h
#define connection_server_h

#include <stddef.h>

struct connection_pool;

struct pool_message {
	int id;
	size_t sz;
	const char *buffer;
};

struct connection_pool * cp_new();
void cp_delete(struct connection_pool *cp);
void cp_timeout(struct connection_pool *cp);

void cp_recv(struct connection_pool *cp, int fd, const char * buffer, size_t sz);
void cp_send(struct connection_pool *cp, int id, const char * buffer, size_t sz);

#define POOL_EMPTY 0
#define POOL_IN 1
#define POOL_OUT 2

int cp_poll(struct connection_pool *cp, struct pool_message *m);

#endif
