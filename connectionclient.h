#ifndef connection_client_h
#define connection_client_h

#include <stddef.h>

struct connection;

struct connection_message {
	int sz;
	const char * buffer;
};

struct connection * cc_open();
void cc_close(struct connection *);
void cc_handshake(struct connection *);

void cc_send(struct connection *, const char * buffer, size_t sz);
void cc_recv(struct connection *, const char * buffer, size_t sz);

#define MESSAGE_EMPTY 0
#define MESSAGE_IN 1
#define MESSAGE_OUT 2

int cc_poll(struct connection *, struct connection_message *);

#endif
