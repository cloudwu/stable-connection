#include "connectionclient.h"
#include "encrypt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define G 5
#define FINGERPRINTCHUNKSIZE 256
#define SENDCACHESIZE 65536
#define HANDSHAKE_HEADER 16

struct message {
	struct message *next;
	size_t sz;
	uint8_t buffer[1];
};

struct connection {
	int handshake_sz;
	// 8 bytes count/secret + 8 bytes challenge
	uint8_t handshake[HANDSHAKE_HEADER];

	uint64_t secret;
	uint64_t recvcount;
	uint64_t sendcount;
	struct rc4_sbox sendbox;
	struct rc4_sbox recvbox;
	uint8_t sendbuffer[SENDCACHESIZE];
	uint32_t fingerprint;

	struct message *temp;

	struct message *in_head;
	struct message *in_tail;

	struct message *out_head;
	struct message *out_tail;

	size_t send_sz;
	struct message *send_head;
	struct message *send_tail;
};

static void
free_message_queue(struct message *m) {
	while (m) {
		struct message *next = m->next;
		free(m);
		m = next;
	}
}

void
cc_close(struct connection *c) {
	if (c == NULL)
		return;
	free(c->temp);
	free_message_queue(c->in_head);
	free_message_queue(c->out_head);
	free_message_queue(c->send_head);
	free(c);
}

static struct message *
new_message(size_t sz) {
	struct message * m = malloc(sizeof(*m) -1 + sz);
	m->sz = sz;
	m->next = NULL;

	return m;
}

static uint64_t
leuint64(const uint8_t * t) {
	uint32_t x = t[0] | t[1] << 8 | t[2] << 16 | t[3] << 24;
	uint32_t y = t[4] | t[5] << 8 | t[6] << 16 | t[7] << 24;
	return (uint64_t)x | (uint64_t)y << 32;
}

static void
uint64le(uint8_t *t, uint64_t v) {
	t[0] = v & 0xff;
	t[1] = (v >>8) & 0xff;
	t[2] = (v >>16) & 0xff;
	t[3] = (v >>24) & 0xff;
	t[4] = (v >>32) & 0xff;
	t[5] = (v >>40) & 0xff;
	t[6] = (v >>48) & 0xff;
	t[7] = (v >>56) & 0xff;
}

static void
uint32le(uint8_t *t, uint32_t v) {
	t[0] = v & 0xff;
	t[1] = (v >>8) & 0xff;
	t[2] = (v >>16) & 0xff;
	t[3] = (v >>24) & 0xff;
}

static uint8_t *
new_inmessage(struct connection *c, size_t sz) {
	struct message *m = new_message(sz);
	if (c->in_tail) {
		c->in_tail->next = m;
		c->in_tail = m;
	} else {
		c->in_head = c->in_tail = m;
	}
	return m->buffer;
}

static uint8_t *
new_outmessage(struct connection *c, size_t sz) {
	struct message *m = new_message(sz);
	if (c->out_tail) {
		c->out_tail->next = m;
		c->out_tail = m;
	} else {
		c->out_head = c->out_tail = m;
	}
	return m->buffer;
}

static uint8_t *
new_sendmessage(struct connection *c, size_t sz) {
	struct message *m = new_message(sz);
	if (c->send_tail) {
		c->send_tail->next = m;
		c->send_tail = m;
	} else {
		c->send_head = c->send_tail = m;
	}
	c->send_sz += sz;
	return m->buffer;
}

void 
cc_handshake(struct connection *c) {
	c->handshake_sz = 0;
	// drop send queue
	free_message_queue(c->out_head);
	c->out_head = c->out_tail = NULL;
	// send new handshake message
	if (c->recvcount == 0) {
		c->secret = randomint64();
		// send 8 bytes count (0), 8 bytes secret
		uint8_t * outmessage = new_outmessage(c, 16);

		uint64le(outmessage, 0);
		uint64_t A = powmodp(G, c->secret);
		uint64le(outmessage+8, A);
	} else {
		// send 8 bytes count, 4 bytes fingerprint
		uint8_t * outmessage = new_outmessage(c, 12);
		uint64le(outmessage, c->recvcount);
		uint32le(outmessage+8, c->fingerprint);
	}
}

struct connection *
cc_open() {
	struct connection * c = malloc(sizeof(*c));
	c->handshake_sz = 0;
	c->recvcount = 0;
	c->temp = NULL;
	c->in_head = NULL;
	c->in_tail = NULL;
	c->out_head = NULL;
	c->out_tail = NULL;
	c->send_head = NULL;
	c->send_tail = NULL;
	c->send_sz = 0;

	cc_handshake(c);

	return c;
}

static void
drop_connection(struct connection *c) {
	new_inmessage(c,0);
	c->handshake_sz = -1;
}

static void
update_sendcache(struct connection *c, const uint8_t * temp, size_t sz) {
	c->sendcount += sz;
	if (sz > SENDCACHESIZE) {
		temp = temp + sz - SENDCACHESIZE;
		sz = SENDCACHESIZE;
	}
	int offset = c->sendcount % SENDCACHESIZE;
	if (sz <= offset) {
		memcpy(c->sendbuffer + offset - sz, temp, sz);
	} else {
		int part1 = sz - offset;
		memcpy(c->sendbuffer + SENDCACHESIZE - part1, temp, part1);
		memcpy(c->sendbuffer, temp + part1, sz - part1);
	}
}

static void
encode_send_message(struct connection *c, uint8_t * buffer) {
	struct message * m = c->send_head;
	while(m) {
		rc4_encode(&c->sendbox, m->buffer, buffer, m->sz);
		buffer += m->sz;
		m = m->next;
	}

	update_sendcache(c, buffer - c->send_sz, c->send_sz);

	c->send_head = c->send_tail = NULL;
	c->send_sz = 0;
}

static int
handshake(struct connection *c, const char *buffer, size_t sz) {
	int need = HANDSHAKE_HEADER - c->handshake_sz;
	if (sz < need) {
		memcpy(c->handshake + c->handshake_sz, buffer, sz);
		c->handshake_sz += sz;
		return 0;
	}
	c->handshake_sz = HANDSHAKE_HEADER;

	uint64_t B = leuint64((const uint8_t *)buffer);
	uint64_t challenge = leuint64((const uint8_t *)buffer+8);

	if (c->recvcount == 0) {
		// new connection
		c->secret = powmodp(B, c->secret);
		c->sendcount = 0;
		rc4_init(&c->sendbox, c->secret);
		c->fingerprint = rc4_init(&c->recvbox, c->secret);
		B = 0;
	} else {
		if (B > c->sendcount || B + SENDCACHESIZE < c->sendcount) {
			drop_connection(c);
			return 0;
		}
	}

	int bytes = (int)(c->sendcount - B);
	uint8_t * outbuffer = new_outmessage(c, 8 + bytes + c->send_sz);
	uint64_t authcode = hmac(challenge, c->secret);
	uint64le(outbuffer, authcode);
	outbuffer += 8;
	if (bytes > 0) {
		int offset = c->sendcount % SENDCACHESIZE;
		if (bytes <= offset) {
			memcpy(outbuffer, c->sendbuffer + offset-bytes, bytes);
		} else {
			int part1 = offset - bytes;
			memcpy(outbuffer, c->sendbuffer + SENDCACHESIZE - part1, part1);
			memcpy(outbuffer + part1, c->sendbuffer, offset);
		}
		outbuffer += bytes;
	}

	if (c->send_sz > 0) {
		encode_send_message(c, outbuffer);
	}

	return need;
}

void
cc_recv(struct connection *c, const char * buffer, size_t sz) {
	if (c->handshake_sz < 0) {
		// connection closed
		return;
	}
	if (sz == 0) {
		drop_connection(c);
		return;
	}
	if (c->handshake_sz < HANDSHAKE_HEADER) {
		int n = handshake(c, buffer, sz);
		if (n == 0)
			return;
		buffer += n;
		sz -= n;
	}
	if (sz > 0) {
		uint8_t * inmessage = new_inmessage(c, sz);
		int tail = (c->recvcount + sz) % FINGERPRINTCHUNKSIZE;
		if (tail > sz) {
			rc4_encode(&c->recvbox, (const uint8_t *)buffer, inmessage, sz);
		} else {
			size_t bytes = sz - tail;
			c->fingerprint = rc4_encode(&c->recvbox, (const uint8_t *)buffer, inmessage, bytes);
			rc4_encode(&c->recvbox, (const uint8_t *)buffer + bytes, inmessage + bytes, tail);
		}
		c->recvcount += sz;
	}
}

void
cc_send(struct connection *c, const char * buffer, size_t sz) {
	if (c->handshake_sz < 0) {
		return;
	}
	if (sz == 0) {
		// rehandshake
		cc_handshake(c);
		return;
	}
	if (c->handshake_sz < HANDSHAKE_HEADER) {
		// wait for handshake
		uint8_t * temp = new_sendmessage(c, sz);
		memcpy(temp, buffer, sz);
		return;
	}
	assert(c->send_head == NULL);
	uint8_t * temp = new_outmessage(c, sz);
	rc4_encode(&c->sendbox, (const uint8_t *)buffer, temp, sz);

	update_sendcache(c, temp, sz);
}

static void
do_fill_message(struct message *m, struct connection_message *cm) {
	cm->sz = m->sz;
	if (cm->sz == 0) {
		cm->buffer = NULL;
	} else {
		cm->buffer = (const char*)m->buffer;
	}
}
static void
fill_message(struct connection *c, struct connection_message *m) {
	do_fill_message(c->temp, m);
}

int 
cc_poll(struct connection *c, struct connection_message *m) {
	if (c->temp) {
		free(c->temp);
		c->temp = NULL;
	}
	if (c->out_head) {
		c->temp = c->out_head;
		c->out_head = c->temp->next;
		if (c->out_head == NULL) {
			c->out_tail = NULL;
		}
		fill_message(c,m);
		return MESSAGE_OUT;
	} 
	if (c->in_head) {
		c->temp = c->in_head;
		c->in_head = c->temp->next;
		if (c->in_head == NULL) {
			c->in_tail = NULL;
		}
		fill_message(c,m);
		return MESSAGE_IN;
	}
	return MESSAGE_EMPTY;
}

int
cc_fetch(struct connection *c, struct connection_message *m) {
	if (c->temp) {
		free(c->temp);
		c->temp = NULL;
	}
	if (c->out_head) {
		do_fill_message(c->out_head, m);
		return MESSAGE_OUT;
	} 
	if (c->in_head) {
		do_fill_message(c->in_head, m);
		return MESSAGE_IN;
	}
	return MESSAGE_EMPTY;
}
