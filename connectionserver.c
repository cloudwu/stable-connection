#include "connectionserver.h"
#include "encrypt.h"

#include <stdlib.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#define G 5
#define FINGERPRINTCHUNKSIZE 256
#define SENDCACHESIZE 65536
#define FDHASHSIZE 16383
#define MAXSOCKET 16384

struct handshake {
	int fd;
	int version;
	int sz;
	int closed;
	// 8 bytes index, 8 bytes A , 8 bytes auth
	uint8_t buffer[8+8+8];
	uint64_t secret;
	uint64_t challenge;
	uint64_t request;
	uint32_t id;
	struct handshake *next;
};

struct connection_handshake {
	int version;
	struct handshake * c[FDHASHSIZE];
};

struct connection {
	int next;
	uint32_t id;
	int fd;
	uint64_t secret;
	uint64_t recvcount;
	uint64_t sendcount;
	struct rc4_sbox sendbox;
	struct rc4_sbox recvbox;
	uint8_t sendbuffer[SENDCACHESIZE];
	uint32_t fingerprint[SENDCACHESIZE/FINGERPRINTCHUNKSIZE];
};

struct message {
	struct message *next;
	int id;
	size_t sz;
	uint8_t buffer[1];
};

struct connection_pool {
	struct connection_handshake ch;
	int idbase;
	// id -> connection *
	struct connection c[MAXSOCKET];
	// fd -> connection index
	int fd[FDHASHSIZE];

	struct message *in_head;
	struct message *in_tail;

	struct message *out_head;
	struct message *out_tail;

	struct message *temp;
};


static void
ch_init(struct connection_handshake *ch) {
	memset(ch,0,sizeof(*ch));
}

static void
ch_exit(struct connection_handshake *ch) {
	int i;
	for (i=0;i<FDHASHSIZE;i++) {
		struct handshake * hs = ch->c[i];
		while(hs) {
			struct handshake *tmp = hs->next;
			free(hs);
			hs = tmp;
		}
	}
}

struct connection_pool *
cp_new() {
	struct connection_pool * cp = malloc(sizeof(*cp));
	ch_init(&cp->ch);
	cp->idbase = 0;
	cp->in_head = NULL;
	cp->in_tail = NULL;
	cp->out_head = NULL;
	cp->out_tail = NULL;
	cp->temp = NULL;
	int i;
	for (i=0;i<MAXSOCKET;i++) {
		// 0 is invalid id
		cp->c[i].id = 0;
	}
	for (i=0;i<FDHASHSIZE;i++) {
		// -1 is nil index
		cp->fd[i] = -1;
	}
	return cp;
}

static void
release_message_queue(struct message * head) {
	while (head) {
		struct message * tmp = head->next;
		free(head);
		head = tmp;
	}
}

static struct message *
new_message(int id, size_t sz) {
	struct message * m = malloc(sizeof(*m) -1 + sz);
	m->id = id;
	m->sz = sz;
	m->next = NULL;

	return m;
}

static uint8_t *
new_inmessage(struct connection_pool *c, int id, size_t sz) {
	struct message *m = new_message(id, sz);
	if (c->in_tail) {
		c->in_tail->next = m;
		c->in_tail = m;
	} else {
		c->in_head = c->in_tail = m;
	}
	return m->buffer;
}

static uint8_t *
new_outmessage(struct connection_pool *c, int id, size_t sz) {
	struct message *m = new_message(id, sz);
	if (c->out_tail) {
		c->out_tail->next = m;
		c->out_tail = m;
	} else {
		c->out_head = c->out_tail = m;
	}
	return m->buffer;
}

void
cp_delete(struct connection_pool * cp) {
	// todo : add cp_close to close all fd
	if (cp == NULL)
		return;
	release_message_queue(cp->in_head);
	release_message_queue(cp->out_head);
	free(cp->temp);

	ch_exit(&cp->ch);
}

static struct connection *
find_by_id(struct connection_pool *cp, uint32_t id) {
	if (id == 0)
		return NULL;
	int slot = id % MAXSOCKET;
	struct connection * c = &cp->c[slot];
	if (c->id == id) {
		return c;
	}
	return NULL;
}

static struct connection *
find_by_fd(struct connection_pool *cp, int fd) {
	if (fd < 0)
		return NULL;
	int slot = fd % FDHASHSIZE;
	int index = cp->fd[slot];
	while(index >= 0) {
		struct connection *c = &cp->c[index];
		if (c->fd == fd) {
			return c;
		}
		index = c->next;
	}
	return NULL;
}

static void
remove_fd(struct connection_pool *cp, struct connection *c) {
	int fd = c->fd;
	if (fd < 0)
		return;
	c->fd = -1;
	fd %= FDHASHSIZE;
	int index = cp->fd[fd];
	struct connection *tmp = &cp->c[index];
	if (c == tmp) {
		cp->fd[fd] = tmp->next;
		tmp->next = -1;
		return;
	}
	while (tmp->next >= 0) {
		struct connection *next = &cp->c[tmp->next];
		if (c == next) {
			tmp->next = c->next;
			c->next = -1;
			return;
		}
		tmp = next;
	}
	assert(0);
}

static void
insert_fd(struct connection_pool *cp, struct connection *c) {
	int fd = c->fd;
	assert(fd >= 0);
	fd %= FDHASHSIZE;
	c->next = cp->fd[fd];
	int index = c->id % MAXSOCKET;
	assert(index == c - cp->c);
	cp->fd[fd] = index;
}

static struct connection *
match_connection(struct connection_pool *cp, struct handshake *hs) {
	struct connection * c= find_by_id(cp, hs->id);
	assert(c);
	remove_fd(cp, c);
	c->fd = hs->fd;
	insert_fd(cp, c);

	uint32_t bytes = (uint32_t)(c->sendcount - hs->request);
	assert(bytes <= SENDCACHESIZE);
	
	if (bytes > 0) {
		uint8_t * buffer = new_outmessage(cp, c->id, bytes);
		uint32_t ptr = (uint32_t)(c->sendcount % SENDCACHESIZE);
		if (bytes <= ptr) {
			memcpy(buffer, c->sendbuffer + ptr-bytes, bytes);
		} else {
			int s = bytes - ptr;
			memcpy(buffer, c->sendbuffer + SENDCACHESIZE - s, s);
			memcpy(buffer + s, c->sendbuffer + s, bytes - s);
		}
	}

	return c;
}

static struct connection *
new_connection(struct connection_pool *cp, struct handshake *hs) {
	int i;
	for (i=0;i<MAXSOCKET;i++) {
		uint32_t id = ++cp->idbase;
		if (id == 0) {
			id = ++cp->idbase;
		}
		int slot = id % MAXSOCKET;
		struct connection * c = &cp->c[slot];
		if (c->id == 0) {
			c->id = id;
			c->fd = hs->fd;
			insert_fd(cp, c);
			c->secret = hs->secret;
			c->recvcount = 0;
			c->sendcount = 0;
			c->fingerprint[0] = rc4_init(&c->sendbox, c->secret);
			rc4_init(&c->recvbox, c->secret);

			return c;
		}
	}
	return NULL;
}

static struct handshake *
handshake_newfd(struct connection_handshake *ch,int fd) {
	int slot = fd % FDHASHSIZE;
	struct handshake * hs = malloc(sizeof(*hs));
	hs->id = 0;
	hs->closed = 0;
	hs->fd = fd;
	hs->version = ch->version;
	hs->sz = 0;
	hs->next = ch->c[slot];

	ch->c[slot] = hs;

	return hs;
}

static struct handshake *
handshake_getfd(struct connection_handshake *ch, int fd) {
	int slot = fd % FDHASHSIZE;
	struct handshake * c = ch->c[slot];
	while (c) {
		if (c->fd == fd)
			return c;
		c = c->next;
	}
	return handshake_newfd(ch, fd);
}

static void
handshake_delete(struct connection_handshake *ch, struct handshake *hs) {
	int slot = hs->fd % FDHASHSIZE;
	struct handshake *t = ch->c[slot];
	if (t == hs) {
		ch->c[slot] = hs->next;
		free(hs);
		return;
	}
	while (t->next) {
		if (t->next == hs) {
			t->next = hs->next;
			free(hs);
			return;
		}
		t=t->next;
	}
	assert(0);
}

static uint32_t
leuint32(const uint8_t * t) {
	return t[0] | t[1] << 8 | t[2] << 16 | t[3] << 24;
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
handshake_kick(struct connection_pool *cp, struct handshake *hs) {
	assert(hs->closed == 0);
	hs->closed = 1;
	new_outmessage(cp, hs->fd, 0);
}

static int
handshake_auth(struct connection_pool *cp, struct handshake *hs, const uint8_t *buffer, size_t sz, int offset) {
	int need = offset + 8 - hs->sz;
	if (sz < need) {
		memcpy(hs->buffer + hs->sz, buffer, sz);
		hs->sz += sz;
		return 0;
	}
	memcpy(hs->buffer + hs->sz, buffer, need);
	hs->sz += need;

	uint64_t code = leuint64(&hs->buffer[offset]);
	uint64_t authcode = hmac(hs->challenge, hs->secret);

	if (code == authcode) {
		return need;
	} else {
		handshake_kick(cp, hs);
		return 0;
	}
}

static int
handshake_new(struct connection_pool *cp, struct handshake *hs, const uint8_t *buffer, size_t sz) {
	if (hs->sz < 16) {
		int need = 16-hs->sz;
		if (sz > need) {
			// invalid handshake package
			// close fd
			handshake_kick(cp, hs);
			return 0;
		}
		if (sz < need) {
			memcpy(hs->buffer + hs->sz, buffer, sz);
			hs->sz += hs->sz;
			return 0;
		}
		memcpy(hs->buffer + hs->sz, buffer, need);
		hs->sz += need;
		sz -= need;
		buffer += need;

		assert(hs->sz == 16);

		// D-H key exchange

		uint64_t B = leuint64(&hs->buffer[8]);		
		uint64_t a = randomint64();
		uint64_t A = powmodp(G, a);
		hs->secret = powmodp(B,a);
		hs->challenge = randomint64();

		uint8_t *outbuffer = new_outmessage(cp, hs->fd, 16);
		uint64le(outbuffer,A);
		uint64le(outbuffer+8,hs->challenge);

		return 0;
	}
	
	return handshake_auth(cp, hs, buffer, sz, 16);
}

static struct connection *
connection_match(struct connection_pool *cp, uint64_t request_count, uint32_t fingerprint) {
	int i;
	for (i=0;i<MAXSOCKET;i++) {
		struct connection *c = &cp->c[i];
		if (c->id == 0)
			continue;
		if (request_count > c->sendcount || request_count + SENDCACHESIZE < c->sendcount)
			continue;
		int index = request_count % SENDCACHESIZE / FINGERPRINTCHUNKSIZE;
		if (c->fingerprint[index] == fingerprint)
			return c;
	}
	return NULL;
}

static int
handshake_reuse(struct connection_pool *cp, struct handshake *hs, const uint8_t *buffer, size_t sz) {
	if (hs->sz < 12) {
		int need = 12-hs->sz;
		if (sz > need) {
			// invalid handshake package
			// close fd
			handshake_kick(cp, hs);
			return 0;
		}
		if (sz < need) {
			memcpy(hs->buffer + hs->sz, buffer, sz);
			hs->sz += hs->sz;
			return 0;
		}
		memcpy(hs->buffer + hs->sz, buffer, need);
		hs->sz += need;
		sz -= need;
		buffer += need;
		assert(hs->sz == 12);

		// match connection
		uint32_t fingerprint = leuint32(hs->buffer + 8);
		struct connection * c = connection_match(cp, hs->request, fingerprint);
		if (c == NULL) {
			handshake_kick(cp, hs);
		} else {
			hs->secret = c->secret;
			hs->id = c->id;
			hs->challenge = randomint64();

			uint8_t *outbuffer = new_outmessage(cp, hs->fd, 16);
			uint64le(outbuffer,c->recvcount);
			uint64le(outbuffer+8,hs->challenge);
		}
		return 0;
	}

	return handshake_auth(cp, hs, buffer, sz, 12);
}

// return n > 0 , use n bytes
// return n == 0, not end
static int
handshake_recv(struct connection_pool *cp, struct handshake *hs, const uint8_t *buffer, size_t sz) {
	if (hs->closed)
		return 0;
	if (sz == 0) {
		// client close handshake
		handshake_kick(cp, hs);
		return 0;
	}

	if (hs->sz < 8) {
		// request sendcount (uint64_t)
		int need = 8-hs->sz;
		if (sz < need) {
			memcpy(hs->buffer + hs->sz, buffer, sz);
			hs->sz += hs->sz;
			return 0;
		}
		memcpy(hs->buffer + hs->sz, buffer, need);
		hs->sz += need;
		sz -= need;
		buffer += need;
	}
	hs->request = leuint64(hs->buffer);
	if (hs->request == 0) {
		return handshake_new(cp, hs, buffer, sz);
	} else {
		return handshake_reuse(cp, hs, buffer, sz);
	}
}

void 
cp_recv(struct connection_pool *cp, int fd, const char * buffer, size_t sz) {
	struct connection *c = find_by_fd(cp, fd);
	if (c == NULL) {
		// handshake
		struct handshake * hs = handshake_getfd(&cp->ch, fd);
		int n = handshake_recv(cp, hs, (const uint8_t *)buffer, sz);
		if (n == 0) {
			// handshake not end
			return;
		}
		if (hs->id == 0) {
			c = new_connection(cp, hs);
		} else {
			c = match_connection(cp, hs);
		}
		handshake_delete(&cp->ch, hs);
		if (c == NULL) {
			// connect failed, close handshake
			new_outmessage(cp, c->fd, 0);
			return;
		}
		sz -= n;
		if (sz == 0)
			return;
		buffer += n;
	}
	if (sz == 0) {
		// client close fd
		remove_fd(cp,c);
	} else {
		uint8_t * inbuffer = new_inmessage(cp, c->id, sz);
		rc4_encode(&c->recvbox, (const uint8_t *)buffer, inbuffer, sz);
		c->recvcount += sz;
	}
}

static void
connection_close(struct connection_pool *cp, struct connection *c) {
	int fd = c->fd;
	if (fd >= 0) {
		remove_fd(cp, c);
		new_outmessage(cp, fd, 0);
	}
	c->id = 0;
}

static inline uint32_t
send_bytes(struct connection *c, const char * src, uint8_t *output, int sz) {
	uint32_t r = rc4_encode(&c->sendbox, (const uint8_t *)src, output, sz);
	if (output) {
		int offset = c->sendcount % SENDCACHESIZE;
		assert(SENDCACHESIZE - offset >= sz);
		memcpy(c->sendbuffer+offset,output,sz);
	}
	c->sendcount += sz;
	return r;
}

static inline void
mark_fingerprint(struct connection *c, uint32_t fingerprint) {
	int index = c->sendcount % SENDCACHESIZE;
	index /= FINGERPRINTCHUNKSIZE;
	c->fingerprint[index] = fingerprint;
}

void
cp_send(struct connection_pool *cp, int id, const char *buffer, size_t sz) {
	struct connection *c = find_by_id(cp, id);
	if (c == NULL)
		return;
	if (sz == 0) {
		// close id
		connection_close(cp, c);
		return;
	}
	uint8_t * output = NULL;
	if (c->fd >= 0) {
		output = new_outmessage(cp, c->fd, sz);
	} else {
		// remote client closed
		return;
	}
	int head = c->sendcount % FINGERPRINTCHUNKSIZE;
	if (head > 0) {
		head = FINGERPRINTCHUNKSIZE - head;
		if (head > sz) {
			send_bytes(c, buffer, output, sz);
			return;
		}
		uint32_t fingerprint = send_bytes(c, buffer, output, head);
		mark_fingerprint(c, fingerprint);
		buffer += head;
		sz -= head;
		if (output)
			output += head;
	}
	if (sz <= FINGERPRINTCHUNKSIZE) {
		uint32_t fingerprint = send_bytes(c, buffer, output, sz);
		if (sz == FINGERPRINTCHUNKSIZE)
			mark_fingerprint(c, fingerprint);
		return;
	}
	size_t i;
	for (i=0;i<sz-FINGERPRINTCHUNKSIZE;i+=FINGERPRINTCHUNKSIZE) {
		uint32_t fingerprint = send_bytes(c, buffer, output, FINGERPRINTCHUNKSIZE);
		mark_fingerprint(c, fingerprint);
		buffer += FINGERPRINTCHUNKSIZE;
		if (output)
			output += FINGERPRINTCHUNKSIZE;
	}
	uint32_t fingerprint = send_bytes(c, buffer, output, sz - i);
	if (sz - i == FINGERPRINTCHUNKSIZE)
		mark_fingerprint(c, fingerprint);
}

static void
close_fd(struct connection_pool *cp, int fd) {
	struct connection *c = find_by_fd(cp, fd);
	if (c) {
		remove_fd(cp, c);
		c->id = 0;
		return;
	}
	struct handshake *hs = handshake_getfd(&cp->ch, fd);
	handshake_delete(&cp->ch, hs);
}

static void
fill_message(struct connection_pool *c, struct pool_message *m) {
	m->sz = c->temp->sz;
	m->id = c->temp->id;
	if (m->sz == 0) {
		m->buffer = NULL;
	} else {
		m->buffer = (const char *)c->temp->buffer;
	}
}

int 
cp_poll(struct connection_pool *c, struct pool_message *m) {
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
		if (m->sz == 0) {
			close_fd(c, m->id);
		}
		return POOL_OUT;
	} 
	if (c->in_head) {
		c->temp = c->in_head;
		c->in_head = c->temp->next;
		if (c->in_head == NULL) {
			c->in_tail = NULL;
		}
		fill_message(c,m);
		return POOL_IN;
	}
	return POOL_EMPTY;
}

