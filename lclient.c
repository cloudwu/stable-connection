#include <lua.h>
#include <lauxlib.h>

#include "connectionclient.h"

static struct connection *
get_self(lua_State *L) {
	struct connection ** c = lua_touserdata(L, 1);
	if (c == NULL || *c == NULL) {
		luaL_error(L, "Need connection object");
	}
	return *c;
}

static int
lcclose(lua_State *L) {
	struct connection *c = get_self(L);
	cc_close(c);
	struct connection ** cc = lua_touserdata(L, 1);
	*cc = NULL;
	return 0;
}

static int
lsend(lua_State *L) {
	struct connection *c = get_self(L);
	size_t sz = 0;
	const char * buffer = luaL_checklstring(L, 2, &sz);
	cc_send(c, buffer, sz);
	return 0;
}

static int
lrecv(lua_State *L) {
	struct connection *c = get_self(L);
	size_t sz = 0;
	const char * buffer = luaL_checklstring(L, 2, &sz);
	cc_recv(c, buffer, sz);
	return 0;
}

static int
lpoll(lua_State *L) {
	struct connection *c = get_self(L);
	struct connection_message msg;
	int t = cc_poll(c, &msg);
	if (t == MESSAGE_EMPTY) {
		return 0;
	}
	lua_pushinteger(L, t);
	lua_pushlstring(L, msg.buffer, msg.sz);
	return 2;
}

static int
lfetch(lua_State* L) {
	struct connection *c = get_self(L);
	struct connection_message msg;
	int t = cc_fetch(c, &msg);
	if (t == MESSAGE_EMPTY) {
		return 0;
	}
	lua_pushinteger(L, t);
	lua_pushlstring(L, msg.buffer, msg.sz);
	return 2;
}

static int
lhandshake(lua_State *L) {
	struct connection *c = get_self(L);
	cc_handshake(c);
	return 0;
}

static int
lclient(lua_State *L) {
	struct connection ** c = lua_newuserdata(L, sizeof(struct connection *));
	if (luaL_newmetatable(L, "socketclient")) {
		luaL_Reg l[] = {
			{ "handshake", lhandshake },
			{ "send", lsend },
			{ "recv", lrecv },
			{ "poll", lpoll },
			{ "fetch", lfetch },
			{ NULL, NULL },
		};
		luaL_newlib(L,l);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, lcclose);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	*c = cc_open();

	return 1;
}

int
luaopen_lsocket_client(lua_State *L) {
	lua_pushcfunction(L, lclient);

	return 1;
}
