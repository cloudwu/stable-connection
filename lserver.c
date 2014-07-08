#include <lua.h>
#include <lauxlib.h>

#include "connectionserver.h"

static struct connection_pool *
get_self(lua_State *L) {
	struct connection_pool ** c = lua_touserdata(L, 1);
	if (c == NULL || *c == NULL) {
		luaL_error(L, "Need connection pool object");
	}
	return *c;
}

static int
lpclose(lua_State *L) {
	struct connection_pool *c = get_self(L);
	cp_delete(c);
	struct connection_pool ** cc = lua_touserdata(L, 1);
	*cc = NULL;
	return 0;
}

static int
lsend(lua_State *L) {
	struct connection_pool *c = get_self(L);
	int id = luaL_checkinteger(L, 2);
	size_t sz = 0;
	const char * buffer = luaL_checklstring(L, 3, &sz);
	if (sz == 0) {
		buffer = NULL;
	}
	cp_send(c, id, buffer, sz);
	return 0;
}

static int
lrecv(lua_State *L) {
	struct connection_pool *c = get_self(L);
	int fd = luaL_checkinteger(L, 2);
	size_t sz = 0;
	const char * buffer = luaL_checklstring(L, 3, &sz);
	if (sz == 0) {
		buffer = NULL;
	}
	cp_recv(c, fd, buffer, sz);
	return 0;
}

static int
lpoll(lua_State *L) {
	struct connection_pool *c = get_self(L);
	struct pool_message msg;
	int t = cp_poll(c, &msg);
	if (t == POOL_EMPTY) {
		return 0;
	}
	lua_pushinteger(L, t);
	lua_pushinteger(L, msg.id);
	lua_pushlstring(L, msg.buffer, msg.sz);
	return 3;
}

static int
lserver(lua_State *L) {
	struct connection_pool ** c = lua_newuserdata(L, sizeof(struct connection_pool *));
	if (luaL_newmetatable(L, "socketclient")) {
		luaL_Reg l[] = {
			{ "send", lsend },
			{ "recv", lrecv },
			{ "poll", lpoll },
			{ NULL, NULL },
		};
		luaL_newlib(L,l);
		lua_setfield(L, -2, "__index");
		lua_pushcfunction(L, lpclose);
		lua_setfield(L, -2, "__gc");
	}
	lua_setmetatable(L, -2);
	*c = cp_new();

	return 1;
}

int
luaopen_lsocket_server(lua_State *L) {
	lua_pushcfunction(L, lserver);

	return 1;
}
