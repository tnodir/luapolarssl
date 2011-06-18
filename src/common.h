#ifndef COMMON_H
#define COMMON_H

#include <string.h>	/* memset, memchr */

#define LUA_LIB

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "luapolarssl.h"


#if LUA_VERSION_NUM < 502
#define lua_rawlen		lua_objlen
#define luaL_typeerror		luaL_typerror
#endif


#ifdef NO_CHECK_UDATA
#define checkudata(L,i,tname)	lua_touserdata(L, i)
#else
#define checkudata(L,i,tname)	luaL_checkudata(L, i, tname)
#endif

#define lua_boxpointer(L,u) \
    (*(void **) (lua_newuserdata(L, sizeof(void *))) = (u))
#define lua_unboxpointer(L,i,tname) \
    (*(void **) (checkudata(L, i, tname)))


/*
 * Error Reporting
 */

#define LSSL_ERROR_MESSAGE	"errorMessage"

static int lssl_seterror (lua_State *L, int err);


#endif
