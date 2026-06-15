/*
 * np_lua.c — Lua scripting processor implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

#define LUA_NETPIPE_PROC_KEY "netpipe_processor"

typedef struct {
    lua_State *L;
    char       script_path[256];
    char       name[64];
    int        process_ref;
    int        init_ref;
    int        free_ref;
} lua_priv_t;

static int l_register_processor(lua_State *L)
{
    // Retrieve the np_processor_t pointer from registry
    lua_getfield(L, LUA_REGISTRYINDEX, LUA_NETPIPE_PROC_KEY);
    np_processor_t *proc = lua_touserdata(L, -1);
    lua_pop(L, 1);

    if (!proc) {
        return luaL_error(L, "NP_REGISTER_PROCESSOR called from invalid context");
    }

    lua_priv_t *priv = proc->priv;

    // The argument must be a table
    luaL_checktype(L, 1, LUA_TTABLE);

    // 1. Get name
    lua_getfield(L, 1, "name");
    const char *name = luaL_optstring(L, -1, "lua_processor");
    strncpy(priv->name, name, sizeof(priv->name) - 1);
    lua_pop(L, 1);

    // 2. Get process callback
    lua_getfield(L, 1, "process");
    if (!lua_isfunction(L, -1)) {
        return luaL_error(L, "NP_REGISTER_PROCESSOR table must contain a 'process' function");
    }
    priv->process_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // 3. Get init callback (optional)
    lua_getfield(L, 1, "init");
    if (lua_isfunction(L, -1)) {
        priv->init_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    // 4. Get free callback (optional)
    lua_getfield(L, 1, "free");
    if (lua_isfunction(L, -1)) {
        priv->free_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    return 0;
}

static void get_packet_payload(const np_packet_t *pkt, const uint8_t **out_data, size_t *out_len)
{
    if (pkt->stream_data && pkt->stream_len > 0) {
        *out_data = pkt->stream_data;
        *out_len  = pkt->stream_len;
        return;
    }
    if (pkt->app && pkt->app->data && pkt->app->len > 0) {
        *out_data = pkt->app->data;
        *out_len  = pkt->app->len;
        return;
    }
    if (pkt->transport && pkt->transport->data && pkt->transport->len > 0) {
        ptrdiff_t offset = (pkt->transport->data + pkt->transport->len) - pkt->raw;
        if (offset >= 0 && (size_t)offset < pkt->caplen) {
            *out_data = pkt->raw + offset;
            *out_len  = pkt->caplen - (size_t)offset;
            return;
        }
    }
    /* Fallback to raw packet data */
    *out_data = pkt->raw;
    *out_len  = pkt->caplen;
}

static np_err_t lua_process(np_processor_t *proc, np_packet_t *pkt)
{
    lua_priv_t *priv = proc->priv;
    if (priv->process_ref == LUA_NOREF) {
        return NP_OK;
    }

    lua_State *L = priv->L;

    // Push the process function onto the stack
    lua_rawgeti(L, LUA_REGISTRYINDEX, priv->process_ref);

    // Create the packet table
    lua_newtable(L);

    lua_pushstring(L, "seq");
    lua_pushinteger(L, (lua_Integer)pkt->seq);
    lua_settable(L, -3);

    lua_pushstring(L, "caplen");
    lua_pushinteger(L, (lua_Integer)pkt->caplen);
    lua_settable(L, -3);

    lua_pushstring(L, "wirelen");
    lua_pushinteger(L, (lua_Integer)pkt->wirelen);
    lua_settable(L, -3);

    lua_pushstring(L, "flow_id");
    lua_pushinteger(L, (lua_Integer)pkt->flow_id);
    lua_settable(L, -3);

    lua_pushstring(L, "raw");
    lua_pushlstring(L, (const char *)pkt->raw, pkt->caplen);
    lua_settable(L, -3);

    // Add deepest layer's payload
    const uint8_t *in_data = NULL;
    size_t in_len = 0;
    get_packet_payload(pkt, &in_data, &in_len);
    if (in_data && in_len > 0) {
        lua_pushstring(L, "payload");
        lua_pushlstring(L, (const char *)in_data, in_len);
        lua_settable(L, -3);
    }

    // Call the function (1 arg, up to 2 return values)
    if (lua_pcall(L, 1, 2, 0) != LUA_OK) {
        NP_LOG_ERROR("Lua process callback execution error: %s", lua_tostring(L, -1));
        lua_pop(L, 1);
        return NP_ERR_GENERIC;
    }

    const char *new_payload = NULL;
    size_t new_len = 0;
    bool keep = true;

    // Stack: [ret1, ret2]
    if (lua_isboolean(L, -2)) {
        keep = lua_toboolean(L, -2);
        if (lua_isstring(L, -1)) {
            new_payload = lua_tolstring(L, -1, &new_len);
        }
    } else if (lua_isstring(L, -2)) {
        new_payload = lua_tolstring(L, -2, &new_len);
    }

    if (!keep) {
        lua_pop(L, 2);
        return NP_ERR_FILTER;
    }

    if (new_payload) {
        uint8_t *copy = malloc(new_len);
        if (copy) {
            memcpy(copy, new_payload, new_len);
            if (pkt->stream_data) {
                free(pkt->stream_data);
            }
            pkt->stream_data = copy;
            pkt->stream_len  = new_len;
        }
    }

    lua_pop(L, 2);
    return NP_OK;
}

static void lua_free(np_processor_t *proc)
{
    lua_priv_t *priv = proc->priv;
    if (priv->L) {
        if (priv->free_ref != LUA_NOREF) {
            lua_rawgeti(priv->L, LUA_REGISTRYINDEX, priv->free_ref);
            if (lua_pcall(priv->L, 0, 0, 0) != LUA_OK) {
                NP_LOG_WARN("Lua free callback execution error: %s", lua_tostring(priv->L, -1));
                lua_pop(priv->L, 1);
            }
        }
        lua_close(priv->L);
    }
    free(priv);
    free(proc);
}

static const struct np_processor_ops lua_processor_ops = {
    .process = lua_process,
    .free    = lua_free
};

np_processor_t *np_processor_lua(const char *script_path)
{
    lua_priv_t *priv = calloc(1, sizeof(*priv));
    if (!priv) return NULL;

    priv->process_ref = LUA_NOREF;
    priv->init_ref    = LUA_NOREF;
    priv->free_ref    = LUA_NOREF;
    snprintf(priv->script_path, sizeof(priv->script_path), "%s", script_path);

    np_processor_t *proc = calloc(1, sizeof(*proc));
    if (!proc) {
        free(priv);
        return NULL;
    }
    proc->ops  = &lua_processor_ops;
    proc->priv = priv;

    // 1. Create Lua State
    priv->L = luaL_newstate();
    if (!priv->L) {
        NP_LOG_ERROR("%s", "failed to create Lua state");
        lua_free(proc);
        return NULL;
    }

    // 2. Open Lua standard libraries
    luaL_openlibs(priv->L);

    // 3. Register NP_REGISTER_PROCESSOR global function
    lua_register(priv->L, "NP_REGISTER_PROCESSOR", l_register_processor);

    // 4. Store pointer to this processor in registry for use in the callback
    lua_pushlightuserdata(priv->L, proc);
    lua_setfield(priv->L, LUA_REGISTRYINDEX, LUA_NETPIPE_PROC_KEY);

    // 5. Load and run the Lua script file
    if (luaL_dofile(priv->L, script_path) != LUA_OK) {
        NP_LOG_ERROR("failed to load Lua script '%s': %s", script_path, lua_tostring(priv->L, -1));
        lua_free(proc);
        return NULL;
    }

    // 6. Invoke init callback if registered
    if (priv->init_ref != LUA_NOREF) {
        lua_rawgeti(priv->L, LUA_REGISTRYINDEX, priv->init_ref);
        if (lua_pcall(priv->L, 0, 0, 0) != LUA_OK) {
            NP_LOG_ERROR("Lua init callback execution error: %s", lua_tostring(priv->L, -1));
            lua_free(proc);
            return NULL;
        }
    }

    NP_LOG_INFO("Lua processor '%s' registered from script '%s'", priv->name[0] ? priv->name : "lua", script_path);
    return proc;
}
