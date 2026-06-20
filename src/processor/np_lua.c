/*
 * np_lua.c — Lua scripting processor implementation
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "netpipe.h"
#include "../log/np_log.h"
#include "../packet/np_packet.h"
#include "../pipeline/np_pipeline.h"

/* ------------------------------------------------------------------ *
 *  Internal header layouts (mirror of np_demux.c — kept private so   *
 *  we can re-extract src/dst IP + ports for the Lua packet table).   *
 * ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint8_t  version_ihl;
    uint8_t  dscp_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
} lua_ip4_hdr_t;

typedef struct {
    uint32_t vcf;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} lua_ip6_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} lua_udp_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset_flags;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} lua_tcp_hdr_t;
#pragma pack(pop)

#define LUA_NETPIPE_PROC_KEY "netpipe_processor"

/* Bug LU1 fix: cap Lua VM memory at 16 MiB so a buggy or malicious
 * script cannot OOM the netpipe process.  Tracked via the custom
 * allocator below. */
#define NP_LUA_MEM_LIMIT  (16UL * 1024UL * 1024UL)

typedef struct {
    lua_State *L;
    char       script_path[256];
    char       name[64];
    int        process_ref;
    int        init_ref;
    int        free_ref;
    size_t     mem_used;     /* current Lua VM allocations (bytes) */
    size_t     mem_limit;    /* hard cap on Lua VM allocations */
} lua_priv_t;

/* Bug LU1 fix: custom allocator that enforces a hard memory cap on
 * the Lua VM.  Without this, a script like `while true do t = t ..
 * "x" end` could grow the VM until the OS OOM-killed the netpipe
 * process. */
static void *np_lua_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    lua_priv_t *priv = (lua_priv_t *)ud;
    if (nsize == 0) {
        free(ptr);
        if (priv) priv->mem_used -= osize;
        return NULL;
    }
    if (priv) {
        /* signed-safe delta: if nsize > osize, we're growing. */
        size_t delta = (nsize > osize) ? (nsize - osize) : 0;
        if (delta > 0 && priv->mem_used + delta > priv->mem_limit) {
            NP_LOG_ERROR("Lua VM hit memory limit (%zu bytes); "
                        "allocation of %zu bytes rejected",
                        priv->mem_limit, nsize);
            return NULL;  /* Lua treats this as out-of-memory */
        }
        priv->mem_used = priv->mem_used - osize + nsize;
    }
    return realloc(ptr, nsize);
}

/* Bug LU1 fix: open only the safe Lua standard libraries.  We OMIT
 * `io`, `os`, `package`, and `debug` because they give the script
 * filesystem, process-spawn, module-loading, and introspection
 * capabilities — none of which a packet-processing script should
 * need, and all of which are exploitation vectors if an untrusted
 * script is loaded.  We also nullify `dofile`, `loadfile`, `load`,
 * and `require` from the base library so the script can't sideload
 * additional Lua bytecode from disk. */
static void np_lua_open_safe_libs(lua_State *L)
{
    /* luaL_openlibs opens: base, package, table, io, os, string, math,
     * coroutine, utf8, debug.  We whitelist only: base, table, string,
     * math, coroutine, utf8. */
    luaL_requiref(L, LUA_GNAME,      luaopen_base,       1); lua_pop(L, 1);
    luaL_requiref(L, LUA_TABLIBNAME, luaopen_table,      1); lua_pop(L, 1);
    luaL_requiref(L, LUA_STRLIBNAME, luaopen_string,     1); lua_pop(L, 1);
    luaL_requiref(L, LUA_MATHLIBNAME,luaopen_math,       1); lua_pop(L, 1);
#if LUA_VERSION_NUM >= 502
    luaL_requiref(L, LUA_COLIBNAME,  luaopen_coroutine,  1); lua_pop(L, 1);
#endif
#if LUA_VERSION_NUM >= 503
    luaL_requiref(L, LUA_UTF8LIBNAME,luaopen_utf8,       1); lua_pop(L, 1);
#endif

    /* Harden the base library: remove file/code-loading primitives. */
    lua_pushnil(L); lua_setglobal(L, "dofile");
    lua_pushnil(L); lua_setglobal(L, "loadfile");
    lua_pushnil(L); lua_setglobal(L, "load");
    lua_pushnil(L); lua_setglobal(L, "require");
    lua_pushnil(L); lua_setglobal(L, "module");
    lua_pushnil(L); lua_setglobal(L, "package");
}

/* FIX (issue: test.lua broken by sandbox):
 * Expose a tiny `np_log(level, msg)` Lua binding so sandboxed scripts
 * can route structured log lines through netpipe's leveled logger
 * (timestamps, file:line, ANSI colours) instead of being forced to
 * call `io.open()` — which the sandbox deliberately nils out.
 *
 * Usage from Lua:
 *   np_log("trace" | "debug" | "info" | "warn" | "error", "message")
 *
 * Unknown levels default to INFO.  Returns true on success. */
static int l_np_log(lua_State *L)
{
    const char *level = luaL_optstring(L, 1, "info");
    const char *msg   = luaL_optstring(L, 2, "");
    if (!strcasecmp(level, "trace"))      NP_LOG_TRACE("%s", msg);
    else if (!strcasecmp(level, "debug")) NP_LOG_DEBUG("%s", msg);
    else if (!strcasecmp(level, "info"))  NP_LOG_INFO("%s", msg);
    else if (!strcasecmp(level, "warn"))  NP_LOG_WARN("%s", msg);
    else if (!strcasecmp(level, "error")) NP_LOG_ERROR("%s", msg);
    else                                  NP_LOG_INFO("%s", msg);
    lua_pushboolean(L, 1);
    return 1;
}

/* FIX (issue: hardcoded NP_LUA_MEM_LIMIT):
 * Expose the configured memory cap and current usage to Lua scripts so
 * they can self-throttle large state tables before hitting the hard
 * limit.  Returns (mem_used, mem_limit) in bytes. */
static int l_np_mem_stats(lua_State *L)
{
    lua_getfield(L, LUA_REGISTRYINDEX, LUA_NETPIPE_PROC_KEY);
    np_processor_t *proc = lua_touserdata(L, -1);
    lua_pop(L, 1);
    if (!proc || !proc->priv) {
        lua_pushinteger(L, 0);
        lua_pushinteger(L, 0);
        return 2;
    }
    lua_priv_t *priv = proc->priv;
    lua_pushinteger(L, (lua_Integer)priv->mem_used);
    lua_pushinteger(L, (lua_Integer)priv->mem_limit);
    return 2;
}

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

    // 1. Get name (Bug LU5 fix: snprintf guarantees NUL-termination)
    lua_getfield(L, 1, "name");
    const char *name = luaL_optstring(L, -1, "lua_processor");
    snprintf(priv->name, sizeof(priv->name), "%s", name);
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


static const char *proto_to_string(const np_packet_t *pkt)
{
    if (pkt->app) {
        switch (pkt->app->proto) {
            case NP_PROTO_HTTP: return "HTTP";
            case NP_PROTO_DNS:  return "DNS";
            case NP_PROTO_TLS:  return "TLS";
            default: break;
        }
    }
    if (pkt->transport) {
        switch (pkt->transport->proto) {
            case NP_PROTO_TCP:  return "TCP";
            case NP_PROTO_UDP:  return "UDP";
            case NP_PROTO_ICMP: return "ICMP";
            default: break;
        }
    }
    if (pkt->net) {
        switch (pkt->net->proto) {
            case NP_PROTO_IP4: return "IPv4";
            case NP_PROTO_IP6: return "IPv6";
            case NP_PROTO_ARP: return "ARP";
            default: break;
        }
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ *
 *  Layer field extraction helpers — populate Lua table fields.       *
 * ------------------------------------------------------------------ */

static void lua_set_str(lua_State *L, const char *key, const char *val)
{
    lua_pushstring(L, key);
    lua_pushstring(L, val ? val : "");
    lua_settable(L, -3);
}

static void lua_set_int(lua_State *L, const char *key, lua_Integer v)
{
    lua_pushstring(L, key);
    lua_pushinteger(L, v);
    lua_settable(L, -3);
}

static void lua_set_bool(lua_State *L, const char *key, bool v)
{
    lua_pushstring(L, key);
    lua_pushboolean(L, v ? 1 : 0);
    lua_settable(L, -3);
}

/* Extract IPv4/IPv6 src+dst and ports from the decoded layer stack and
 * push them onto the Lua packet table on top of the stack. */
static void lua_push_l3_l4_fields(lua_State *L, const np_packet_t *pkt)
{
    /* ---- L3: IPv4 / IPv6 ---- */
    if (pkt->net && pkt->net->data && pkt->net->len >= 20) {
        if (pkt->net->proto == NP_PROTO_IP4) {
            const lua_ip4_hdr_t *ip = (const lua_ip4_hdr_t *)pkt->net->data;
            struct in_addr s, d;
            s.s_addr = ip->src;
            d.s_addr = ip->dst;
            char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &s, sbuf, sizeof(sbuf));
            inet_ntop(AF_INET, &d, dbuf, sizeof(dbuf));
            lua_set_str(L, "src_ip",   sbuf);
            lua_set_str(L, "dst_ip",   dbuf);
            lua_set_str(L, "net_proto","IPv4");
            lua_set_int(L, "ttl",      ip->ttl);
            lua_set_int(L, "ip_proto", ip->protocol);
        } else if (pkt->net->proto == NP_PROTO_IP6 && pkt->net->len >= sizeof(lua_ip6_hdr_t)) {
            const lua_ip6_hdr_t *ip6 = (const lua_ip6_hdr_t *)pkt->net->data;
            char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, ip6->src, sbuf, sizeof(sbuf));
            inet_ntop(AF_INET6, ip6->dst, dbuf, sizeof(dbuf));
            lua_set_str(L, "src_ip",    sbuf);
            lua_set_str(L, "dst_ip",    dbuf);
            lua_set_str(L, "net_proto", "IPv6");
            lua_set_int(L, "ip_proto",  ip6->next_header);
        }
    }

    /* ---- L4: TCP / UDP ---- */
    if (pkt->transport && pkt->transport->data && pkt->transport->len >= 4) {
        if (pkt->transport->proto == NP_PROTO_UDP &&
            pkt->transport->len >= sizeof(lua_udp_hdr_t)) {
            const lua_udp_hdr_t *u = (const lua_udp_hdr_t *)pkt->transport->data;
            lua_set_int(L, "src_port", ntohs(u->src_port));
            lua_set_int(L, "dst_port", ntohs(u->dst_port));
            lua_set_str(L, "transport_proto", "UDP");
        } else if (pkt->transport->proto == NP_PROTO_TCP &&
                   pkt->transport->len >= sizeof(lua_tcp_hdr_t)) {
            const lua_tcp_hdr_t *t = (const lua_tcp_hdr_t *)pkt->transport->data;
            lua_set_int(L, "src_port", ntohs(t->src_port));
            lua_set_int(L, "dst_port", ntohs(t->dst_port));
            lua_set_str(L, "transport_proto", "TCP");
        } else if (pkt->transport->proto == NP_PROTO_ICMP) {
            lua_set_str(L, "transport_proto", "ICMP");
        }
    }
}

/* If the application layer decoded a DNS message, expose the parsed fields. */
static void lua_push_dns_fields(lua_State *L, const np_packet_t *pkt)
{
    if (!pkt->app || pkt->app->proto != NP_PROTO_DNS || !pkt->app->decoded) {
        return;
    }
    const np_dns_msg_t *dns = (const np_dns_msg_t *)pkt->app->decoded;

    lua_set_int(L, "dns_id",         (lua_Integer)dns->id);
    lua_set_bool(L, "dns_is_response", dns->is_response);
    lua_set_int(L, "dns_rcode",      (lua_Integer)dns->rcode);
    lua_set_int(L, "dns_query_type", (lua_Integer)dns->query_type);
    lua_set_str(L, "dns_query_name", dns->query_name);
    lua_set_int(L, "dns_num_answers",(lua_Integer)dns->num_answers);

    /* answers[] — array of { name, type, ttl, rdata } */
    lua_pushstring(L, "dns_answers");
    lua_newtable(L);
    for (int i = 0; i < dns->num_answers && i < NP_MAX_DNS_ANSWERS; i++) {
        const np_dns_answer_t *a = &dns->answers[i];
        lua_pushinteger(L, (lua_Integer)(i + 1));   /* 1-indexed */
        lua_newtable(L);
        lua_set_str(L, "name",  a->name);
        lua_set_int(L, "type",  (lua_Integer)a->type);
        lua_set_int(L, "ttl",   (lua_Integer)a->ttl);
        lua_set_str(L, "rdata", a->rdata_str);
        lua_settable(L, -3);
    }
    lua_settable(L, -3);  /* pkt["dns_answers"] = {...} */
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

    lua_pushstring(L, "proto");
    lua_pushstring(L, proto_to_string(pkt));
    lua_settable(L, -3);

    lua_pushstring(L, "flow_id");
    lua_pushinteger(L, (lua_Integer)pkt->flow_id);
    lua_settable(L, -3);

    /* Timestamp as a Unix-epoch float (seconds.microseconds). */
    lua_pushstring(L, "ts_sec");
    lua_pushinteger(L, (lua_Integer)pkt->ts.tv_sec);
    lua_settable(L, -3);
    lua_pushstring(L, "ts_usec");
    lua_pushinteger(L, (lua_Integer)pkt->ts.tv_nsec / 1000);
    lua_settable(L, -3);

    /* L3/L4 + DNS decoded fields (added in 0.2 — exposes the internal
     * layer keys the Lua script needs to isolate test cases such as
     * a DNS data-exfiltration payload). */
    lua_push_l3_l4_fields(L, pkt);
    lua_push_dns_fields(L, pkt);

    /* Bug LU2 fix: guard against NULL pkt->raw — hand-constructed or
     * partially-initialized packets may have raw == NULL even when
     * caplen > 0. */
    lua_pushstring(L, "raw");
    if (pkt->raw && pkt->caplen > 0) {
        lua_pushlstring(L, (const char *)pkt->raw, pkt->caplen);
    } else {
        lua_pushlstring(L, "", 0);
    }
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
        /* Bug LU3 fix: lua_tostring may return NULL if the error on the
         * stack isn't a string (e.g. a table).  luaL_tolstring always
         * returns a valid string (pushing it on the stack — pop after). */
        const char *err = lua_tostring(L, -1);
        if (!err) {
            luaL_tolstring(L, -1, NULL);
            err = lua_tostring(L, -1);
            lua_pop(L, 1);
        }
        NP_LOG_ERROR("Lua process callback execution error: %s", err ? err : "<unknown>");
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
    if (!priv) { free(proc); return; }
    if (priv->L) {
        if (priv->free_ref != LUA_NOREF) {
            lua_rawgeti(priv->L, LUA_REGISTRYINDEX, priv->free_ref);
            if (lua_pcall(priv->L, 0, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(priv->L, -1);
                if (!err) {
                    luaL_tolstring(priv->L, -1, NULL);
                    err = lua_tostring(priv->L, -1);
                    lua_pop(priv->L, 1);
                }
                NP_LOG_WARN("Lua free callback execution error: %s", err ? err : "<unknown>");
                lua_pop(priv->L, 1);
            }
        }
        lua_close(priv->L);
        priv->L = NULL;
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
    /* FIX (issue: hardcoded NP_LUA_MEM_LIMIT): the wrapper preserves the
     * historical 16 MiB default.  Callers that need a different cap
     * should use np_processor_lua_ex(). */
    return np_processor_lua_ex(script_path, 0);
}

np_processor_t *np_processor_lua_ex(const char *script_path,
                                     size_t mem_limit_bytes)
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

    // 1. Create Lua State (Bug LU1 fix: with custom memory-capping allocator)
    priv->mem_limit = (mem_limit_bytes > 0) ? mem_limit_bytes : NP_LUA_MEM_LIMIT;
    priv->mem_used  = 0;
    if (mem_limit_bytes > 0 && mem_limit_bytes != NP_LUA_MEM_LIMIT) {
        NP_LOG_INFO("lua: VM memory cap = %zu bytes (default %zu)",
                    mem_limit_bytes, (size_t)NP_LUA_MEM_LIMIT);
    }
    priv->L = lua_newstate(np_lua_alloc, priv);
    if (!priv->L) {
        NP_LOG_ERROR("%s", "failed to create Lua state");
        lua_free(proc);
        return NULL;
    }
    /* Initialise the panic + warn handlers so uncaught errors don't
     * kill the whole process. */
    lua_atpanic(priv->L, NULL);

    // 2. Open only the safe Lua standard libraries (Bug LU1 fix:
    //    no io, no os, no package, no require)
    np_lua_open_safe_libs(priv->L);

    // 3. Register NP_REGISTER_PROCESSOR global function
    lua_register(priv->L, "NP_REGISTER_PROCESSOR", l_register_processor);

    // 3a. FIX (issue: test.lua broken by sandbox): expose np_log() so
    // sandboxed scripts can write to netpipe's leveled logger without
    // needing the (intentionally removed) `io` library.  Also expose
    // np_mem_stats() so scripts can self-throttle against the
    // configurable memory cap (see -lua-mem-limit CLI flag).
    lua_register(priv->L, "np_log",       l_np_log);
    lua_register(priv->L, "np_mem_stats", l_np_mem_stats);

    // 4. Store pointer to this processor in registry for use in the callback
    lua_pushlightuserdata(priv->L, proc);
    lua_setfield(priv->L, LUA_REGISTRYINDEX, LUA_NETPIPE_PROC_KEY);

    // 5. Load and run the Lua script file
    if (luaL_dofile(priv->L, script_path) != LUA_OK) {
        /* Bug LU3 fix: luaL_tolstring guarantees a non-NULL string. */
        const char *err = lua_tostring(priv->L, -1);
        if (!err) {
            luaL_tolstring(priv->L, -1, NULL);
            err = lua_tostring(priv->L, -1);
            lua_pop(priv->L, 1);
        }
        NP_LOG_ERROR("failed to load Lua script '%s': %s", script_path, err ? err : "<unknown>");
        lua_free(proc);
        return NULL;
    }

    if (priv->process_ref == LUA_NOREF) {
        NP_LOG_ERROR("%s", "Lua script did not call NP_REGISTER_PROCESSOR");
        lua_free(proc);
        return NULL;
    }

    // 6. Invoke init callback if registered
    if (priv->init_ref != LUA_NOREF) {
        lua_rawgeti(priv->L, LUA_REGISTRYINDEX, priv->init_ref);
        if (lua_pcall(priv->L, 0, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(priv->L, -1);
            if (!err) {
                luaL_tolstring(priv->L, -1, NULL);
                err = lua_tostring(priv->L, -1);
                lua_pop(priv->L, 1);
            }
            NP_LOG_ERROR("Lua init callback execution error: %s", err ? err : "<unknown>");
            lua_free(proc);
            return NULL;
        }
    }

    NP_LOG_INFO("Lua processor '%s' registered from script '%s'", priv->name[0] ? priv->name : "lua", script_path);
    return proc;
}
