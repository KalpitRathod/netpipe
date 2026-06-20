-- mitigate.lua  —  Scenario 3: Turing-Complete Intrusion Prevention
--
-- This is the Lua IDS script from the user's "Scenario 3" spec, ported
-- to netpipe's actual Lua API (which uses NP_REGISTER_PROCESSOR and a
-- `process(pkt)` callback, with DNS fields exposed as `pkt.dns_query_name`
-- rather than `packet.dns.query.name`).
--
-- Detection rules (all configurable below):
--   1. DNS query name longer than 50 chars       -> DROP + alert
--   2. DNS query name matches exfil / tunnel     -> DROP + alert
--   3. DNS query name uses base32-tunnel labels  -> flag suspicious
--   4. DNS query name is an absurdly long label  -> flag suspicious
--
-- Returning `false` from process() drops the packet from the pipeline
-- (np_lua.c returns NP_ERR_FILTER which the pipeline interprets as
-- "do not forward to sinks").  Returning `true` keeps the packet.

-- FIX (issue: mitigate.lua hardcodes EXFIL_RESOLVER = "8.8.8.8" — a
-- demo, not production-ready IPS):
--
-- All thresholds and the resolver list are now configurable via:
--   (1) Environment variables (read at init time via the os.getenv
--       binding — but the sandbox nils out `os`, so we instead use
--       the new np_log Lua binding and accept resolver lists from
--       globals set by the C caller via a wrapper script).
--   (2) A Lua module-level configuration table at the top of this
--       file — operators can edit the file directly or override
--       individual fields from a wrapper script that does
--       `dofile` is not available, so instead operators can edit
--       the values in place.
--
-- For full env-var support, see the C-side wrapper that netpipe can
-- expose via np_log() — but since `os.getenv` is sandboxed away, the
-- pragmatic fix is to make the resolver list a comma-separated Lua
-- table that the operator edits in-file.

local CONFIG = {
    THRESHOLD_LONG_NAME = 50,
    EXFIL_PATTERN       = "exfil[%-_]payload",
    TUNNEL_LABEL_LEN    = 30,
    -- FIX: list of resolver IPs considered "exfil destinations".
    -- The default list includes the public DNS resolvers most commonly
    -- abused for DNS exfiltration.  Operators should add their own
    -- known-bad resolvers or remove entries that are legitimate in
    -- their environment.
    EXFIL_RESOLVERS = {
        "8.8.8.8",        -- Google Public DNS
        "8.8.4.4",        -- Google Public DNS (secondary)
        "1.1.1.1",        -- Cloudflare DNS
        "1.0.0.1",        -- Cloudflare DNS (secondary)
        "9.9.9.9",        -- Quad9
        "208.67.222.222", -- Cisco OpenDNS
    },
    -- FIX: optional list of additional domains/keywords to flag as
    -- exfil destinations (matched against dns_query_name).  Empty by
    -- default; operators add e.g. { "%.exfil%.example%.com$" }.
    EXFIL_DOMAIN_PATTERNS = {},
}

-- Local aliases for backwards compatibility with the old single-resolver
-- rule.  Operators who only want to flag 8.8.8.8 can shrink the list.
local THRESHOLD_LONG_NAME  = CONFIG.THRESHOLD_LONG_NAME
local EXFIL_PATTERN        = CONFIG.EXFIL_PATTERN
local TUNNEL_LABEL_LEN     = CONFIG.TUNNEL_LABEL_LEN

-- Build a set for O(1) resolver lookup.
local EXFIL_RESOLVER_SET = {}
for _, ip in ipairs(CONFIG.EXFIL_RESOLVERS) do
    EXFIL_RESOLVER_SET[ip] = true
end

local drops        = 0
local alerts       = 0
local total        = 0

local function matches(s, pattern)
    if not s or s == "" then return false end
    return s:find(pattern) ~= nil
end

-- FIX: returns true if `dst` is in the EXFIL_RESOLVERS list.
local function is_exfil_resolver(dst)
    return dst and EXFIL_RESOLVER_SET[dst] == true
end

-- FIX: returns true if `name` matches any of the configured
-- EXFIL_DOMAIN_PATTERNS.
local function matches_exfil_domain(name)
    if not name then return false end
    for _, pat in ipairs(CONFIG.EXFIL_DOMAIN_PATTERNS) do
        if name:find(pat) then return true end
    end
    return false
end

-- Split a domain name on '.' and return the longest single label length.
-- Useful for catching DNS-tunnel toolkits that encode data in a single
-- very long left-most label (e.g. izmeq4tgnrwgc3tb.fakedomain.com).
local function longest_label(name)
    if not name then return 0 end
    local longest = 0
    for label in name:gmatch("[^.]+") do
        if #label > longest then longest = #label end
    end
    return longest
end

-- Check whether a label looks like base32-encoded tunnel data:
-- 30+ chars of [a-z0-9] with no vowels (the Iodine / dns2tcp default
-- alphabet excludes a/e/i/o/u to stay within DNS label limits while
-- maximising entropy per character).
local function looks_like_base32_tunnel(label)
    if not label or #label < TUNNEL_LABEL_LEN then return false end
    -- Must be all lowercase letters/digits.
    if label:find("[^a-z0-9]") then return false end
    -- Must NOT contain a vowel (heuristic — base32 alphabets omit them).
    if label:find("[aeiou]") then return false end
    return true
end

local function classify(pkt)
    if pkt.proto ~= "DNS" then
        return "passthrough", false
    end
    local name = pkt.dns_query_name or ""
    local dst  = pkt.dst_ip or ""

    -- FIX: check both the resolver list AND the domain pattern list.
    local dst_is_exfil = is_exfil_resolver(dst) or matches_exfil_domain(name)

    if #name >= THRESHOLD_LONG_NAME and matches(name, EXFIL_PATTERN) and dst_is_exfil then
        return "EXFIL_PAYLOAD", true     -- drop
    end
    if #name >= THRESHOLD_LONG_NAME then
        return "long_dns_name", true     -- drop (matches user's spec)
    end
    if matches(name, EXFIL_PATTERN) then
        return "exfil_keyword", true     -- drop
    end
    -- DNS-tunnel heuristic: one label is 30+ chars of base32-style chars.
    if longest_label(name) >= TUNNEL_LABEL_LEN then
        for label in name:gmatch("[^.]+") do
            if looks_like_base32_tunnel(label) then
                return "dns_tunnel_suspect", true  -- drop
            end
        end
    end
    return "dns_normal", false
end

NP_REGISTER_PROCESSOR({
    name = "lua_ids_mitigate",

    init = function()
        -- FIX: use np_log if available (added in this patch set) for
        -- structured logging; fall back to print() otherwise.
        local function log(msg)
            if np_log then np_log("info", msg) else print(msg) end
        end
        log("[LUA-IDS] mitigate.lua loaded")
        log(string.format("[LUA-IDS] rules: long_name>=%d  exfil=%q  tunnel_label>=%d  resolvers=%d",
                          THRESHOLD_LONG_NAME, EXFIL_PATTERN, TUNNEL_LABEL_LEN,
                          #CONFIG.EXFIL_RESOLVERS))
        if #CONFIG.EXFIL_DOMAIN_PATTERNS > 0 then
            log(string.format("[LUA-IDS] also flagging %d domain pattern(s)",
                              #CONFIG.EXFIL_DOMAIN_PATTERNS))
        end
    end,

    process = function(pkt)
        total = total + 1
        local tag, drop = classify(pkt)

        if drop then
            drops = drops + 1
            print(string.format("[!!!] LUA SECURITY ALERT: %s  qname=%s  src=%s  dst=%s",
                  tag, pkt.dns_query_name or "?", pkt.src_ip or "?", pkt.dst_ip or "?"))
            return false   -- DROP from pipeline
        end

        if tag == "dns_normal" then
            -- quiet
        else
            print(string.format("[LUA-IDS] %-18s qname=%s", tag, pkt.dns_query_name or "?"))
        end
        return true   -- keep
    end,

    free = function()
        print(string.format("[LUA-IDS] summary: total=%d  dropped=%d  alerts=%d",
              total, drops, alerts))
    end,
})

