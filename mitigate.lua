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

local THRESHOLD_LONG_NAME  = 50   -- chars
local EXFIL_PATTERN        = "exfil[%-_]payload"
local TUNNEL_LABEL_LEN     = 30                  -- suspicious long base32 label
local EXFIL_RESOLVER       = "8.8.8.8"          -- threshold dst for alert

local drops        = 0
local alerts       = 0
local total        = 0

local function matches(s, pattern)
    if not s or s == "" then return false end
    return s:find(pattern) ~= nil
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

    if #name >= THRESHOLD_LONG_NAME and matches(name, EXFIL_PATTERN) and dst == EXFIL_RESOLVER then
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
        print("[LUA-IDS] mitigate.lua loaded")
        print(string.format("[LUA-IDS] rules: long_name>=%d  exfil=%q  tunnel_label>=%d  resolver=%s",
                            THRESHOLD_LONG_NAME, EXFIL_PATTERN, TUNNEL_LABEL_LEN,
                            EXFIL_RESOLVER))
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
