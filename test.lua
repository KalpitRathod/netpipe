-- test.lua  —  DNS exfil-payload isolation harness
--
-- FIX (sandbox compatibility): the previous version called io.open() in
-- init() to write to /tmp/netpipe_packet.log, but np_lua_open_safe_libs
-- in np_lua.c deliberately nils out `io`, `os`, `package`, `debug`,
-- `dofile`, `loadfile`, `load`, and `require` to prevent untrusted
-- scripts from touching the filesystem.  As a result the old test.lua
-- would fail at processor construction time with
-- "attempt to index a nil value (global 'io')".
--
-- The fix has two parts:
--   (1) Replace file I/O with a stdout/stderr streamer (print).  This
--       is allowed by the sandbox and produces a streamable log on
--       stderr that the operator can redirect with `2> /tmp/...log`.
--   (2) Use the new `np_log(level, msg)` C binding (added in this same
--       patch set) when available, so logs go through netpipe's own
--       leveled logger with timestamps and file:line info.  We probe
--       for it at init time and degrade gracefully if absent.
--
-- A "test case" is flagged as EXFIL_DETECTED when:
--   * proto == "DNS"
--   * dns_query_name length >= 40  (well beyond typical hostnames)
--   * dns_query_name matches the regex  exfil[-_]payload
--   * dst_ip == 8.8.8.8             (Google public DNS — the exfil resolver)
--
-- The expected test packet this harness was written for is:
--   21:31:02  10.124.56.172 → 8.8.8.8  dns  Q A
--             exfil-payload-data-infosec-test-abc123xyz987-long-domain.com

local total       = 0
local exfil_hits  = 0

-- Heuristic thresholds
local MIN_NAME_LEN  = 40
local EXFIL_PATTERN = "exfil[%-_]payload"
local EXFIL_DST_IP  = "8.8.8.8"

-- Optional C-side bridge.  np_log is registered by np_lua.c in this
-- patch set; if it's not present (older netpipe build) we fall back to
-- plain `print`, which still works inside the sandbox.
local np_log = rawget(_G, "np_log")
local function log(level, msg)
    if np_log then
        np_log(level, msg)
    else
        -- Sandbox-safe fallback: print always works (it goes to stdout).
        -- We deliberately do NOT touch `io` here — the sandbox nils it
        -- out, so any `io.write(...)` reference would crash.
        print(msg)
    end
end

-- tiny string pattern helper: returns true if `s` contains `pattern`
local function matches(s, pattern)
    if not s or s == "" then return false end
    return s:find(pattern) ~= nil
end

-- Format a packet table as a flat key=value block, prefixed by a header
-- line.  Keys are emitted in a stable order so the log is diff-able.
local KEYS = {
    "seq", "ts_sec", "ts_usec", "proto",
    "caplen", "wirelen", "flow_id",
    "net_proto", "src_ip", "dst_ip", "ip_proto", "ttl",
    "transport_proto", "src_port", "dst_port",
    "dns_id", "dns_is_response", "dns_rcode",
    "dns_query_name", "dns_query_type", "dns_num_answers",
}

local function dump_packet(pkt, tag)
    local lines = {}
    table.insert(lines, string.format("==== packet #%d  tag=%s ====",
                                      pkt.seq or -1, tag))
    for _, k in ipairs(KEYS) do
        local v = pkt[k]
        if v == nil then v = "<nil>" end
        table.insert(lines, string.format("  %-18s = %s", k, tostring(v)))
    end
    -- payload + raw lengths (bytes are not always printable)
    if pkt.payload then
        table.insert(lines, string.format("  %-18s = %d bytes", "payload_len", #pkt.payload))
    else
        table.insert(lines, string.format("  %-18s = 0 bytes", "payload_len"))
    end
    if pkt.raw then
        table.insert(lines, string.format("  %-18s = %d bytes", "raw_len", #pkt.raw))
    end

    -- DNS answers (if any)
    if pkt.dns_answers and #pkt.dns_answers > 0 then
        for i, ans in ipairs(pkt.dns_answers) do
            table.insert(lines, string.format(
                "  dns_answers[%d]    = name=%s type=%d ttl=%d rdata=%s",
                i, ans.name, ans.type, ans.ttl, ans.rdata))
        end
    end

    table.insert(lines, "")  -- blank separator
    return table.concat(lines, "\n")
end

-- Classify a packet.  Returns a tag string.
local function classify(pkt)
    if pkt.proto ~= "DNS" then
        return "non_dns_passthrough"
    end
    local name   = pkt.dns_query_name or ""
    local dst    = pkt.dst_ip or ""
    local is_long  = #name >= MIN_NAME_LEN
    local is_match = matches(name, EXFIL_PATTERN)
    local is_dst   = (dst == EXFIL_DST_IP)

    if is_long and is_match and is_dst then
        return "EXFIL_DETECTED"
    elseif is_long or is_match then
        return "dns_suspicious"
    else
        return "dns_normal"
    end
end

NP_REGISTER_PROCESSOR({
    name = "exfil_payload_isolator",

    init = function()
        -- FIX: no file I/O.  Logs go to stdout/stderr (redirect with
        -- `2>/tmp/netpipe_packet.log` if you want a file).
        log("info", "# netpipe packet log")
        log("info", "# created by test.lua (exfil_payload_isolator)")
        log("info", string.format("# detection rules: name_len>=%d  pattern=%q  dst=%s",
                                MIN_NAME_LEN, EXFIL_PATTERN, EXFIL_DST_IP))
        print(string.format("[LUA] logging packet introspection to stderr (redirect with 2>file)"))
    end,

    process = function(pkt)
        total = total + 1
        local tag = classify(pkt)
        if tag == "EXFIL_DETECTED" then
            exfil_hits = exfil_hits + 1
        end

        -- FIX: stream to stdout via print (sandbox-safe); for the
        -- detailed dump, route through the leveled logger so each line
        -- is timestamped and prefixed with file:line.
        local dump = dump_packet(pkt, tag)
        for line in dump:gmatch("[^\n]*") do
            log("info", line)
        end

        -- One-line summary to stdout so the operator can see progress.
        print(string.format("[LUA] #%d  proto=%-4s  %-15s:%-5s -> %-15s:%-5s  tag=%s%s",
              pkt.seq, pkt.proto,
              pkt.src_ip or "?", pkt.src_port or 0,
              pkt.dst_ip or "?", pkt.dst_port or 0,
              tag,
              (pkt.dns_query_name and pkt.dns_query_name ~= "")
                  and ("  qname=" .. pkt.dns_query_name) or ""))
        return true   -- keep packet in the pipeline
    end,

    free = function()
        log("info", "# ==== summary ====")
        log("info", string.format("# total_packets    = %d", total))
        log("info", string.format("# exfil_detected   = %d", exfil_hits))
        log("info", string.format("# status           = %s",
                                exfil_hits > 0 and "EXFIL_PAYLOAD_FOUND" or "NO_EXFIL_PAYLOAD"))
        print(string.format("[LUA] total=%d  exfil_hits=%d  (logs on stderr)",
              total, exfil_hits))
    end,
})
