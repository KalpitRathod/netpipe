-- test.lua  —  DNS exfil-payload isolation harness
--
-- This script registers a Lua processor on the netpipe pipeline and, for
-- every packet that reaches it, writes the internal keys/properties of
-- that packet to /tmp/netpipe_packet.log.
--
-- A "test case" is flagged as EXFIL_DETECTED when:
--   * proto == "DNS"
--   * dns_query_name length >= 40  (well beyond typical hostnames)
--   * dns_query_name matches the regex  exfil[-_]payload
--   * dst_ip == 8.8.8.8             (Google public DNS — the exfil resolver)
--
-- The expected test packet this harness was written for is:
--   21:31:02  10.124.56.172 → 8.8.8.8  dns  Q A
--            exfil-payload-data-infosec-test-abc123xyz987-long-domain.com

local LOG_PATH = "/tmp/netpipe_packet.log"

local log         -- file handle, opened in init(), closed in free()
local total       = 0
local exfil_hits  = 0

-- Heuristic thresholds
local MIN_NAME_LEN  = 40
local EXFIL_PATTERN = "exfil[%-_]payload"
local EXFIL_DST_IP  = "8.8.8.8"

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
        log = io.open(LOG_PATH, "w")   -- truncate on every fresh run
        if not log then
            error(string.format("could not open %s for writing", LOG_PATH))
        end
        log:write(string.format("# netpipe packet log\n"))
        log:write(string.format("# created by test.lua (exfil_payload_isolator)\n"))
        log:write(string.format("# detection rules: name_len>=%d  pattern=%q  dst=%s\n\n",
                                MIN_NAME_LEN, EXFIL_PATTERN, EXFIL_DST_IP))
        log:flush()
        print(string.format("[LUA] logging packet introspection to %s", LOG_PATH))
    end,

    process = function(pkt)
        total = total + 1
        local tag = classify(pkt)
        if tag == "EXFIL_DETECTED" then
            exfil_hits = exfil_hits + 1
        end

        log:write(dump_packet(pkt, tag))
        log:flush()

        -- Also print a one-line summary to stdout so the operator can see
        -- progress without tailing the log file.
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
        if log then
            log:write(string.format("# ==== summary ====\n"))
            log:write(string.format("# total_packets    = %d\n", total))
            log:write(string.format("# exfil_detected   = %d\n", exfil_hits))
            log:write(string.format("# status           = %s\n",
                                    exfil_hits > 0 and "EXFIL_PAYLOAD_FOUND" or "NO_EXFIL_PAYLOAD"))
            log:close()
        end
        print(string.format("[LUA] total=%d  exfil_hits=%d  log=%s",
              total, exfil_hits, LOG_PATH))
    end,
})
