#!/usr/bin/env python3
"""
24_lua_pipeline.py — Drive a Lua processing script from Python

Shows how to launch netpipe with a Lua processor script from Python,
capture Lua's stdout output, and parse per-packet events.

Generates a temporary Lua script that logs protocol and size for every
packet, then reads the output back into Python for analysis.

No root required — offline PCAP replay.

Run:
    python3 examples/python/24_lua_pipeline.py
"""

import subprocess
import tempfile
import os
import json
import re

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
BIN       = os.path.join(REPO_ROOT, "build", "bin", "netpipe")
FIXTURE   = os.path.join(REPO_ROOT, "tests", "fixtures", "all.pcap")

# ── Lua script ────────────────────────────────────────────────────────────────
LUA_SCRIPT = """\
-- Lua processor: emit one JSON line per packet to stdout
local hits = {}

NP_REGISTER_PROCESSOR({
    name = "json_emitter",

    init = function()
        io.write('[lua:init]\\n')
        io.flush()
    end,

    process = function(pkt)
        local record = string.format(
            '{"seq":%d,"proto":"%s","caplen":%d,"flow_id":%d}',
            pkt.seq, pkt.proto, pkt.caplen, pkt.flow_id
        )
        io.write(record .. '\\n')
        io.flush()
        table.insert(hits, pkt.proto)
        return true
    end,

    free = function()
        local counts = {}
        for _, p in ipairs(hits) do
            counts[p] = (counts[p] or 0) + 1
        end
        io.write('[lua:free] proto_counts=')
        for proto, cnt in pairs(counts) do
            io.write(proto .. ':' .. cnt .. ' ')
        end
        io.write('\\n')
        io.flush()
    end,
})
"""


def main():
    print("=" * 60)
    print(" netpipe — Example 24: Lua Pipeline from Python")
    print("=" * 60)

    # ── 1. Write temporary Lua script ────────────────────────────────
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".lua", delete=False, prefix="np_example24_"
    ) as f:
        f.write(LUA_SCRIPT)
        lua_path = f.name

    print(f"\n[1] Temporary Lua script: {lua_path}\n")
    print("    Script content:")
    for i, line in enumerate(LUA_SCRIPT.splitlines(), 1):
        print(f"    {i:3}: {line}")

    try:
        # ── 2. Run pipeline with Lua processor ───────────────────────
        print(f"\n[2] Running pipeline: {os.path.basename(FIXTURE)} -proc lua:{os.path.basename(lua_path)}\n")
        result = subprocess.run(
            [BIN, "-r", FIXTURE, "-proc", f"lua:{lua_path}", "-fmt", "null"],
            capture_output=True, text=True, timeout=10
        )

        combined = result.stdout + result.stderr

        # ── 3. Parse Lua output lines ─────────────────────────────────
        print("[3] Raw output from Lua callbacks:\n")
        for line in combined.splitlines():
            if line.startswith("[lua:") or line.startswith("{"):
                print(f"    {line}")

        # ── 4. Parse JSON records emitted by Lua ─────────────────────
        print("\n[4] Parsed per-packet records:\n")
        print(f"  {'seq':<5} {'proto':<8} {'caplen':>8} {'flow_id':>12}")
        print(f"  {'-'*5} {'-'*8} {'-'*8} {'-'*12}")

        json_lines = [l for l in combined.splitlines() if l.startswith("{")]
        for line in json_lines:
            try:
                pkt = json.loads(line)
                print(f"  {pkt['seq']:<5} {pkt['proto']:<8} {pkt['caplen']:>8} {pkt['flow_id']:>12}")
            except json.JSONDecodeError:
                pass

        # ── 5. Proto frequency from free callback ─────────────────────
        print("\n[5] Protocol frequency (from Lua free callback):\n")
        for line in combined.splitlines():
            if "[lua:free]" in line:
                parts = re.findall(r'(\w+):(\d+)', line)
                for proto, count in parts:
                    bar = "█" * int(count)
                    print(f"    {proto:<8} {bar} {count}")

        # ── 6. Drop mode: return false to filter packets ──────────────
        print("\n[6] Drop mode — Lua returns false to suppress ICMP:\n")
        drop_lua = """\
NP_REGISTER_PROCESSOR({
    name = "icmp_dropper",
    process = function(pkt)
        if pkt.proto == "ICMP" then
            io.write("  [DROPPED] ICMP caplen=" .. pkt.caplen .. "\\n")
            io.flush()
            return false  -- drop this packet
        end
        io.write("  [PASSED]  " .. pkt.proto .. " caplen=" .. pkt.caplen .. "\\n")
        io.flush()
        return true
    end,
})
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".lua", delete=False, prefix="np_drop_"
        ) as f2:
            f2.write(drop_lua)
            drop_path = f2.name

        result2 = subprocess.run(
            [BIN, "-r", FIXTURE, "-proc", f"lua:{drop_path}", "-fmt", "null"],
            capture_output=True, text=True, timeout=10
        )
        for line in (result2.stdout + result2.stderr).splitlines():
            if "[DROPPED]" in line or "[PASSED]" in line:
                print(f"  {line}")

        os.unlink(drop_path)

    finally:
        os.unlink(lua_path)

    print("\nDone.")


if __name__ == "__main__":
    main()
