#!/usr/bin/env python3
"""
polydrop_deaddrop_poll.py - read POLYDROP's C2 dead drop from the Polygon chain.

POLYDROP stores its C2 configuration in a smart contract and reads it whenever
its primary WebSocket C2 is unreachable. The contract address and function
selector were recovered from the malware's own JSON-RPC traffic during analysis
(see analysis/polydrop.md section 4.2).

That makes the operator's configuration publicly readable. eth_call executes
against a node's local state: it is read-only, creates no transaction, is never
broadcast, costs nothing, and leaves no on-chain record. The contract owner
cannot see that it happened.

So this script polls the dead drop and reports when the value changes - i.e.
when the operator rotates infrastructure. No sample required, indefinitely.

WHAT THIS DOES NOT DO
    The returned 48 bytes are encrypted (16-byte IV + 32-byte ciphertext is the
    working hypothesis; bcrypt.dll is loaded by the implant). The key lives in
    the malware and was not recovered. This script reports the ciphertext and
    flags changes; it does not decrypt. Recovering the key - see section 8.2 -
    would turn change detection into actual config extraction.

DELIBERATELY NOT USED: the three RPC providers the malware itself contacts.
    Querying those would place your source address alongside implant traffic in
    their logs for no analytical gain.

Usage
    python3 polydrop_deaddrop_poll.py                 # single read
    python3 polydrop_deaddrop_poll.py --watch 3600    # poll hourly, report changes
    python3 polydrop_deaddrop_poll.py --state s.json  # persist last value

Author: Mustafa Emre
Report: analysis/polydrop.md
"""

import argparse
import hashlib
import json
import math
import os
import sys
import time
import urllib.request
from collections import Counter

CONTRACT = "0x0E04c59f31E382D2B8A1637f4B9A5f04165EC48d"
SELECTOR = "0x44574e9b"

# Neutral public Polygon RPC endpoints. Intentionally NOT the three the malware
# uses (api.zan.top, polygon.lava.build, polygon-mainnet.gateway.tatum.io).
RPCS = [
    "https://polygon-bor-rpc.publicnode.com",
    "https://1rpc.io/matic",
    "https://polygon.llamarpc.com",
]


def eth_call(rpc, timeout=20):
    """Issue the same read-only call the implant makes. Returns hex result."""
    payload = json.dumps({
        "jsonrpc": "2.0",
        "method": "eth_call",
        "params": [{"to": CONTRACT, "data": SELECTOR}, "latest"],
        "id": 1,
    }).encode()
    req = urllib.request.Request(
        rpc, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = json.loads(r.read().decode())
    if "error" in body:
        raise RuntimeError(body["error"])
    return body["result"]


def read_deaddrop():
    """Query providers until two independent ones agree, or all fail."""
    results = {}
    for rpc in RPCS:
        try:
            results[rpc] = eth_call(rpc)
        except Exception as e:
            print("  [!] %-45s %s" % (rpc, e), file=sys.stderr)
    if not results:
        raise RuntimeError("no RPC endpoint answered")

    counts = Counter(results.values())
    value, n = counts.most_common(1)[0]
    if n < 2 and len(results) > 1:
        print("  [!] providers disagree - treat result as unverified",
              file=sys.stderr)
    return value, n, len(results)


def decode_abi_string(hexdata):
    """Decode a single ABI-encoded dynamic string return value."""
    b = bytes.fromhex(hexdata[2:] if hexdata.startswith("0x") else hexdata)
    if len(b) < 64:
        raise ValueError("response too short for an ABI string")
    offset = int.from_bytes(b[0:32], "big")
    length = int.from_bytes(b[offset:offset + 32], "big")
    start = offset + 32
    return b[start:start + length].decode("ascii", "replace")


def entropy(data):
    """Shannon entropy. Note the ceiling is log2(len) for short samples,
    not 8.0 - a 48-byte blob cannot exceed ~5.58 however random it is."""
    if not data:
        return 0.0
    return -sum((c / len(data)) * math.log2(c / len(data))
                for c in Counter(data).values())


def report(value):
    print("raw result   : %s" % value)
    try:
        s = decode_abi_string(value)
    except Exception as e:
        print("  [!] ABI decode failed: %s" % e)
        return None
    print("decoded string: %s" % s)
    print("               (%d chars)" % len(s))
    try:
        blob = bytes.fromhex(s)
    except ValueError:
        print("  [i] not hex - value may now be cleartext, inspect manually")
        return s
    e = entropy(blob)
    ceiling = math.log2(len(blob)) if blob else 0
    print("hex-decoded  : %d bytes" % len(blob))
    print("entropy      : %.2f bits/byte (ceiling %.2f for this length)"
          % (e, ceiling))
    if e > ceiling * 0.95:
        print("               -> at ceiling: encrypted or compressed")
    else:
        print("               -> below ceiling: may be structured/cleartext")
    print("sha256       : %s" % hashlib.sha256(blob).hexdigest())
    return s


def load_state(path):
    if path and os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(path, state):
    if path:
        with open(path, "w") as f:
            json.dump(state, f, indent=2)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--watch", type=int, metavar="SECONDS",
                    help="poll every SECONDS and report changes")
    ap.add_argument("--state", metavar="FILE",
                    help="persist last seen value to FILE")
    args = ap.parse_args()

    state = load_state(args.state)
    previous = state.get("last_value")

    while True:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print("\n=== %s ===" % stamp)
        print("contract %s  selector %s" % (CONTRACT, SELECTOR))
        try:
            value, agree, total = read_deaddrop()
            print("consensus    : %d/%d providers agree" % (agree, total))
            report(value)

            if previous is None:
                print("\n[*] baseline recorded")
            elif value != previous:
                print("\n[!!] VALUE CHANGED - operator rotated configuration")
                print("     previous: %s" % previous)
                print("     current : %s" % value)
            else:
                print("\n[ ] unchanged since last poll")

            previous = value
            state["last_value"] = value
            state["last_seen"] = stamp
            save_state(args.state, state)

        except Exception as e:
            print("[!] read failed: %s" % e, file=sys.stderr)

        if not args.watch:
            break
        time.sleep(args.watch)


if __name__ == "__main__":
    main()
