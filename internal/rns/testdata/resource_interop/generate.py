#!/usr/bin/env python3
"""Generate golden wire-byte fixtures for the Go Resource interop test.

Run: python generate.py

Outputs bytes files this directory the Go test can load:
  - adv_minimal.bin    A 3-part single-segment advertisement
  - adv_compressed.bin Same shape but with the c flag set
  - req_not_exhausted.bin
  - req_exhausted.bin
  - hmu_segment2.bin
  - prf.bin
  - cancel.bin

Bytes are produced via the same umsgpack the upstream RNS code uses.
The Go test parses each fixture and asserts every field.

Pin: RNS 1.2.4 — bump this comment if the upstream constants drift.
"""

from __future__ import annotations
import os
import sys

# Reuse upstream's bundled umsgpack so wire bytes are byte-identical
# to what RNS emits, not whatever a recent vmihailenco version would
# produce on its own.
try:
    import RNS.vendor.umsgpack as umsgpack
except ImportError:
    print("could not import RNS.vendor.umsgpack — install rns first", file=sys.stderr)
    sys.exit(1)

OUT = os.path.dirname(os.path.abspath(__file__))


def write(name: str, payload: bytes) -> None:
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(payload)
    print(f"  wrote {name} ({len(payload)} bytes)")


def main() -> None:
    print("generating resource interop fixtures...")

    # --- ADV: minimal, 3-part, single-segment, encrypted ----------
    h = b"\x11" * 32
    r = bytes([0xAA, 0xBB, 0xCC, 0xDD])
    hashmap = b"\xCA\xFE\x00\x01" + b"\xCA\xFE\x00\x02" + b"\xCA\xFE\x00\x03"
    adv = {
        "t": 544,                # transfer size
        "d": 484,                # data size
        "n": 3,                  # parts
        "h": h,
        "r": r,
        "o": h,                  # single-segment so o == h
        "i": 1,                  # 1-based segment index
        "l": 1,                  # total segments
        "q": None,               # not a Link request/response
        "f": 0x01,               # encrypted flag (e=1)
        "m": hashmap,
    }
    write("adv_minimal.bin", umsgpack.packb(adv))

    # --- ADV: compressed flavor (c=1) -----------------------------
    adv["f"] = 0x01 | 0x02  # e | c
    write("adv_compressed.bin", umsgpack.packb(adv))

    # --- REQ: not exhausted, 2 parts requested --------------------
    req = bytes([0x00])                 # HASHMAP_NOT_EXHAUSTED
    req += b"\x22" * 32                 # resource_hash
    req += b"\x01\x02\x03\x04"          # requested map_hash 1
    req += b"\x05\x06\x07\x08"          # requested map_hash 2
    write("req_not_exhausted.bin", req)

    # --- REQ: exhausted (HMU prompt) ------------------------------
    req = bytes([0xFF])                 # HASHMAP_EXHAUSTED
    req += b"\xDE\xAD\xBE\xEF"          # last_map_hash
    req += b"\x33" * 32                 # resource_hash
    write("req_exhausted.bin", req)

    # --- HMU: segment 2 with one map_hash -------------------------
    hmu = b"\x44" * 32                  # resource_hash
    hmu += umsgpack.packb([2, b"\xAB\xCD\xEF\x01"])
    write("hmu_segment2.bin", hmu)

    # --- PRF --------------------------------------------------------
    prf = b"\x55" * 32 + b"\x66" * 32
    write("prf.bin", prf)

    # --- ICL/RCL ---------------------------------------------------
    write("cancel.bin", b"\x77" * 32)

    print("done.")


if __name__ == "__main__":
    main()
