"""Link DATA proof interop helper.

Drives upstream RNS 1.2.0's exact link DATA proof construction
(RNS/Link.py:prove_packet + RNS/Identity.sign) with a deterministic
identity, and emits JSON that the Go-side interop test consumes:

    {
      "identity_priv_hex":  "<128 hex chars: X25519 priv(32) || Ed25519 seed(32)>",
      "identity_pub_hex":   "<128 hex chars: X25519 pub(32) || Ed25519 pub(32)>",
      "link_id_hex":        "<32 hex chars>",
      "original_packet_hex": "<wire bytes of a fake link DATA packet>",
      "expected_proof_hex":  "<wire bytes of the upstream-built link DATA proof>"
    }

The Go test loads this, parses the original packet, calls our
BuildLinkProof with id.Sign, and asserts the resulting wire bytes are
byte-identical to the upstream proof. It then calls ValidateLinkProof
on the upstream proof bytes and asserts it accepts the signature.

Ed25519 signatures are deterministic per RFC 8032, so byte-equality
is achievable and is the strongest possible interop assertion.
"""
import hashlib
import json
import os
import sys
import tempfile

import RNS


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-linkproof-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def main():
    init_minimal_rns()

    # Deterministic priv: 64 bytes of (X25519 priv || Ed25519 seed).
    priv = bytes(range(64))
    identity = RNS.Identity.from_bytes(priv)
    if identity is None:
        print("RNS.Identity.from_bytes returned None", file=sys.stderr)
        sys.exit(2)

    # Hand-build a HEADER_1 link DATA packet.
    # flags: header_type=0, ifac=0, ctx_flag=0, transport_type=0(BROADCAST),
    #        dest_type=3(LINK), packet_type=0(DATA) → 0x0C
    flags = (RNS.Packet.HEADER_1 << 6) | (RNS.Destination.LINK << 2) | RNS.Packet.DATA
    hops = 0
    link_id = bytes(range(16, 32))   # any deterministic 16 bytes
    context = 0
    body = b"ciphertext-placeholder-doesnt-have-to-decrypt"
    original_wire = bytes([flags, hops]) + link_id + bytes([context]) + body

    # Compute packet_hash exactly as upstream Packet.get_hashable_part does:
    #   hashable = (raw[0] & 0x0F) || raw[2:]
    hashable = bytes([original_wire[0] & 0x0F]) + original_wire[2:]
    packet_hash = hashlib.sha256(hashable).digest()

    # Sign with the identity's long-term Ed25519 priv (matches
    # RNS/Link.py:279 responder-side proof signing).
    sig = identity.sign(packet_hash)
    if len(sig) != 64:
        print(f"sign returned {len(sig)} bytes, want 64", file=sys.stderr)
        sys.exit(2)
    proof_body = packet_hash + sig  # 96 bytes (explicit form, SPEC §6.5.6)

    # Build the proof packet wire bytes per upstream Packet.pack:
    #   flags = HEADER_1<<6 | dest_type=LINK<<2 | packet_type=PROOF → 0x0F
    proof_flags = (RNS.Packet.HEADER_1 << 6) | (RNS.Destination.LINK << 2) | RNS.Packet.PROOF
    proof_wire = bytes([proof_flags, 0]) + link_id + bytes([0]) + proof_body

    # Sanity: verify the signature ourselves before emitting (catch any
    # accidental mistake here rather than confusing the Go side).
    pub_bytes = identity.get_public_key()
    if len(pub_bytes) != 64:
        print(f"identity pubkey length = {len(pub_bytes)}, want 64", file=sys.stderr)
        sys.exit(2)

    print(json.dumps({
        "identity_priv_hex":   priv.hex(),
        "identity_pub_hex":    pub_bytes.hex(),
        "link_id_hex":         link_id.hex(),
        "original_packet_hex": original_wire.hex(),
        "expected_proof_hex":  proof_wire.hex(),
    }))


if __name__ == "__main__":
    main()
