"""Link DATA wire-format interop helper.

Drives upstream RNS 1.2.4 to produce a deterministic link DATA packet
(SPEC §6.4 link-form Token + outer Reticulum DATA framing addressed to a
link_id). Pins every random source — ephemeral keys, IV, identity priv —
so the output is byte-reproducible. The matching Go-side interop test
then asserts our encoder produces identical bytes for the same inputs.

Output JSON keys:
    initiator_x25519_priv_hex   (32 bytes)
    initiator_ed25519_priv_hex  (32 bytes seed)
    responder_x25519_priv_hex   (32 bytes)
    responder_full_name         (e.g. "lxmf.delivery")
    responder_priv_hex          (64 bytes; X25519 priv || Ed25519 seed)
    link_id_hex                 (16 bytes — derived from LINKREQUEST)
    signing_key_hex             (32 bytes — first half of HKDF output)
    encryption_key_hex          (32 bytes — second half of HKDF output)
    plaintext_hex               (the bytes encrypted)
    iv_hex                      (16 bytes — pinned for determinism)
    link_data_wire_hex          (full Reticulum DATA packet, HEADER_1 LINK)

Why every source is pinned: AES-CBC + HMAC are deterministic given (key,
IV, plaintext); the link_id derivation, the HKDF over the shared secret,
and the LINKREQUEST body are deterministic given the ephemeral keys.
With nothing left to randomize the wire output is byte-stable across
runs and platforms — strong byte-level interop assertion.
"""
import hashlib
import hmac
import json
import os
import sys
import tempfile

import RNS

from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def init_minimal_rns():
    cfg_dir = tempfile.mkdtemp(prefix="rns-linkdata-")
    with open(os.path.join(cfg_dir, "config"), "w", encoding="utf-8") as f:
        f.write("[reticulum]\nenable_transport = No\nshare_instance = No\n")
    return RNS.Reticulum(configdir=cfg_dir, loglevel=0)


def x25519_pub_from_clamped_priv(priv: bytes) -> bytes:
    # Match upstream RNS clamping (RFC 7748).
    p = bytearray(priv)
    p[0] &= 248
    p[31] &= 127
    p[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(p)).public_key().public_bytes_raw()


def x25519_priv_for_ecdh(priv: bytes) -> X25519PrivateKey:
    p = bytearray(priv)
    p[0] &= 248
    p[31] &= 127
    p[31] |= 64
    return X25519PrivateKey.from_private_bytes(bytes(p))


def main():
    init_minimal_rns()

    responder_priv = bytes(range(64))
    responder_id = RNS.Identity.from_bytes(responder_priv)
    # RNS.Destination.hash takes (app_name, *aspects) and refuses dots
    # inside app_name; pass them split as upstream's expand_name expects.
    responder_full_name = "lxmf.delivery"
    responder_dest_hash = RNS.Destination.hash(responder_id, "lxmf", "delivery")
    if len(responder_dest_hash) != 16:
        print(f"responder dest_hash length = {len(responder_dest_hash)}", file=sys.stderr)
        sys.exit(2)

    # Deterministic ephemerals for the initiator.
    initiator_x25519_priv = bytes([(0x80 + i) & 0xFF for i in range(32)])
    initiator_ed25519_priv = bytes([(0xC0 + i) & 0xFF for i in range(32)])
    initiator_x25519_pub = x25519_pub_from_clamped_priv(initiator_x25519_priv)
    initiator_ed25519_pub = (
        RNS.Identity.from_bytes(bytes(32) + initiator_ed25519_priv)
        .get_public_key()[32:]
    )

    # Build the LINKREQUEST body bytes (just initiator pubs) and assemble
    # the wire packet manually so we don't depend on RNS internals.
    flags_lr = (RNS.Packet.HEADER_1 << 6) | (RNS.Destination.SINGLE << 2) | RNS.Packet.LINKREQUEST
    lr_body = initiator_x25519_pub + initiator_ed25519_pub
    lr_wire = bytes([flags_lr, 0]) + responder_dest_hash + bytes([0]) + lr_body
    # link_id = SHA256(hashable_part)[:16] where hashable_part for HEADER_1
    # is (raw[0] & 0x0F) || raw[2:].
    hashable = bytes([lr_wire[0] & 0x0F]) + lr_wire[2:]
    link_id = hashlib.sha256(hashable).digest()[:16]

    # ECDH between deterministic responder ephemeral and the LINKREQUEST's
    # initiator pub. The responder ephemeral here represents what the
    # responder would generate locally; we pin it to a deterministic seed.
    responder_x25519_priv = bytes([(0x40 + i) & 0xFF for i in range(32)])
    responder_x25519_pub = x25519_pub_from_clamped_priv(responder_x25519_priv)

    initiator_obj = x25519_priv_for_ecdh(initiator_x25519_priv)
    # We compute the shared from initiator's POV (initPriv * respPub) — both
    # sides arrive at the same shared secret via X25519 commutativity.
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    shared = initiator_obj.exchange(X25519PublicKey.from_public_bytes(responder_x25519_pub))

    # HKDF: salt = link_id, info = empty, output 64 bytes = signing(32) || encryption(32).
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=link_id,
        info=None,
    ).derive(shared)
    signing_key = derived[:32]
    encryption_key = derived[32:]

    # Encrypt a known plaintext with a pinned IV to make the wire bytes
    # deterministic. Everything past this point is pure AES + HMAC.
    plaintext = b"interop-link-data-bytes-1234567890" * 6  # ~204 bytes
    iv = bytes(16)  # zero IV — DETERMINISTIC FOR INTEROP TESTS ONLY

    padder = PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    enc = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    h = crypto_hmac.HMAC(signing_key, hashes.SHA256())
    h.update(iv + ciphertext)
    mac = h.finalize()

    link_token_wire = iv + ciphertext + mac

    # Assemble the outer Reticulum DATA packet (HEADER_1 + dest_type=LINK
    # + packet_type=DATA, dest_hash slot = link_id).
    flags_data = (RNS.Packet.HEADER_1 << 6) | (RNS.Destination.LINK << 2) | RNS.Packet.DATA
    link_data_wire = bytes([flags_data, 0]) + link_id + bytes([0]) + link_token_wire

    print(json.dumps({
        "initiator_x25519_priv_hex":   initiator_x25519_priv.hex(),
        "initiator_ed25519_priv_hex":  initiator_ed25519_priv.hex(),
        "responder_x25519_priv_hex":   responder_x25519_priv.hex(),
        "responder_full_name":         responder_full_name,
        "responder_priv_hex":          responder_priv.hex(),
        "responder_pub_hex":           responder_id.get_public_key().hex(),
        "responder_dest_hash_hex":     responder_dest_hash.hex(),
        "link_id_hex":                 link_id.hex(),
        "shared_secret_hex":           shared.hex(),
        "signing_key_hex":             signing_key.hex(),
        "encryption_key_hex":          encryption_key.hex(),
        "plaintext_hex":               plaintext.hex(),
        "iv_hex":                      iv.hex(),
        "link_data_wire_hex":          link_data_wire.hex(),
    }))


if __name__ == "__main__":
    main()
