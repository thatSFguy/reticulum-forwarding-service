# Resource transfer — security audit

**Scope:** the RNS Resource transfer implementation in `internal/rns/`
(`resource.go`, `resource_hash.go`, `resource_adv.go`, `resource_wire.go`,
`resource_sender.go`, `resource_receiver.go`, `resource_dispatch.go`).
Audited at the resource-transfer branch, 2026-05-10.

**Out of scope:** Reticulum Link layer (audited separately during the
LRPROOF interop work), msgpack library safety (vmihailenco/msgpack/v5
upstream).

---

## Findings

### F1 — bz2 decompression bomb (FIXED)

**Class:** memory amplification.

A peer-controlled ADV with `c=1` (compressed) carries a body that bz2-
expands to many times its on-wire size. A 256 KiB encrypted body can
legitimately decompress to gigabytes; an unbounded
`bz2.decompress(data)` call would OOM the daemon.

**Fix applied:** `ParseResourceAdv` rejects any ADV with the `c` flag
set, returning `ErrResourceTooLarge` with a diagnostic message. fwdsvc
never produces `c=1` ADVs and has no use case for receiving compressed
resources (every legitimate inbound is an LXMF DM body well under the
per-message limit). If compressed inbound resources become a real
requirement later, replace the reject with bounded
`bz2.NewReader(io.LimitReader(stream, MaxDecompressedResourceLen))` in
`ResourceReceiver.assemble`, with a post-decompress size check against
`MaxDecompressedResourceLen`.

Mirrors the upstream RNS 1.1.9 fix
(`bz2.BZ2Decompressor.decompress(data, max_length=...)` + `eof` check).

---

### F2 — unbounded inbound receivers per link (FIXED)

**Class:** resource exhaustion.

A misbehaving peer that sent a flood of distinct-hash ADVs over a
single link would spawn one `ResourceReceiver` goroutine per ADV.
Each receiver lives up to `DefaultLinkSendTimeout = 30s` before its
context fires. At 100 distinct-hash ADVs/sec, the daemon accumulates
~3000 goroutines and their parts buffers (each up to ~30 KiB) until
the first generation expires — a slow leak that an attacker could
sustain indefinitely.

**Fix applied:** `MaxConcurrentInboundResourcesPerLink = 4` enforced
in `Transport.openResourceReceiver`. New ADVs beyond the cap are
rejected with a logged error (no RCL emitted, since the rejection
itself is the signal). Four concurrent inbound transfers per link is
more than any legitimate workload needs and small enough to bound
worst-case memory at ~120 KiB per active link.

---

### F3 — sender allocation bound at construction (already enforced)

**Class:** memory.

`PackResourceAdv` rejects `n > HashmapMaxLen = 74` parts at the
sender side; we never produce a multi-segment-hashmap ADV. fwdsvc
replies are at most a few KiB, comfortably within 74 parts × ~464
bytes = ~33 KiB total wire size. If a future caller passes a body
that would exceed this, `NewResourceSender` returns an explicit
"multi-segment not yet implemented" error — loud and safe.

---

### F4 — receiver allocation bound at construction (already enforced)

**Class:** memory.

`ParseResourceAdv` rejects ADVs with `t` or `d` over
`MaxAcceptedResourceSize = 256 KiB`, or `n` over `HashmapMaxLen = 74`,
**before** any state allocation. The receiver's parts buffer is
sized to `n × *byte` (≤ 74 nil pointers ≈ 600 bytes of upfront
allocation); per-part ciphertext slices are added as parts arrive,
and the parts buffer caps at `n × ResourceSDU = 74 × 464 ≈ 33 KiB`.

---

### F5 — ADV parse handles malformed input (verified)

**Class:** DoS via crash.

`ParseResourceAdv` returns `ErrResourceADVMalformed` for every
non-conforming msgpack input — including nil bodies, empty bodies,
truncated bytes, and arbitrary garbage. `TestInteropMalformedADVNoPanic`
covers the panic-vs-error contract over a representative set of
malformed inputs.

---

### F6 — encryption layering matches SPEC §10.12 (verified)

**Class:** crypto correctness.

The full `random_hash_prefix || compressed?body` blob is link-Token-
encrypted ONCE up-front. Per-part wire bytes are RAW slices of that
ciphertext (no per-part Token framing). Receiver concatenates parts,
decrypts the whole blob in one operation, strips the 4-byte prefix.

This is the spec's most common implementation trap — a receiver that
calls `link.decrypt(part)` on each inbound RESOURCE packet fails with
HMAC errors on every chunk. fwdsvc's `ResourceReceiver.assemble`
correctly does the single decrypt over the concatenation.

Tampering detection:

- A tampered part's `map_hash = SHA256(tampered || r)[:4]` won't match
  any hashmap slot → receiver rejects (`placePart` returns "part
  map_hash not in remaining hashmap").
- An attacker swapping two parts produces wrong-positioned ciphertext
  that won't decrypt-and-hash to `h` → assemble fails with
  `ErrResourceHashMismatch`.
- The hashmap itself is in the ADV body, which is link-Token-
  encrypted+HMAC'd → not tamperable by transit relays.

---

### F7 — proof verification is constant-time (verified)

**Class:** timing side-channel.

`ResourceSender.Run` validates the inbound `RESOURCE_PRF` body via
`proofEqualsConstantTime(prf.FullProof, rs.expectedProof)`, which
XORs every byte before testing. No early-exit on first mismatch. Even
though the link is typically not directly observable to a remote
adversary, constant-time compare is defensive practice with no
performance cost on 32-byte buffers.

---

### F8 — PRF / RCL / ICL spoofing (KNOWN LIMITATION)

**Class:** integrity.

`RESOURCE_PRF` is a PROOF-type packet not encrypted at the resource
layer (per SPEC §10.3 + upstream `Packet.pack:195-197`). Same for
`RESOURCE_RCL` and `RESOURCE_ICL` — they're encrypted at the link
layer but not signed at the resource layer. An adversary that:

1. Knows or guesses the link_id (16 random bytes per link).
2. Knows or guesses the resource_hash (32 bytes; observable to
   transit relays but not to off-path attackers).
3. Has access to the link's session keys (for RCL/ICL — required to
   produce the link-encrypted body).

…can forge a PRF/RCL/ICL to terminate a transfer.

Practically:

- An off-path attacker can't get any of these → no risk.
- An on-path transit relay sees link_id and resource_hash and has the
  session keys (it routed the LINKREQUEST/LRPROOF). It can already
  drop packets to disrupt transfers; forging a PRF/RCL/ICL is a
  marginal escalation, not a new capability.
- An attacker on the same broadcast medium (LoRa, etc.) without the
  link key can see link_ids and resource_hashes but can't produce
  link-encrypted RCL/ICL bodies. They CAN forge unencrypted PRFs;
  this lets them prematurely "complete" a transfer at the sender if
  they also know the body plaintext (needed to compute
  `expected_proof`). Since the body is link-encrypted on the wire,
  they don't know it.
- **Net risk:** an on-path relay can disrupt transfers; an off-path
  attacker cannot.

**Decision:** accept. RNS doesn't provide resource-layer
authentication; adopting a non-standard scheme would break interop
with Sideband / MeshChat / NomadNet. A real fix requires a spec
change.

---

### F9 — goroutine cleanup on link teardown (verified)

**Class:** resource leak.

`LinkManager.CloseLink` calls `closeResourcesForLink(linkID)` which
iterates the sender + receiver registries by hex-prefix match, sends
HandleCancel to each, and removes them from the registry. Both
`ResourceSender.Run` and `ResourceReceiver.Run` defer
`unregisterResource` so an exit by any path (success, ctx cancel,
proof mismatch, peer cancel) frees its registry slot.

`TestSenderCloseLinkCancelsTransfer` verifies a close-mid-transfer
exits the sender within 2 seconds with `ErrResourceCancelled`.

---

### F10 — collision-guard sender retries are bounded (verified)

**Class:** liveness.

`NewResourceSender` regenerates `randomR` on hashmap collision up to
4 times. With 4-byte map_hashes inside a 75-part window, single-
attempt collision probability is ~1e-15; four retries make
unrecoverable failure essentially impossible. Returning
`ErrResourceCollisionGuard` after 4 failures is a clear, loud signal
rather than infinite spinning.

---

### F11 — receive-side hashmap-segment misalignment rejected (verified)

**Class:** correctness.

`ResourceReceiver.applyHmu` rejects HMU packets whose
`segment_index` doesn't match `hashmapKnownPrefix / HashmapMaxLen` —
the next expected boundary. Mirrors upstream
`Resource.py:1043-1046`. A misbehaving sender that emits
out-of-sequence HMUs gets the receiver to log + RCL + abandon
cleanly, no buffer corruption.

---

## Summary

| Finding | Class | Status |
|---|---|---|
| F1 — bz2 decompression bomb | memory | **FIXED** (reject c=1) |
| F2 — unbounded inbound receivers | resource | **FIXED** (cap 4 / link) |
| F3 — sender allocation bound | memory | already enforced |
| F4 — receiver allocation bound | memory | already enforced |
| F5 — malformed-ADV no-panic | DoS | already enforced + tested |
| F6 — encryption layering | crypto | spec-correct |
| F7 — proof const-time compare | timing | implemented |
| F8 — PRF/RCL/ICL spoofing | integrity | accepted limitation |
| F9 — goroutine cleanup | leak | implemented + tested |
| F10 — collision-guard retries bounded | liveness | implemented |
| F11 — HMU misalignment rejection | correctness | implemented |

Two fixes shipped in stage 6. No outstanding findings block release.
