package rns

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

// Hash math for the Resource protocol. Centralised here so wire-
// format builders, parsers, and the sender/receiver state machines
// all reach for the same SHA-256 inputs — a one-byte off-by-one
// here breaks interop silently.

// NewResourceRandomHash returns ResourceRandomHashSize random bytes
// suitable for use as either the body prefix OR the advertisement's
// `r` field. Callers MUST allocate two distinct values per resource —
// the body prefix and the `r` salt are deliberately decorrelated
// (SPEC §10.8 callout).
func NewResourceRandomHash() ([]byte, error) {
	b := make([]byte, ResourceRandomHashSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// ResourceHash computes `h = SHA256(plaintext_body || r)` per SPEC
// §10.2 step 5. `plaintext_body` is the ORIGINAL caller bytes —
// before the optional 4-byte body-prefix is prepended, before
// compression, before encryption. Verifies the resource end-to-end
// against tampering anywhere along the wire.
func ResourceHash(plaintextBody, randomHashR []byte) []byte {
	if len(randomHashR) != ResourceRandomHashSize {
		// Programming error — no recovery, return zero. Callers should
		// never reach here; a panic would crash the daemon over a
		// recoverable mistake. The downstream comparison will fail
		// loudly via ErrResourceHashMismatch.
		return make([]byte, sha256.Size)
	}
	sum := sha256.Sum256(append(append([]byte(nil), plaintextBody...), randomHashR...))
	return sum[:]
}

// ResourceExpectedProof computes `expected_proof = SHA256(plaintext_body
// || h)` per SPEC §10.2 step 5. The receiver's RESOURCE_PRF body
// payload is `h || expected_proof`; the sender pre-computes this so
// validation is a constant-time comparison instead of a re-hash.
func ResourceExpectedProof(plaintextBody, hash []byte) []byte {
	if len(hash) != sha256.Size {
		return make([]byte, sha256.Size)
	}
	sum := sha256.Sum256(append(append([]byte(nil), plaintextBody...), hash...))
	return sum[:]
}

// ResourceMapHash computes the 4-byte fingerprint of one part:
// `SHA256(part_ciphertext || r)[:4]` per SPEC §10.2 step 7. The
// hashmap is the concatenation of these for every part. Receivers
// match inbound parts to hashmap positions by recomputing this and
// scanning the bounded `hashmap[height : height + window]` window.
func ResourceMapHash(partCiphertext, randomHashR []byte) []byte {
	if len(randomHashR) != ResourceRandomHashSize {
		return make([]byte, ResourceMapHashLen)
	}
	sum := sha256.Sum256(append(append([]byte(nil), partCiphertext...), randomHashR...))
	return sum[:ResourceMapHashLen]
}

// SplitParts slices `wireBlob` (the link-encrypted body) into
// per-part ciphertext chunks of ResourceSDU bytes. The last chunk is
// short. Returns nil on empty input — a zero-length resource is
// invalid (the caller should fall back to an empty Link DATA packet).
//
// Critically, parts are SLICES of the encrypted blob, not separately
// encrypted units (SPEC §10.12). A receiver that calls link.decrypt
// on each part fails — the per-part bytes are missing the Token
// header. Decrypt happens once over the concatenation in assemble().
func SplitParts(wireBlob []byte) [][]byte {
	if len(wireBlob) == 0 {
		return nil
	}
	parts := make([][]byte, 0, (len(wireBlob)+ResourceSDU-1)/ResourceSDU)
	for off := 0; off < len(wireBlob); off += ResourceSDU {
		end := off + ResourceSDU
		if end > len(wireBlob) {
			end = len(wireBlob)
		}
		// Defensive copy so callers mutating the slice can't poison
		// our hashmap-aligned references.
		parts = append(parts, append([]byte(nil), wireBlob[off:end]...))
	}
	return parts
}

// BuildHashmap concatenates per-part map_hashes into the wire-form
// hashmap bytes. Returns ErrResourceCollisionGuard if two parts
// within the COLLISION_GUARD_SIZE sliding window collide on their
// 4-byte map_hash — caller should regenerate `r` and rebuild.
//
// The duplicate detection is what makes the receiver's bounded-
// window search safe: it only scans `parts[height : height + window]`
// for a matching map_hash, so a colliding pair within that range
// would mis-place chunks.
func BuildHashmap(parts [][]byte, randomHashR []byte) ([]byte, error) {
	if len(randomHashR) != ResourceRandomHashSize {
		return nil, errors.New("resource: random_hash must be 4 bytes")
	}
	out := make([]byte, 0, len(parts)*ResourceMapHashLen)
	guard := make([][]byte, 0, CollisionGuardSize)
	for _, p := range parts {
		mh := ResourceMapHash(p, randomHashR)
		for _, prev := range guard {
			if bytesEqual(prev, mh) {
				return nil, ErrResourceCollisionGuard
			}
		}
		guard = append(guard, mh)
		if len(guard) > CollisionGuardSize {
			guard = guard[1:]
		}
		out = append(out, mh...)
	}
	return out, nil
}
