package rns

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// PathRequestDestHashHex is the well-known PLAIN destination address that
// path? requests are sent to (SPEC §7.1, §1.2). Verified against upstream
// RNS 1.2.0 — `RNS.Transport.path_request_destination.hash`.
//
// PLAIN destinations have NO identity hash component (per upstream
// `RNS.Destination.hash`: when `identity is None`, `addr_hash_material`
// is just the 10-byte name_hash with nothing appended — NOT name_hash
// concatenated with 16 zero bytes, which is what an earlier draft of our
// notes incorrectly said). Computation:
//
//	name_hash = SHA-256("rnstransport.path.request")[:10]
//	          = 7926bbe7dd7f9aba88b0
//	dest_hash = SHA-256(name_hash)[:16]
//	          = 6b9f66014d9853faab220fba47d02761
//
// TestPathRequestDestHashRecomputes guards against drift in either step.
const PathRequestDestHashHex = "6b9f66014d9853faab220fba47d02761"

// PathRequestPayloadLen is the leaf-client form payload length (SPEC §7.1):
// target_dest_hash(16) || random_tag(16). Transport-enabled nodes append a
// 16-byte transport_id for a 48-byte payload, but we're a leaf, so 32B.
const PathRequestPayloadLen = 32

// BuildPathRequest constructs an SPEC §7.1 path? request for the given target
// destination_hash. Sent on receive of a message from an unknown sender so
// path-aware relays push back a path-response announce carrying the sender's
// public key.
//
// Leaf-client form (no transport_id): payload is target(16) || random_tag(16)
// where random_tag is 16 random bytes used by relay nodes for dedup so the
// same request isn't infinitely re-broadcast.
func BuildPathRequest(targetDestHash []byte) (*Packet, error) {
	if len(targetDestHash) != IdentityHashLen {
		return nil, fmt.Errorf("target dest_hash must be %d bytes, got %d", IdentityHashLen, len(targetDestHash))
	}

	wellKnown, err := hex.DecodeString(PathRequestDestHashHex)
	if err != nil {
		return nil, fmt.Errorf("decode path-request dest hash: %w", err)
	}

	tag := make([]byte, IdentityHashLen)
	if _, err := rand.Read(tag); err != nil {
		return nil, fmt.Errorf("path request tag entropy: %w", err)
	}

	payload := make([]byte, 0, PathRequestPayloadLen)
	payload = append(payload, targetDestHash...)
	payload = append(payload, tag...)

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationPlain,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        wellKnown,
		Context:         ContextNone,
		Data:            payload,
	}, nil
}

// PathRequestTarget extracts the target destination_hash from a path-request
// packet payload (the first 16 bytes). Useful when our service decides to
// answer path requests for our own destinations (not implemented yet —
// transit relay is out of scope).
func PathRequestTarget(payload []byte) ([]byte, error) {
	if len(payload) < IdentityHashLen {
		return nil, errors.New("path request payload too short")
	}
	out := make([]byte, IdentityHashLen)
	copy(out, payload[:IdentityHashLen])
	return out, nil
}
