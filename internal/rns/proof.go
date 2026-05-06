package rns

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// PROOF body lengths (SPEC §6.5.1). The receiver length-dispatches between
// the two; there is no flag or context bit that distinguishes them. We emit
// the implicit form, which is the upstream default (Reticulum 1.2.0 has
// `__use_implicit_proof = True` by default).
const (
	ProofBodyImplicitLen = 64       // signature only
	ProofBodyExplicitLen = 32 + 64  // packet_hash || signature
)

// ProveOpportunistic builds a PROOF packet (packet_type=PROOF, context=NONE)
// acknowledging receipt of an opportunistic DATA packet, per SPEC §6.5.
//
// Without this acknowledgement, the sender's PacketReceipt never resolves
// and their retransmit queue fires, hammering us with the same message
// repeatedly until it gives up.
//
// The signature is computed over the FULL 32-byte SHA-256 of the original
// packet's hashable part (NOT truncated to 16 bytes — that truncation is
// only used for the proof's outer dest_hash slot). Receivers length-dispatch
// the body between implicit (64B sig) and explicit (32B hash + 64B sig);
// upstream emits implicit by default and we follow suit.
//
// The outer dest_hash is packet_hash[:16] — a synthetic ProofDestination
// that relays look up in their reverse_table to route the proof back along
// the reverse path to the original sender.
func ProveOpportunistic(receiver *Identity, original *Packet) (*Packet, error) {
	if receiver == nil {
		return nil, errors.New("nil receiver identity")
	}
	if original == nil {
		return nil, errors.New("nil original packet")
	}

	hashable, err := original.HashablePart()
	if err != nil {
		return nil, fmt.Errorf("hashable part: %w", err)
	}
	digest := sha256.Sum256(hashable)
	sig := receiver.Sign(digest[:])
	if len(sig) != ProofBodyImplicitLen {
		return nil, fmt.Errorf("unexpected signature length %d", len(sig))
	}

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketProof,
		Hops:            0,
		DestHash:        append([]byte(nil), digest[:IdentityHashLen]...),
		Context:         ContextNone,
		Data:            sig,
	}, nil
}
