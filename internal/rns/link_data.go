package rns

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Link DATA wire format (SPEC §6.4): a regular DATA packet whose outer
// header has dest_type=LINK and dest_hash=link_id; the body is the
// link-form Token ciphertext (no eph_pub prefix; session keys are
// pre-derived from the handshake).
//
// Link DATA proofs (SPEC §6.5.6) are always the explicit 96-byte form
// (packet_hash || signature). The signature is computed with the
// link-derived signing key (used as an Ed25519 seed), NOT either side's
// long-term Ed25519 priv. Both sides share the same session keys, so
// either can sign and either can verify.

// BuildLinkDataPacket encrypts plaintext under the link's session keys
// and wraps the ciphertext in a Reticulum DATA packet addressed to the
// link.
func BuildLinkDataPacket(linkID, signing, encryption, plaintext []byte) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes, got %d", IdentityHashLen, len(linkID))
	}
	ciphertext, err := LinkTokenEncrypt(plaintext, signing, encryption)
	if err != nil {
		return nil, fmt.Errorf("link encrypt: %w", err)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextNone,
		Data:            ciphertext,
	}, nil
}

// ParseLinkDataPacket decrypts the payload of a DATA packet that
// arrived addressed to this link's link_id. Verifies the wire form is
// link DATA (dest_type=LINK), then runs the link-form Token decryptor.
func ParseLinkDataPacket(p *Packet, signing, encryption []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketData {
		return nil, fmt.Errorf("packet_type %d is not DATA", p.PacketType)
	}
	if p.DestinationType != DestinationLink {
		return nil, fmt.Errorf("dest_type %d is not LINK", p.DestinationType)
	}
	if p.Context != ContextNone {
		return nil, fmt.Errorf("link DATA context = 0x%02x, want 0x00", p.Context)
	}
	return LinkTokenDecrypt(p.Data, signing, encryption)
}

// BuildLinkProof builds the explicit-form (96-byte) PROOF packet that
// acknowledges receipt of an inbound link DATA packet (SPEC §6.5.6).
// Per upstream RNS 1.2.0 link DATA proofs are ALWAYS explicit
// regardless of the global use_implicit_proof setting.
//
// The signature is over SHA-256(original.HashablePart()), signed with
// the link-derived signing_key (used as an Ed25519 seed). Both sides
// have the same signing_key from the HKDF, so either side can sign and
// either can verify proofs on this link.
func BuildLinkProof(linkID, signingSeed []byte, original *Packet) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	if len(signingSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes (Ed25519 seed)", ed25519.SeedSize)
	}
	if original == nil {
		return nil, errors.New("nil original packet")
	}

	hashable, err := original.HashablePart()
	if err != nil {
		return nil, fmt.Errorf("hashable part: %w", err)
	}
	digest := sha256.Sum256(hashable)
	priv := ed25519.NewKeyFromSeed(signingSeed)
	sig := ed25519.Sign(priv, digest[:])

	// Explicit form body: packet_hash || signature
	body := make([]byte, 0, ProofBodyExplicitLen)
	body = append(body, digest[:]...)
	body = append(body, sig...)

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketProof,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextNone, // proof-ness is in packet_type, not context
		Data:            body,
	}, nil
}

// ValidateLinkProof verifies an inbound explicit-form link DATA proof
// against the signing seed (which both sides share). Returns the
// 32-byte packet_hash on success — callers can use it to match against
// outstanding PacketReceipts.
func ValidateLinkProof(p *Packet, signingSeed []byte) ([]byte, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketProof {
		return nil, fmt.Errorf("packet_type %d is not PROOF", p.PacketType)
	}
	if p.DestinationType != DestinationLink {
		return nil, fmt.Errorf("dest_type %d is not LINK", p.DestinationType)
	}
	if p.Context != ContextNone {
		return nil, fmt.Errorf("link DATA proof context = 0x%02x, want 0x00", p.Context)
	}
	if len(p.Data) != ProofBodyExplicitLen {
		return nil, fmt.Errorf("link proof must be explicit form (%d bytes), got %d", ProofBodyExplicitLen, len(p.Data))
	}
	if len(signingSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("signing seed must be %d bytes", ed25519.SeedSize)
	}

	packetHash := p.Data[:32]
	sig := p.Data[32:]
	pub := ed25519.NewKeyFromSeed(signingSeed).Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, packetHash, sig) {
		return nil, errors.New("link proof signature invalid")
	}
	return append([]byte(nil), packetHash...), nil
}

// Context byte for KEEPALIVE on a link (SPEC §6 / RNS source).
const ContextKeepalive = 0xFA

// BuildLinkKeepalive builds a small DATA packet with context=KEEPALIVE
// addressed to the link, used to refresh the activity timer at both
// ends. Body is a single 0x00 byte (matches upstream RNS, which sends
// `bytes([0x00])` as the keepalive payload).
func BuildLinkKeepalive(linkID []byte) (*Packet, error) {
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextKeepalive,
		Data:            []byte{0x00},
	}, nil
}
