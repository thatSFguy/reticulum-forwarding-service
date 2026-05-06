package rns

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// fakeOpportunisticData builds a Reticulum DATA packet shaped like an
// inbound opportunistic LXMF — used only as a stand-in for proof tests.
func fakeOpportunisticData(t *testing.T, destHash []byte) *Packet {
	t.Helper()
	return &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationSingle,
		PacketType:      PacketData,
		Hops:            0,
		DestHash:        destHash,
		Context:         ContextNone,
		Data:            []byte("fake encrypted body"),
	}
}

func TestProveOpportunisticImplicitForm(t *testing.T) {
	id, _ := NewIdentity()
	original := fakeOpportunisticData(t, id.DestinationHashFor(FullName("lxmf", "delivery")))

	proof, err := ProveOpportunistic(id, original)
	if err != nil {
		t.Fatal(err)
	}

	if proof.PacketType != PacketProof {
		t.Errorf("packet_type = %d, want %d (PROOF)", proof.PacketType, PacketProof)
	}
	if proof.Context != ContextNone {
		t.Errorf("context = 0x%02x, want 0x00 (NONE)", proof.Context)
	}
	if proof.DestinationType != DestinationSingle {
		t.Errorf("dest_type = %d, want %d", proof.DestinationType, DestinationSingle)
	}
	if proof.HeaderType != HeaderType1 {
		t.Errorf("header_type = %d, want HEADER_1", proof.HeaderType)
	}
	if len(proof.Data) != ProofBodyImplicitLen {
		t.Errorf("body length = %d, want %d (implicit form)", len(proof.Data), ProofBodyImplicitLen)
	}
}

func TestProveOpportunisticDestHashIsPacketHashPrefix(t *testing.T) {
	id, _ := NewIdentity()
	original := fakeOpportunisticData(t, id.DestinationHashFor(FullName("lxmf", "delivery")))

	hashable, err := original.HashablePart()
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest := sha256.Sum256(hashable)

	proof, err := ProveOpportunistic(id, original)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(proof.DestHash, expectedDigest[:IdentityHashLen]) {
		t.Errorf("proof dest_hash mismatch\n got %x\nwant %x", proof.DestHash, expectedDigest[:IdentityHashLen])
	}
}

func TestProveOpportunisticSignatureValidates(t *testing.T) {
	id, _ := NewIdentity()
	original := fakeOpportunisticData(t, id.DestinationHashFor(FullName("lxmf", "delivery")))

	hashable, _ := original.HashablePart()
	digest := sha256.Sum256(hashable)

	proof, err := ProveOpportunistic(id, original)
	if err != nil {
		t.Fatal(err)
	}
	// Implicit form: body IS the signature.
	sig := proof.Data
	pub := id.PublicKey()[32:] // Ed25519 half
	if !Validate(pub, digest[:], sig) {
		t.Errorf("proof signature did not verify against SHA256(hashable_part)")
	}
}

func TestProveOpportunisticRejectsBadInputs(t *testing.T) {
	id, _ := NewIdentity()
	if _, err := ProveOpportunistic(nil, fakeOpportunisticData(t, make([]byte, IdentityHashLen))); err == nil {
		t.Error("expected error for nil identity")
	}
	if _, err := ProveOpportunistic(id, nil); err == nil {
		t.Error("expected error for nil packet")
	}
}

// TestProofUsesPacketHashNotTruncated guards against a subtle bug: the
// signature input is the full 32-byte SHA-256, NOT the 16-byte truncated
// hash that goes in the proof's outer dest_hash slot. Signing the truncated
// form produces a sig that won't validate against an upstream-style verifier.
func TestProofUsesPacketHashNotTruncated(t *testing.T) {
	id, _ := NewIdentity()
	original := fakeOpportunisticData(t, id.DestinationHashFor(FullName("lxmf", "delivery")))
	hashable, _ := original.HashablePart()
	full := sha256.Sum256(hashable)

	proof, _ := ProveOpportunistic(id, original)
	pub := id.PublicKey()[32:]

	// Should validate against the full 32-byte digest.
	if !Validate(pub, full[:], proof.Data) {
		t.Error("sig must validate against full 32B SHA-256")
	}
	// Must NOT validate against the truncated 16-byte form (otherwise
	// we'd be signing the wrong thing).
	if Validate(pub, full[:IdentityHashLen], proof.Data) {
		t.Error("sig validated against truncated 16B hash — wrong signed-data scope")
	}
}
