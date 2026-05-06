package rns

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestPathRequestDestHashRecomputes is a regression guard: if either NameHash
// or the PLAIN-destination derivation rule (16 zero bytes for identity_hash)
// ever changes, this test fails before users hit a silent network bug.
func TestPathRequestDestHashRecomputes(t *testing.T) {
	nh := NameHash("rnstransport.path.request")
	expectedNameHashHex := "7926bbe7dd7f9aba88b0"
	if hex.EncodeToString(nh) != expectedNameHashHex {
		t.Errorf("NameHash(rnstransport.path.request) = %x, want %s", nh, expectedNameHashHex)
	}

	// For PLAIN destinations, the identity hash is OMITTED — not zero-padded.
	// Per upstream RNS.Destination.hash: addr_hash_material = name_hash only
	// when identity is None.
	d := sha256.Sum256(nh)
	got := hex.EncodeToString(d[:IdentityHashLen])
	if got != PathRequestDestHashHex {
		t.Errorf("path-request dest hash recompute mismatch\n got %s\nwant %s", got, PathRequestDestHashHex)
	}
}

func TestBuildPathRequestStructure(t *testing.T) {
	target := newDummyHash(0xAB)
	pkt, err := BuildPathRequest(target)
	if err != nil {
		t.Fatal(err)
	}

	if pkt.PacketType != PacketData {
		t.Errorf("packet_type = %d, want PacketData", pkt.PacketType)
	}
	if pkt.DestinationType != DestinationPlain {
		t.Errorf("dest_type = %d, want DestinationPlain", pkt.DestinationType)
	}
	if pkt.TransportType != BroadcastTransport {
		t.Errorf("transport_type = %d, want BroadcastTransport", pkt.TransportType)
	}
	if pkt.HeaderType != HeaderType1 {
		t.Errorf("header_type = %d, want HEADER_1", pkt.HeaderType)
	}
	if pkt.Context != ContextNone {
		t.Errorf("context = 0x%02x, want 0x00", pkt.Context)
	}
	expectedDest, _ := hex.DecodeString(PathRequestDestHashHex)
	if !bytes.Equal(pkt.DestHash, expectedDest) {
		t.Errorf("dest_hash = %x, want well-known %x", pkt.DestHash, expectedDest)
	}
	if len(pkt.Data) != PathRequestPayloadLen {
		t.Fatalf("payload length = %d, want %d", len(pkt.Data), PathRequestPayloadLen)
	}
	if !bytes.Equal(pkt.Data[:IdentityHashLen], target) {
		t.Errorf("payload target prefix mismatch: got %x, want %x", pkt.Data[:IdentityHashLen], target)
	}
}

func TestBuildPathRequestRejectsBadTarget(t *testing.T) {
	if _, err := BuildPathRequest(nil); err == nil {
		t.Error("expected error for nil target")
	}
	if _, err := BuildPathRequest(make([]byte, 8)); err == nil {
		t.Error("expected error for short target")
	}
}

func TestBuildPathRequestUsesFreshTagEachCall(t *testing.T) {
	target := newDummyHash(0xCD)
	a, _ := BuildPathRequest(target)
	b, _ := BuildPathRequest(target)
	// Tags are random; two builds back-to-back should differ.
	if bytes.Equal(a.Data[IdentityHashLen:], b.Data[IdentityHashLen:]) {
		t.Error("two BuildPathRequest calls produced the same tag (expected random)")
	}
	// Targets are stable.
	if !bytes.Equal(a.Data[:IdentityHashLen], b.Data[:IdentityHashLen]) {
		t.Error("target half changed between calls")
	}
}

func TestPathRequestTargetExtracts(t *testing.T) {
	target := newDummyHash(0x77)
	pkt, _ := BuildPathRequest(target)
	got, err := PathRequestTarget(pkt.Data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, target) {
		t.Errorf("target extraction mismatch")
	}
}
