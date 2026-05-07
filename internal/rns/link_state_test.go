package rns

import (
	"bytes"
	"testing"
)

// TestLinkHandshakeEndToEnd exercises the initiator + responder state
// machines together: alice initiates, bob accepts, both end up with
// matching session keys and active link state.
func TestLinkHandshakeEndToEnd(t *testing.T) {
	bob, _ := NewIdentity()
	bobDest := bob.DestinationHashFor(FullName("vectors", "link"))

	aliceMgr := NewLinkManager()
	bobMgr := NewLinkManager()

	// Alice initiates.
	aliceLink, lrReq, err := aliceMgr.StartLinkAsInitiator(bobDest, &LinkSignalling{MTU: 500, Mode: LinkModeAES256CBC})
	if err != nil {
		t.Fatalf("StartLinkAsInitiator: %v", err)
	}
	if aliceLink.State != LinkPending {
		t.Errorf("alice's link should be Pending right after init, got %s", aliceLink.State)
	}

	// Bob receives the LINKREQUEST and accepts it.
	bobLink, lrProof, err := bobMgr.AcceptIncomingLinkRequest(lrReq, bob, &LinkSignalling{MTU: 500, Mode: LinkModeAES256CBC})
	if err != nil {
		t.Fatalf("AcceptIncomingLinkRequest: %v", err)
	}
	if bobLink.State != LinkActive {
		t.Errorf("bob's link should be Active immediately after sending LRPROOF, got %s", bobLink.State)
	}
	if !bytes.Equal(aliceLink.ID, bobLink.ID) {
		t.Errorf("link_ids disagree:\n  alice: %x\n  bob:   %x", aliceLink.ID, bobLink.ID)
	}

	// Alice receives the LRPROOF and transitions to Active.
	if _, err := aliceMgr.HandleLRProof(lrProof, bob.PublicKey()[32:]); err != nil {
		t.Fatalf("HandleLRProof: %v", err)
	}
	if !aliceLink.IsActive() {
		t.Errorf("alice's link should be Active after LRPROOF, got %s", aliceLink.State)
	}

	// Both sides should have IDENTICAL session keys.
	if !bytes.Equal(aliceLink.Signing, bobLink.Signing) {
		t.Error("signing keys disagree between alice and bob")
	}
	if !bytes.Equal(aliceLink.Encryption, bobLink.Encryption) {
		t.Error("encryption keys disagree between alice and bob")
	}
}

func TestLinkDataRoundTrip(t *testing.T) {
	signing := bytes.Repeat([]byte{0x11}, 32)
	encryption := bytes.Repeat([]byte{0x22}, 32)
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)

	plaintext := []byte("hello over a link")
	pkt, err := BuildLinkDataPacket(linkID, signing, encryption, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.DestinationType != DestinationLink {
		t.Errorf("dest_type = %d, want LINK", pkt.DestinationType)
	}
	if !bytes.Equal(pkt.DestHash, linkID) {
		t.Errorf("dest_hash mismatch")
	}

	got, err := ParseLinkDataPacket(pkt, signing, encryption)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext round-trip mismatch")
	}
}

func TestLinkProofRoundTripExplicitForm(t *testing.T) {
	// Build/validate now use asymmetric Ed25519 (sign with priv, verify
	// with pub) per SPEC §6.5.6 / RNS Link.py:279, NOT a shared HKDF seed.
	signer, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)

	// Build a fake DATA packet to prove against.
	original := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		DestHash:        linkID,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}

	proofPkt, err := BuildLinkProof(linkID, signer.Sign, original)
	if err != nil {
		t.Fatal(err)
	}
	if proofPkt.PacketType != PacketProof {
		t.Errorf("packet_type = %d, want PROOF", proofPkt.PacketType)
	}
	if proofPkt.DestinationType != DestinationLink {
		t.Errorf("dest_type = %d, want LINK", proofPkt.DestinationType)
	}
	if proofPkt.Context != ContextNone {
		t.Errorf("context = 0x%02x, want 0x00", proofPkt.Context)
	}
	if len(proofPkt.Data) != ProofBodyExplicitLen {
		t.Errorf("body length = %d, want %d (always explicit on links)", len(proofPkt.Data), ProofBodyExplicitLen)
	}

	signerPub := signer.PublicKey()[32:] // Ed25519 half
	gotHash, err := ValidateLinkProof(proofPkt, signerPub)
	if err != nil {
		t.Fatalf("ValidateLinkProof: %v", err)
	}
	// Recompute expected hash.
	hp, _ := original.HashablePart()
	want := sha256Sum32(hp)
	if !bytes.Equal(gotHash, want[:]) {
		t.Errorf("packet_hash mismatch: got %x, want %x", gotHash, want)
	}
}

func TestValidateLinkProofRejectsImplicit(t *testing.T) {
	// A 64-byte body would be the implicit form. SPEC §6.5.6 says link
	// DATA proofs are ALWAYS the explicit (96-byte) form on RNS 1.2.0;
	// our validator must reject 64-byte bodies.
	signer, _ := NewIdentity()
	pub := signer.PublicKey()[32:]
	implicitProof := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationLink,
		PacketType:      PacketProof,
		DestHash:        bytes.Repeat([]byte{0x77}, IdentityHashLen),
		Context:         ContextNone,
		Data:            bytes.Repeat([]byte{0x00}, ProofBodyImplicitLen),
	}
	if _, err := ValidateLinkProof(implicitProof, pub); err == nil {
		t.Error("validator accepted implicit-form body on a link DATA proof — must reject per SPEC §6.5.6")
	}
}

func TestValidateLinkProofRejectsBadSignature(t *testing.T) {
	signer, _ := NewIdentity()
	wrongSigner, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)
	original := &Packet{
		HeaderType:      HeaderType1,
		DestinationType: DestinationLink,
		PacketType:      PacketData,
		DestHash:        linkID,
		Context:         ContextNone,
		Data:            []byte("ciphertext"),
	}

	proofPkt, _ := BuildLinkProof(linkID, signer.Sign, original)
	wrongPub := wrongSigner.PublicKey()[32:]
	if _, err := ValidateLinkProof(proofPkt, wrongPub); err == nil {
		t.Error("validator accepted proof signed with a different identity")
	}
}

func TestLinkManagerInboundDataDispatch(t *testing.T) {
	bob, _ := NewIdentity()
	bobDest := bob.DestinationHashFor(FullName("vectors", "link"))

	aliceMgr := NewLinkManager()
	bobMgr := NewLinkManager()

	// Establish the link.
	aliceLink, lrReq, _ := aliceMgr.StartLinkAsInitiator(bobDest, nil)
	bobLink, lrProof, _ := bobMgr.AcceptIncomingLinkRequest(lrReq, bob, nil)
	_, _ = aliceMgr.HandleLRProof(lrProof, bob.PublicKey()[32:])

	// Bob receives a DATA packet alice sent.
	dataPkt, err := BuildLinkDataPacket(aliceLink.ID, aliceLink.Signing, aliceLink.Encryption, []byte("hi bob"))
	if err != nil {
		t.Fatal(err)
	}
	gotPlaintext, gotLink, err := bobMgr.HandleLinkData(dataPkt)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotPlaintext) != "hi bob" {
		t.Errorf("plaintext = %q, want %q", gotPlaintext, "hi bob")
	}
	if gotLink.ID == nil || !bytes.Equal(gotLink.ID, bobLink.ID) {
		t.Errorf("returned link mismatch")
	}
}

func TestLinkManagerActiveTo(t *testing.T) {
	bob, _ := NewIdentity()
	bobDest := bob.DestinationHashFor(FullName("vectors", "link"))

	mgr := NewLinkManager()
	if l := mgr.ActiveTo(bobDest); l != nil {
		t.Errorf("ActiveTo on empty mgr should be nil, got %v", l)
	}

	_, lrReq, _ := mgr.StartLinkAsInitiator(bobDest, nil)
	if l := mgr.ActiveTo(bobDest); l != nil {
		t.Error("ActiveTo should not return Pending links")
	}

	// Pretend the proof arrived (manufacture it by acting as bob).
	bobMgr := NewLinkManager()
	_, lrProof, _ := bobMgr.AcceptIncomingLinkRequest(lrReq, bob, nil)
	_, _ = mgr.HandleLRProof(lrProof, bob.PublicKey()[32:])
	if l := mgr.ActiveTo(bobDest); l == nil {
		t.Error("ActiveTo should now return the active link")
	}
}

func TestCloseLinkIsIdempotent(t *testing.T) {
	mgr := NewLinkManager()
	bob, _ := NewIdentity()
	bobDest := bob.DestinationHashFor(FullName("x", "y"))
	link, _, _ := mgr.StartLinkAsInitiator(bobDest, nil)

	mgr.CloseLink(link.ID)
	mgr.CloseLink(link.ID) // second call should be a no-op
	if mgr.ActiveCount() != 0 {
		t.Errorf("ActiveCount = %d, want 0", mgr.ActiveCount())
	}
	if mgr.Get(link.ID) != nil {
		t.Error("Get on closed link should return nil")
	}
}

func TestBuildLinkKeepalive(t *testing.T) {
	linkID := bytes.Repeat([]byte{0xCC}, IdentityHashLen)
	pkt, err := BuildLinkKeepalive(linkID)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PacketType != PacketData {
		t.Errorf("KEEPALIVE packet_type = %d, want DATA", pkt.PacketType)
	}
	if pkt.DestinationType != DestinationLink {
		t.Errorf("dest_type = %d, want LINK", pkt.DestinationType)
	}
	if pkt.Context != ContextKeepalive {
		t.Errorf("context = 0x%02x, want 0x%02x", pkt.Context, ContextKeepalive)
	}
	if !bytes.Equal(pkt.DestHash, linkID) {
		t.Error("dest_hash should be link_id")
	}
	if len(pkt.Data) != 1 || pkt.Data[0] != 0 {
		t.Errorf("KEEPALIVE body = %x, want [0x00]", pkt.Data)
	}
}

// sha256Sum32 is a small helper that doesn't pull a new import.
func sha256Sum32(b []byte) [32]byte {
	var out [32]byte
	d := sumSHA256(b)
	copy(out[:], d)
	return out
}

func sumSHA256(b []byte) []byte {
	hh := newSHA256Hash()
	hh.Write(b)
	return hh.Sum(nil)
}

// newSHA256Hash bridges to crypto/sha256 without explicitly importing it
// in the test file (already pulled in via package code).
func newSHA256Hash() interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
} {
	return sha256NewFromInternal()
}
