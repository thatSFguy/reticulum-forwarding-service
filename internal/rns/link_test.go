package rns

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestLinkSignallingRoundTrip(t *testing.T) {
	cases := []LinkSignalling{
		{MTU: 0, Mode: 0},
		{MTU: 500, Mode: 1},     // alice-to-bob test vector
		{MTU: 0x1FFFFF, Mode: 7}, // max in 21+3 bits
		{MTU: 256, Mode: 0},
	}
	for _, c := range cases {
		raw := c.Encode()
		got, err := DecodeLinkSignalling(raw[:])
		if err != nil {
			t.Fatalf("decode %v: %v", c, err)
		}
		if got != c {
			t.Errorf("round-trip mismatch: got %+v, want %+v", got, c)
		}
	}
}

func TestLinkSignallingMatchesSpecVector(t *testing.T) {
	// alice_to_bob_aes256cbc: mtu=500, mode=1 -> 0x2001f4
	got := LinkSignalling{MTU: 500, Mode: 1}.Encode()
	want := [3]byte{0x20, 0x01, 0xf4}
	if got != want {
		t.Errorf("encode mtu=500 mode=1 = %x, want %x", got, want)
	}
}

func TestBuildLinkRequestRejectsBadInputs(t *testing.T) {
	good := make([]byte, 32)
	hash := make([]byte, IdentityHashLen)

	if _, err := BuildLinkRequest(good[:31], good, hash, nil); err == nil {
		t.Error("expected error for short X25519 pub")
	}
	if _, err := BuildLinkRequest(good, good[:31], hash, nil); err == nil {
		t.Error("expected error for short Ed25519 pub")
	}
	if _, err := BuildLinkRequest(good, good, hash[:8], nil); err == nil {
		t.Error("expected error for short dest_hash")
	}
}

func TestParseLinkRequestRoundTrip(t *testing.T) {
	x := bytes.Repeat([]byte{0xAA}, 32)
	e := bytes.Repeat([]byte{0xBB}, 32)
	dest := newDummyHash(0xCC)
	sig := &LinkSignalling{MTU: 500, Mode: 1}

	pkt, err := BuildLinkRequest(x, e, dest, sig)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PacketType != PacketLinkRequest || pkt.DestinationType != DestinationSingle {
		t.Errorf("packet shape mismatch: type=%d destType=%d", pkt.PacketType, pkt.DestinationType)
	}

	parsed, err := ParseLinkRequest(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.InitiatorX25519Pub, x) {
		t.Error("X25519 pub round-trip failed")
	}
	if !bytes.Equal(parsed.InitiatorEd25519Pub, e) {
		t.Error("Ed25519 pub round-trip failed")
	}
	if parsed.Signalling == nil || *parsed.Signalling != *sig {
		t.Errorf("signalling round-trip failed: got %+v", parsed.Signalling)
	}

	// Without signalling
	pkt2, _ := BuildLinkRequest(x, e, dest, nil)
	parsed2, err := ParseLinkRequest(pkt2)
	if err != nil {
		t.Fatal(err)
	}
	if parsed2.Signalling != nil {
		t.Errorf("expected nil signalling, got %+v", parsed2.Signalling)
	}
}

func TestLinkIDInvariantUnderSignalling(t *testing.T) {
	x := bytes.Repeat([]byte{0xAA}, 32)
	e := bytes.Repeat([]byte{0xBB}, 32)
	dest := newDummyHash(0xCC)

	withoutSig, _ := BuildLinkRequest(x, e, dest, nil)
	withSig, _ := BuildLinkRequest(x, e, dest, &LinkSignalling{MTU: 500, Mode: 1})

	idA, err := LinkID(withoutSig)
	if err != nil {
		t.Fatal(err)
	}
	idB, err := LinkID(withSig)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(idA, idB) {
		t.Errorf("link_id should be invariant under signalling presence:\n  no_sig = %x\n  w_sig  = %x", idA, idB)
	}
}

func TestDeriveLinkSessionKeysSymmetric(t *testing.T) {
	a, _ := NewIdentity()
	b, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x42}, IdentityHashLen)

	aSign, aEnc, err := DeriveLinkSessionKeys(a.x25519Priv[:], b.X25519Public(), linkID)
	if err != nil {
		t.Fatal(err)
	}
	bSign, bEnc, err := DeriveLinkSessionKeys(b.x25519Priv[:], a.X25519Public(), linkID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aSign, bSign) || !bytes.Equal(aEnc, bEnc) {
		t.Error("session keys disagree between peers")
	}
	if len(aSign) != 32 || len(aEnc) != 32 {
		t.Errorf("session-key lengths: signing=%d encryption=%d, want 32 each", len(aSign), len(aEnc))
	}
}

func TestBuildVerifyLRProofRoundTrip(t *testing.T) {
	responder, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)
	respX25519Pub := bytes.Repeat([]byte{0xEE}, 32)
	sig := &LinkSignalling{MTU: 500, Mode: 1}

	pkt, err := BuildLRProof(responder, linkID, respX25519Pub, sig)
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PacketType != PacketProof || pkt.Context != ContextLRProof {
		t.Errorf("LRPROOF outer header wrong: type=%d ctx=0x%02x", pkt.PacketType, pkt.Context)
	}
	if pkt.DestinationType != DestinationLink {
		t.Errorf("LRPROOF dest_type = %d, want %d (LINK)", pkt.DestinationType, DestinationLink)
	}
	if !bytes.Equal(pkt.DestHash, linkID) {
		t.Error("LRPROOF outer dest_hash should be link_id")
	}

	parsed, err := ParseLRProof(pkt)
	if err != nil {
		t.Fatalf("ParseLRProof: %v", err)
	}
	if !bytes.Equal(parsed.ResponderX25519Pub, respX25519Pub) {
		t.Error("X25519 pub round-trip mismatch")
	}
	if err := parsed.Verify(responder.PublicKey()[32:]); err != nil {
		t.Errorf("Verify against responder Ed25519 pub: %v", err)
	}
}

func TestLRProofRejectsTamperedSignalling(t *testing.T) {
	responder, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)
	respX25519Pub := bytes.Repeat([]byte{0xEE}, 32)
	sig := &LinkSignalling{MTU: 500, Mode: 1}

	pkt, _ := BuildLRProof(responder, linkID, respX25519Pub, sig)
	parsed, _ := ParseLRProof(pkt)

	// Tamper with the signalling — sig was committed to MTU=500, Mode=1.
	tampered := *parsed
	tw := *sig
	tw.MTU = 1500
	tampered.Signalling = &tw

	if err := tampered.Verify(responder.PublicKey()[32:]); err == nil {
		t.Error("Verify accepted tampered signalling — sig should commit to it")
	}
}

func TestLRProofRejectsWrongResponderPub(t *testing.T) {
	right, _ := NewIdentity()
	wrong, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)
	respX25519Pub := bytes.Repeat([]byte{0xEE}, 32)

	pkt, _ := BuildLRProof(right, linkID, respX25519Pub, nil)
	parsed, _ := ParseLRProof(pkt)

	if err := parsed.Verify(wrong.PublicKey()[32:]); err == nil {
		t.Error("Verify accepted with wrong responder Ed25519 pub")
	}
}

func TestLinkTokenRoundTrip(t *testing.T) {
	signing := bytes.Repeat([]byte{0x11}, 32)
	encryption := bytes.Repeat([]byte{0x22}, 32)

	cases := [][]byte{
		[]byte("hi"),
		bytes.Repeat([]byte{0x33}, 16),
		bytes.Repeat([]byte{0x44}, 17),
		bytes.Repeat([]byte{0x55}, 1024),
	}
	for _, plaintext := range cases {
		wire, err := LinkTokenEncrypt(plaintext, signing, encryption)
		if err != nil {
			t.Fatalf("encrypt %d: %v", len(plaintext), err)
		}
		got, err := LinkTokenDecrypt(wire, signing, encryption)
		if err != nil {
			t.Fatalf("decrypt %d: %v", len(plaintext), err)
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("link token round-trip mismatch (len %d)", len(plaintext))
		}
	}
}

func TestLinkTokenWrongKeysRejected(t *testing.T) {
	a := bytes.Repeat([]byte{0x11}, 32)
	b := bytes.Repeat([]byte{0x22}, 32)
	c := bytes.Repeat([]byte{0x33}, 32)
	d := bytes.Repeat([]byte{0x44}, 32)

	wire, _ := LinkTokenEncrypt([]byte("secret"), a, b)
	if _, err := LinkTokenDecrypt(wire, c, d); err == nil {
		t.Error("link token decrypted with wrong keys")
	}
}

// TestLRProofSignatureUsesLongTermPub guards against the gotcha that the
// responder's long-term Ed25519 pub goes into the signed_data even though
// it is NOT on the wire (SPEC §6.2). A signer that omits it would produce
// a signature the receiver rejects.
func TestLRProofSignatureUsesLongTermPub(t *testing.T) {
	responder, _ := NewIdentity()
	linkID := bytes.Repeat([]byte{0x77}, IdentityHashLen)
	respX25519Pub := bytes.Repeat([]byte{0xEE}, 32)

	pkt, _ := BuildLRProof(responder, linkID, respX25519Pub, nil)
	parsed, _ := ParseLRProof(pkt)

	// Compute the wrong signed_data (without long-term pub) and check
	// the actual signature does NOT match it — proving the long-term pub
	// IS in the signed_data.
	without := append([]byte(nil), linkID...)
	without = append(without, respX25519Pub...)
	digest := sha256.Sum256(without) // (just to use the import; not actually needed)
	_ = digest

	if Validate(responder.PublicKey()[32:], without, parsed.Signature) {
		t.Error("signature validated against signed_data WITHOUT long-term pub — wrong signing scope")
	}
}
