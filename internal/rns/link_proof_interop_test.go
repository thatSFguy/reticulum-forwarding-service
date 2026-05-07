//go:build interop_python

package rns

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestLinkProofBytewiseInterop runs scripts/gen_link_proof.py (which
// drives upstream RNS 1.2.0's identity.sign + manual proof assembly
// matching RNS/Link.py:279 + RNS/Packet.pack), then asserts:
//
//  1. Our BuildLinkProof, given the same identity priv + same original
//     packet, produces wire bytes that are byte-identical to upstream's
//     proof. Ed25519 is deterministic per RFC 8032, so byte equality
//     is achievable and the strongest possible interop assertion.
//  2. Our ValidateLinkProof, given the upstream proof bytes + the
//     identity's Ed25519 pubkey, accepts the signature.
//
// This test exists because the previous round-trip-only tests
// (TestLinkProofRoundTripExplicitForm) confirmed self-consistency
// without proving interop. v1.0.3 fixed a bug — link DATA proofs
// signed with an HKDF-derived shared seed instead of the responder's
// long-term Ed25519 priv — that round-trip-only tests could not
// detect. See feedback_test_against_outside_oracle.md.
//
// Build-tagged so plain `go test ./...` skips it. Run with:
//
//	go test -tags interop_python ./internal/rns/... -run LinkProofBytewiseInterop
//
// Skipped (not failed) if Python or upstream RNS isn't available.
func TestLinkProofBytewiseInterop(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "scripts", "gen_link_proof.py")
	out, err := exec.Command("python", scriptPath).Output()
	if err != nil {
		t.Skipf("python helper unavailable (%v); install RNS 1.2.0 to run this test", err)
	}

	var v struct {
		IdentityPrivHex   string `json:"identity_priv_hex"`
		IdentityPubHex    string `json:"identity_pub_hex"`
		LinkIDHex         string `json:"link_id_hex"`
		OriginalPacketHex string `json:"original_packet_hex"`
		ExpectedProofHex  string `json:"expected_proof_hex"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("decode python output: %v\nstdout=%s", err, out)
	}

	priv, _ := hex.DecodeString(v.IdentityPrivHex)
	pub, _ := hex.DecodeString(v.IdentityPubHex)
	linkID, _ := hex.DecodeString(v.LinkIDHex)
	originalWire, _ := hex.DecodeString(v.OriginalPacketHex)
	expectedProofWire, _ := hex.DecodeString(v.ExpectedProofHex)

	id, err := IdentityFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	if !bytes.Equal(id.PublicKey(), pub) {
		t.Fatalf("our identity's pub doesn't match upstream's:\n got %x\nwant %x", id.PublicKey(), pub)
	}

	original, err := ParsePacket(originalWire)
	if err != nil {
		t.Fatalf("ParsePacket(original): %v", err)
	}

	// (1) Our build must produce byte-identical wire to upstream's.
	gotProof, err := BuildLinkProof(linkID, id.Sign, original)
	if err != nil {
		t.Fatalf("BuildLinkProof: %v", err)
	}
	gotProofWire, err := gotProof.Pack()
	if err != nil {
		t.Fatalf("Pack proof: %v", err)
	}
	if !bytes.Equal(gotProofWire, expectedProofWire) {
		t.Errorf("link proof bytes mismatch\n got %x\nwant %x", gotProofWire, expectedProofWire)
	}

	// (2) Our validate must accept upstream's proof bytes against the
	// responder's known long-term Ed25519 pubkey.
	upstreamProof, err := ParsePacket(expectedProofWire)
	if err != nil {
		t.Fatalf("ParsePacket(expectedProof): %v", err)
	}
	ed25519Pub := pub[32:] // upstream pubkey blob is X25519(32) || Ed25519(32)
	gotHash, err := ValidateLinkProof(upstreamProof, ed25519Pub)
	if err != nil {
		t.Fatalf("ValidateLinkProof rejected upstream proof: %v", err)
	}
	if len(gotHash) != 32 {
		t.Errorf("packet_hash length = %d, want 32", len(gotHash))
	}
}
