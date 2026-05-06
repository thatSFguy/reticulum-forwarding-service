package rns

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// TestLinkVectorsBytewiseInterop loads
// ../reticulum-specifications/test-vectors/links.json (deterministic
// LINKREQUEST + LRPROOF bytes regenerated from upstream Python rns 1.2.0
// via tools/regen_links.py with every random source pinned) and verifies:
//
//  1. Our BuildLinkRequest, given the same initiator ephemeral keys +
//     responder dest_hash + signalling, emits bytes that match
//     expected.linkrequest_raw_hex BYTE-FOR-BYTE.
//  2. LinkID() over the canonical LINKREQUEST yields expected.link_id_hex.
//  3. ECDH(initiator_eph, responder_eph) matches expected.shared_secret_hex.
//  4. HKDF over that shared secret with salt=link_id yields expected.derived_key_hex
//     (64 bytes split as signing||encryption).
//  5. Our BuildLRProof, given the responder's identity + linkID +
//     responder ephemeral pub + signalling, emits bytes that match
//     expected.lrproof_raw_hex BYTE-FOR-BYTE.
//
// Together these prove the link handshake interoperates with upstream
// at the byte level for the AES-256-CBC mode (SPEC §6.1, §6.2, §6.3,
// §6.4, §6.6).
func TestLinkVectorsBytewiseInterop(t *testing.T) {
	idents := loadIdentitiesIntoMap(t)

	for _, v := range loadLinkVectors(t) {
		t.Run(v.Label, func(t *testing.T) {
			initiator, ok := idents[v.Inputs.InitiatorIdentityLabel]
			if !ok {
				t.Fatalf("unknown initiator identity %q", v.Inputs.InitiatorIdentityLabel)
			}
			responder, ok := idents[v.Inputs.ResponderIdentityLabel]
			if !ok {
				t.Fatalf("unknown responder identity %q", v.Inputs.ResponderIdentityLabel)
			}
			_ = initiator // not directly used; the LINKREQUEST uses initiator's EPHEMERAL keys

			respDest := DestinationHash(NameHash(v.Inputs.DestinationFullName), responder.Hash())

			initX25519Priv := mustHex(t, v.Inputs.InitiatorX25519PrivHex)
			initEd25519Priv := mustHex(t, v.Inputs.InitiatorEd25519PrivHex)
			respX25519Priv := mustHex(t, v.Inputs.ResponderX25519PrivHex)

			// Derive the public halves the spec test produces.
			initX25519Pub := mustX25519Pub(t, initX25519Priv)
			initEd25519Pub := ed25519PubFromSeed(initEd25519Priv)
			respX25519Pub := mustX25519Pub(t, respX25519Priv)

			sig := &LinkSignalling{MTU: uint32(v.Expected.MTU), Mode: byte(v.Expected.Mode)}

			// 1. Build LINKREQUEST and assert byte-equality.
			lrPkt, err := BuildLinkRequest(initX25519Pub, initEd25519Pub, respDest, sig)
			if err != nil {
				t.Fatalf("BuildLinkRequest: %v", err)
			}
			gotLR, err := lrPkt.Pack()
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			wantLR := mustHex(t, v.Expected.LinkRequestRawHex)
			if !bytes.Equal(gotLR, wantLR) {
				t.Errorf("LINKREQUEST bytes mismatch\n got %x\nwant %x", gotLR, wantLR)
			}

			// 2. LinkID over the canonical bytes.
			lrParsed, err := ParsePacket(wantLR)
			if err != nil {
				t.Fatalf("ParsePacket(canonical LINKREQUEST): %v", err)
			}
			gotID, err := LinkID(lrParsed)
			if err != nil {
				t.Fatalf("LinkID: %v", err)
			}
			wantID := mustHex(t, v.Expected.LinkIDHex)
			if !bytes.Equal(gotID, wantID) {
				t.Errorf("link_id mismatch\n got %x\nwant %x", gotID, wantID)
			}

			// 3. ECDH shared secret (responder side: respPriv * initPub).
			shared, err := curve25519.X25519(respX25519Priv, initX25519Pub)
			if err != nil {
				t.Fatal(err)
			}
			wantShared := mustHex(t, v.Expected.SharedSecretHex)
			if !bytes.Equal(shared, wantShared) {
				t.Errorf("shared secret mismatch\n got %x\nwant %x", shared, wantShared)
			}

			// 4. HKDF derived keys.
			signing, encryption, err := DeriveLinkSessionKeys(respX25519Priv, initX25519Pub, gotID)
			if err != nil {
				t.Fatal(err)
			}
			gotDerived := append([]byte(nil), signing...)
			gotDerived = append(gotDerived, encryption...)
			wantDerived := mustHex(t, v.Expected.DerivedKeyHex)
			if !bytes.Equal(gotDerived, wantDerived) {
				t.Errorf("derived key mismatch\n got %x\nwant %x", gotDerived, wantDerived)
			}

			// 5. Build LRPROOF and assert byte-equality. Responder signs
			// with its long-term Ed25519 priv.
			proofPkt, err := BuildLRProof(responder, gotID, respX25519Pub, sig)
			if err != nil {
				t.Fatal(err)
			}
			gotProof, err := proofPkt.Pack()
			if err != nil {
				t.Fatal(err)
			}
			wantProof := mustHex(t, v.Expected.LRProofRawHex)
			if !bytes.Equal(gotProof, wantProof) {
				t.Errorf("LRPROOF bytes mismatch\n got %x\nwant %x", gotProof, wantProof)
			}

			// And the inverse: parse + verify the canonical LRPROOF.
			parsedProof, err := ParseLRProof(proofPkt)
			if err != nil {
				t.Fatal(err)
			}
			if err := parsedProof.Verify(responder.PublicKey()[32:]); err != nil {
				t.Errorf("Verify on canonical LRPROOF: %v", err)
			}
		})
	}
}

// --- vector loading + small helpers ------------------------------------

type linkVector struct {
	Label  string `json:"label"`
	Inputs struct {
		InitiatorIdentityLabel  string `json:"initiator_identity_label"`
		ResponderIdentityLabel  string `json:"responder_identity_label"`
		DestinationFullName     string `json:"destination_full_name"`
		InitiatorX25519PrivHex  string `json:"initiator_x25519_priv_hex"`
		InitiatorEd25519PrivHex string `json:"initiator_ed25519_priv_hex"`
		ResponderX25519PrivHex  string `json:"responder_x25519_priv_hex"`
	} `json:"inputs"`
	Expected struct {
		LinkRequestRawHex string `json:"linkrequest_raw_hex"`
		LinkIDHex         string `json:"link_id_hex"`
		LRProofRawHex     string `json:"lrproof_raw_hex"`
		SharedSecretHex   string `json:"shared_secret_hex"`
		DerivedKeyHex     string `json:"derived_key_hex"`
		MTU               int    `json:"mtu"`
		Mode              int    `json:"mode"`
	} `json:"expected"`
}

func loadLinkVectors(t *testing.T) []linkVector {
	t.Helper()
	abs, err := filepath.Abs("../../../reticulum-specifications/test-vectors/links.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("links.json unavailable (%s): %v", abs, err)
	}
	var f struct{ Vectors []linkVector `json:"vectors"` }
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("unmarshal links.json: %v", err)
	}
	if len(f.Vectors) == 0 {
		t.Fatalf("no link vectors in %s", abs)
	}
	return f.Vectors
}

// loadIdentitiesIntoMap reads identities.json and returns a label -> *Identity
// map. Skips test if the spec sibling repo isn't available.
func loadIdentitiesIntoMap(t *testing.T) map[string]*Identity {
	t.Helper()
	abs, err := filepath.Abs("../../../reticulum-specifications/test-vectors/identities.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		t.Skipf("identities.json unavailable (%s): %v", abs, err)
	}
	var f struct {
		Vectors []struct {
			Label  string `json:"label"`
			Inputs struct {
				PrivateKeyHex string `json:"private_key_hex"`
			} `json:"inputs"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	out := map[string]*Identity{}
	for _, v := range f.Vectors {
		priv, _ := hex.DecodeString(v.Inputs.PrivateKeyHex)
		id, err := IdentityFromPrivateKey(priv)
		if err != nil {
			t.Fatalf("identity %s: %v", v.Label, err)
		}
		out[v.Label] = id
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func mustX25519Pub(t *testing.T, priv []byte) []byte {
	t.Helper()
	if len(priv) != 32 {
		t.Fatalf("X25519 priv must be 32 bytes, got %d", len(priv))
	}
	scratch := append([]byte(nil), priv...)
	scratch[0] &= 248
	scratch[31] &= 127
	scratch[31] |= 64
	pub, err := curve25519.X25519(scratch, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func ed25519PubFromSeed(seed []byte) []byte {
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey)
}
