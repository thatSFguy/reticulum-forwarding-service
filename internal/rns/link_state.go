package rns

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

// Link state machine — SPEC §6 (state machine itself isn't formally
// specified; modeled after upstream RNS.Link). Tracks the lifecycle of
// an established or in-progress Link between us and a peer:
//
//	Pending  : we sent a LINKREQUEST, waiting for matching LRPROOF.
//	Active   : handshake complete; can send/receive DATA on the link.
//	Closed   : torn down, never reopens with this link_id.
//
// KEEPALIVE-driven Expired/Stale states are deferred to a follow-up;
// the basic state machine here is enough for opportunistic-vs-link
// fallback in Delivery.Send (PR 3 of the link-delivery work).
//
// All public methods on Link and LinkManager are safe to call from
// multiple goroutines.

// LinkState enumerates the link lifecycle.
type LinkState int

const (
	LinkPending LinkState = iota
	LinkActive
	LinkClosed
)

func (s LinkState) String() string {
	switch s {
	case LinkPending:
		return "pending"
	case LinkActive:
		return "active"
	case LinkClosed:
		return "closed"
	}
	return fmt.Sprintf("LinkState(%d)", int(s))
}

// Link is one in-flight or established Reticulum Link.
type Link struct {
	mu sync.Mutex

	ID    []byte // 16-byte link_id (SPEC §6.3)
	State LinkState

	// Session keys derived from the handshake (SPEC §6.4). 32 bytes each;
	// signing is also used as the Ed25519 seed for link-DATA proofs.
	Signing    []byte
	Encryption []byte

	// Initiator-side state used while Pending: ephemeral X25519 priv we
	// sent in the LINKREQUEST, plus the peer destination we addressed.
	// Cleared once the link transitions to Active.
	myEphemeralX25519Priv []byte
	peerDestHash          []byte

	// Responder-side state: the responder's ephemeral X25519 priv we
	// generated to derive session keys. Cleared once Active.
	myResponderEphPriv []byte

	CreatedAt    time.Time
	LastActivity time.Time

	// OnInboundData is called from the Transport's dispatcher with each
	// successfully decrypted link DATA payload. Non-nil during Active.
	OnInboundData func(plaintext []byte)
}

// IsActive returns true iff State == LinkActive.
func (l *Link) IsActive() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.State == LinkActive
}

// LinkManager tracks links keyed by link_id. It does not own a Transport;
// callers (Delivery / Service) wire its outbound packets through their own
// Transport.Broadcast and route inbound LINKREQUEST/LRPROOF/link-addressed
// DATA/PROOF packets through the Handle* methods.
type LinkManager struct {
	mu    sync.Mutex
	links map[string]*Link // hex link_id -> *Link

	// Optional per-link callback. The application (Delivery) sets this
	// when it wants to receive plaintext payloads from inbound link
	// DATA. Default no-op.
	defaultOnInboundData func(linkID, plaintext []byte)
}

// NewLinkManager constructs an empty manager.
func NewLinkManager() *LinkManager {
	return &LinkManager{links: map[string]*Link{}}
}

// SetDefaultInboundDataHandler sets a fallback callback used by Active
// links that don't have a per-link OnInboundData set.
func (lm *LinkManager) SetDefaultInboundDataHandler(cb func(linkID, plaintext []byte)) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.defaultOnInboundData = cb
}

// Get returns the Link with the given link_id, or nil if unknown.
func (lm *LinkManager) Get(linkID []byte) *Link {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	return lm.links[hex.EncodeToString(linkID)]
}

// Active returns the active Link (if any) toward responderDestHash.
// Useful for "do I already have a link to this peer or do I need to
// open one?". Returns nil if no active link is known.
func (lm *LinkManager) ActiveTo(responderDestHash []byte) *Link {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	for _, l := range lm.links {
		l.mu.Lock()
		match := l.State == LinkActive && len(l.peerDestHash) == len(responderDestHash) &&
			bytesEqual(l.peerDestHash, responderDestHash)
		l.mu.Unlock()
		if match {
			return l
		}
	}
	return nil
}

// StartLinkAsInitiator generates an ephemeral X25519 + Ed25519 keypair
// and returns:
//
//	link    -- a *Link in the Pending state (registered in the manager)
//	request -- the LINKREQUEST packet to broadcast on the wire.
//
// The caller is responsible for transmitting `request`. When the
// matching LRPROOF arrives, hand it to HandleLRProof to transition the
// link to Active.
func (lm *LinkManager) StartLinkAsInitiator(responderDestHash []byte, sig *LinkSignalling) (*Link, *Packet, error) {
	if len(responderDestHash) != IdentityHashLen {
		return nil, nil, fmt.Errorf("responder dest_hash must be %d bytes", IdentityHashLen)
	}

	ephPriv, ephPub, err := newClampedX25519()
	if err != nil {
		return nil, nil, err
	}
	// Initiator's ephemeral Ed25519 (per SPEC §6.1, both ephemerals are
	// fresh — they are NOT the long-term identity keys). Used by upstream
	// for some additional handshake flows; we include it on the wire as
	// required even though we don't use it for our own DATA proofs.
	var ephEd25519Seed [32]byte
	if _, err := rand.Read(ephEd25519Seed[:]); err != nil {
		return nil, nil, fmt.Errorf("Ed25519 seed entropy: %w", err)
	}
	ephID, err := identityFromHalves([32]byte(ephPriv), ephEd25519Seed)
	if err != nil {
		return nil, nil, fmt.Errorf("derive ephemeral identity: %w", err)
	}

	pkt, err := BuildLinkRequest(ephPub, ephID.PublicKey()[32:], responderDestHash, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("BuildLinkRequest: %w", err)
	}
	id, err := LinkID(pkt)
	if err != nil {
		return nil, nil, fmt.Errorf("LinkID: %w", err)
	}

	l := &Link{
		ID:                    id,
		State:                 LinkPending,
		myEphemeralX25519Priv: ephPriv,
		peerDestHash:          append([]byte(nil), responderDestHash...),
		CreatedAt:             time.Now(),
		LastActivity:          time.Now(),
	}
	lm.mu.Lock()
	lm.links[hex.EncodeToString(id)] = l
	lm.mu.Unlock()
	return l, pkt, nil
}

// HandleLRProof transitions a Pending initiator-side Link to Active by
// verifying the responder's LRPROOF and deriving session keys. The
// responder's long-term Ed25519 pub is supplied separately because both
// sides know it from the responder's prior announce — it's NOT on the
// LRPROOF wire (SPEC §6.2).
func (lm *LinkManager) HandleLRProof(p *Packet, responderEd25519Pub []byte) (*Link, error) {
	parsed, err := ParseLRProof(p)
	if err != nil {
		return nil, err
	}
	if err := parsed.Verify(responderEd25519Pub); err != nil {
		return nil, err
	}

	lm.mu.Lock()
	l, ok := lm.links[hex.EncodeToString(parsed.LinkID)]
	lm.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("LRPROOF for unknown link_id %x", parsed.LinkID)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.State != LinkPending {
		return nil, fmt.Errorf("LRPROOF for link in state %s, want pending", l.State)
	}
	signing, encryption, err := DeriveLinkSessionKeys(l.myEphemeralX25519Priv, parsed.ResponderX25519Pub, parsed.LinkID)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}
	l.Signing = signing
	l.Encryption = encryption
	l.State = LinkActive
	l.LastActivity = time.Now()
	l.myEphemeralX25519Priv = nil // no longer needed
	return l, nil
}

// AcceptIncomingLinkRequest is the responder-side counterpart to
// StartLinkAsInitiator. Given an inbound LINKREQUEST + the local
// destination's identity (which signs the LRPROOF), it generates an
// ephemeral X25519 keypair, derives session keys, registers an Active
// link in the manager, and returns the LRPROOF the caller should
// broadcast back.
func (lm *LinkManager) AcceptIncomingLinkRequest(reqPkt *Packet, localID *Identity, sig *LinkSignalling) (*Link, *Packet, error) {
	req, err := ParseLinkRequest(reqPkt)
	if err != nil {
		return nil, nil, err
	}
	id, err := LinkID(reqPkt)
	if err != nil {
		return nil, nil, err
	}

	respEphPriv, respEphPub, err := newClampedX25519()
	if err != nil {
		return nil, nil, err
	}
	signing, encryption, err := DeriveLinkSessionKeys(respEphPriv, req.InitiatorX25519Pub, id)
	if err != nil {
		return nil, nil, fmt.Errorf("derive session keys: %w", err)
	}

	proofPkt, err := BuildLRProof(localID, id, respEphPub, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("BuildLRProof: %w", err)
	}

	l := &Link{
		ID:                 id,
		State:              LinkActive,
		Signing:            signing,
		Encryption:         encryption,
		myResponderEphPriv: respEphPriv, // kept around in case we want to renegotiate
		CreatedAt:          time.Now(),
		LastActivity:       time.Now(),
	}
	lm.mu.Lock()
	lm.links[hex.EncodeToString(id)] = l
	lm.mu.Unlock()
	return l, proofPkt, nil
}

// HandleLinkData processes an inbound link DATA packet — verifies the
// outer wire shape, decrypts using the link's session keys, and routes
// the plaintext through OnInboundData (or the manager's default).
// Returns the plaintext and the original packet (so the caller can emit
// a link DATA proof against it).
func (lm *LinkManager) HandleLinkData(p *Packet) ([]byte, *Link, error) {
	if p == nil {
		return nil, nil, errors.New("nil packet")
	}
	l := lm.Get(p.DestHash)
	if l == nil {
		return nil, nil, fmt.Errorf("link DATA for unknown link_id %x", p.DestHash)
	}
	l.mu.Lock()
	if l.State != LinkActive {
		l.mu.Unlock()
		return nil, l, fmt.Errorf("link DATA on link in state %s", l.State)
	}
	signing := l.Signing
	encryption := l.Encryption
	cb := l.OnInboundData
	l.LastActivity = time.Now()
	l.mu.Unlock()

	plaintext, err := ParseLinkDataPacket(p, signing, encryption)
	if err != nil {
		return nil, l, err
	}
	if cb != nil {
		cb(plaintext)
	} else if lm.defaultOnInboundData != nil {
		lm.defaultOnInboundData(l.ID, plaintext)
	}
	return plaintext, l, nil
}

// CloseLink moves the link to Closed and removes it from the manager.
// Idempotent.
func (lm *LinkManager) CloseLink(linkID []byte) {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	key := hex.EncodeToString(linkID)
	if l, ok := lm.links[key]; ok {
		l.mu.Lock()
		l.State = LinkClosed
		l.Signing = nil
		l.Encryption = nil
		l.mu.Unlock()
		delete(lm.links, key)
	}
}

// ActiveCount returns the number of links currently in Active state.
// Useful for tests and debug logs.
func (lm *LinkManager) ActiveCount() int {
	lm.mu.Lock()
	defer lm.mu.Unlock()
	n := 0
	for _, l := range lm.links {
		l.mu.Lock()
		if l.State == LinkActive {
			n++
		}
		l.mu.Unlock()
	}
	return n
}

// newClampedX25519 generates a fresh X25519 keypair, applying RFC 7748
// scalar clamping to the priv before computing the pub. Returns
// (priv32, pub32). Both slices are freshly allocated.
func newClampedX25519() ([]byte, []byte, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return nil, nil, fmt.Errorf("X25519 priv entropy: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive X25519 pub: %w", err)
	}
	return priv, pub, nil
}
