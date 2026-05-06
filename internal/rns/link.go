package rns

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// Reticulum Link primitives — SPEC §6.
//
// A Link is an ephemeral encrypted full-duplex channel between two
// destinations, set up via a 2-packet handshake (LINKREQUEST -> LRPROOF)
// and used afterwards for arbitrary-size DATA exchanges. This file
// implements only the wire format + crypto of the handshake:
//
//   - BuildLinkRequest / ParseLinkRequest  (§6.1)
//   - LinkID derivation                    (§6.3)
//   - DeriveLinkSessionKeys                (§6.4)
//   - BuildLRProof / ParseLRProof / Verify (§6.2)
//   - LinkTokenEncrypt / LinkTokenDecrypt  (§3.1 link form, no eph_pub
//                                           on wire because session keys
//                                           are pre-derived)
//
// The Link state machine (active/expired/dead, KEEPALIVE, teardown,
// link-DATA framing, link-DATA explicit-form PROOFs) is a separate
// concern handled in PR 2 of the link-delivery work.

// Body lengths from SPEC §6.1 / §6.2.
const (
	// LinkRequestBodyLen is the LINKREQUEST body without the optional
	// 3-byte MTU/mode signalling trailer (§6.6).
	LinkRequestBodyLen = 32 + 32 // initiator X25519 pub + Ed25519 pub

	// LinkRequestBodyLenSignalled is LinkRequestBodyLen + signalling.
	LinkRequestBodyLenSignalled = LinkRequestBodyLen + LinkSignallingLen

	// LRProofBodyLen is the LRPROOF body without signalling.
	LRProofBodyLen = 64 + 32 // sig + responder X25519 pub

	// LRProofBodyLenSignalled is LRProofBodyLen + signalling.
	LRProofBodyLenSignalled = LRProofBodyLen + LinkSignallingLen

	// LinkSignallingLen is the fixed width of a signalling trailer.
	LinkSignallingLen = 3

	// LinkSessionKeyLen is the total HKDF output: signing(32) + encrypt(32).
	LinkSessionKeyLen = 64
)

// Reticulum link-mode IDs (SPEC §6.6). Only AES-256-CBC is implemented;
// others are listed for parser tolerance.
const (
	LinkModeAES128CBC = 0x00
	LinkModeAES256CBC = 0x01
	LinkModeChaCha20  = 0x02
)

// LinkSignalling carries the negotiated MTU (21 bits) and link mode
// (3 bits) per SPEC §6.6. When the trailer is present it MUST also be
// included in the LRPROOF signed_data exactly where the spec shows it,
// so a peer flipping a bit in transit invalidates the proof.
type LinkSignalling struct {
	MTU  uint32 // up to 21 bits (0 .. 0x1FFFFF)
	Mode byte   // up to 3 bits  (0 .. 7)
}

// MTUByteMask + ModeByteMask per SPEC §6.6.
const (
	mtuByteMask  = 0x1FFFFF
	modeByteMask = 0xE0
)

// Encode packs the signalling into the canonical 3 bytes.
//
//	byte 0 :  M M M m m m m m       — top 3 bits = mode, low 5 bits = mtu[20..16]
//	byte 1 :  m m m m m m m m       — mtu[15..8]
//	byte 2 :  m m m m m m m m       — mtu[7..0]
func (s LinkSignalling) Encode() [3]byte {
	value := (s.MTU & mtuByteMask) | ((uint32(s.Mode<<5) & modeByteMask) << 16)
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return [3]byte{raw[1], raw[2], raw[3]}
}

// DecodeLinkSignalling parses the 3-byte trailer.
func DecodeLinkSignalling(b []byte) (LinkSignalling, error) {
	if len(b) != LinkSignallingLen {
		return LinkSignalling{}, fmt.Errorf("signalling must be %d bytes, got %d", LinkSignallingLen, len(b))
	}
	value := uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	return LinkSignalling{
		MTU:  value & mtuByteMask,
		Mode: byte((value >> 16) >> 5),
	}, nil
}

// BuildLinkRequest builds a LINKREQUEST packet (SPEC §6.1) from the
// initiator's ephemeral X25519+Ed25519 public keys to the responder's
// destination_hash. Optional signalling is appended verbatim.
func BuildLinkRequest(initiatorX25519Pub, initiatorEd25519Pub, responderDestHash []byte, sig *LinkSignalling) (*Packet, error) {
	if len(initiatorX25519Pub) != 32 {
		return nil, fmt.Errorf("initiator X25519 pub must be 32 bytes, got %d", len(initiatorX25519Pub))
	}
	if len(initiatorEd25519Pub) != 32 {
		return nil, fmt.Errorf("initiator Ed25519 pub must be 32 bytes, got %d", len(initiatorEd25519Pub))
	}
	if len(responderDestHash) != IdentityHashLen {
		return nil, fmt.Errorf("responder dest_hash must be %d bytes, got %d", IdentityHashLen, len(responderDestHash))
	}

	body := make([]byte, 0, LinkRequestBodyLenSignalled)
	body = append(body, initiatorX25519Pub...)
	body = append(body, initiatorEd25519Pub...)
	if sig != nil {
		s := sig.Encode()
		body = append(body, s[:]...)
	}

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationSingle,
		PacketType:      PacketLinkRequest,
		Hops:            0,
		DestHash:        responderDestHash,
		Context:         ContextNone,
		Data:            body,
	}, nil
}

// LinkRequest is a parsed LINKREQUEST packet body (SPEC §6.1).
type LinkRequest struct {
	InitiatorX25519Pub  []byte // 32
	InitiatorEd25519Pub []byte // 32
	Signalling          *LinkSignalling
}

// ParseLinkRequest extracts the initiator's ephemeral keys and any
// optional signalling. The presence of signalling is detected by body
// length per SPEC §6.1.
func ParseLinkRequest(p *Packet) (*LinkRequest, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketLinkRequest {
		return nil, fmt.Errorf("packet_type %d is not LINKREQUEST", p.PacketType)
	}

	out := &LinkRequest{}
	switch len(p.Data) {
	case LinkRequestBodyLen:
		out.InitiatorX25519Pub = p.Data[0:32]
		out.InitiatorEd25519Pub = p.Data[32:64]
	case LinkRequestBodyLenSignalled:
		out.InitiatorX25519Pub = p.Data[0:32]
		out.InitiatorEd25519Pub = p.Data[32:64]
		s, err := DecodeLinkSignalling(p.Data[64:67])
		if err != nil {
			return nil, err
		}
		out.Signalling = &s
	default:
		return nil, fmt.Errorf("LINKREQUEST body must be %d or %d bytes, got %d",
			LinkRequestBodyLen, LinkRequestBodyLenSignalled, len(p.Data))
	}
	return out, nil
}

// LinkID derives the 16-byte link identifier from a LINKREQUEST packet
// (SPEC §6.3). The hashable_part already strips the high nibble of flags,
// the hops byte, and (for HEADER_2) the transport_id slot. We additionally
// strip the optional signalling trailer from the END of the body so the
// link_id is invariant under MTU-discovery signalling.
func LinkID(linkRequest *Packet) ([]byte, error) {
	if linkRequest == nil {
		return nil, errors.New("nil packet")
	}
	if linkRequest.PacketType != PacketLinkRequest {
		return nil, fmt.Errorf("packet_type %d is not LINKREQUEST", linkRequest.PacketType)
	}

	hp, err := linkRequest.HashablePart()
	if err != nil {
		return nil, err
	}
	if len(linkRequest.Data) > LinkRequestBodyLen {
		hp = hp[:len(hp)-LinkSignallingLen]
	}

	digest := sha256.Sum256(hp)
	out := make([]byte, IdentityHashLen)
	copy(out, digest[:IdentityHashLen])
	return out, nil
}

// DeriveLinkSessionKeys runs ECDH + HKDF per SPEC §6.4. salt = link_id,
// info = empty, output = 64 bytes split as (signing, encryption). Both
// sides compute the same keys.
func DeriveLinkSessionKeys(myEphPriv, peerEphPub, linkID []byte) (signing, encryption []byte, err error) {
	if len(myEphPriv) != 32 {
		return nil, nil, fmt.Errorf("ephemeral private must be 32 bytes, got %d", len(myEphPriv))
	}
	if len(peerEphPub) != 32 {
		return nil, nil, fmt.Errorf("peer ephemeral pub must be 32 bytes, got %d", len(peerEphPub))
	}
	if len(linkID) != IdentityHashLen {
		return nil, nil, fmt.Errorf("link_id must be %d bytes, got %d", IdentityHashLen, len(linkID))
	}

	shared, err := curve25519.X25519(myEphPriv, peerEphPub)
	if err != nil {
		return nil, nil, fmt.Errorf("ECDH: %w", err)
	}
	r := hkdf.New(sha256.New, shared, linkID, nil /* info */)
	derived := make([]byte, LinkSessionKeyLen)
	if _, err := io.ReadFull(r, derived); err != nil {
		return nil, nil, fmt.Errorf("HKDF: %w", err)
	}
	return derived[:32], derived[32:], nil
}

// BuildLRProof builds an LRPROOF packet (SPEC §6.2) sent from the
// responder back to the initiator after a successful LINKREQUEST. The
// responder signs with its long-term Ed25519 private key (responderID).
//
// Wire packet:
//
//	flags(1) || hops(1) || link_id(16) || context=0xff(1) || sig(64)
//	|| responder_X25519_pub(32) || [signalling(3)]
//
// Signed data:
//
//	link_id || responder_X25519_pub || responder_long_term_Ed25519_pub || [signalling]
//
// Note: the responder's long-term Ed25519 pub is included in the signature
// input even though it is NOT on the wire — both sides already know it
// from the responder's prior announce. This commits the proof to the
// announcing identity.
func BuildLRProof(responderID *Identity, linkID, responderX25519Pub []byte, sig *LinkSignalling) (*Packet, error) {
	if responderID == nil {
		return nil, errors.New("nil responder identity")
	}
	if len(linkID) != IdentityHashLen {
		return nil, fmt.Errorf("link_id must be %d bytes", IdentityHashLen)
	}
	if len(responderX25519Pub) != 32 {
		return nil, fmt.Errorf("responder X25519 pub must be 32 bytes")
	}

	ed25519Pub := responderID.PublicKey()[32:]
	signed := buildLRProofSignedData(linkID, responderX25519Pub, ed25519Pub, sig)
	signature := responderID.Sign(signed)

	body := make([]byte, 0, LRProofBodyLenSignalled)
	body = append(body, signature...)
	body = append(body, responderX25519Pub...)
	if sig != nil {
		s := sig.Encode()
		body = append(body, s[:]...)
	}

	return &Packet{
		HeaderType:      HeaderType1,
		ContextFlag:     false,
		TransportType:   BroadcastTransport,
		DestinationType: DestinationLink, // SPEC §6.2: outer dest_hash slot is link_id, dest_type=LINK
		PacketType:      PacketProof,
		Hops:            0,
		DestHash:        linkID,
		Context:         ContextLRProof,
		Data:            body,
	}, nil
}

// LRProof is a parsed LRPROOF body.
type LRProof struct {
	LinkID             []byte // 16, taken from outer packet header
	Signature          []byte // 64
	ResponderX25519Pub []byte // 32
	Signalling         *LinkSignalling
}

// ParseLRProof extracts the LRPROOF body. The link_id is taken from the
// outer packet header; the body itself does NOT carry it.
func ParseLRProof(p *Packet) (*LRProof, error) {
	if p == nil {
		return nil, errors.New("nil packet")
	}
	if p.PacketType != PacketProof || p.Context != ContextLRProof {
		return nil, fmt.Errorf("packet is not LRPROOF (type=%d ctx=0x%02x)", p.PacketType, p.Context)
	}
	if p.DestinationType != DestinationLink {
		return nil, fmt.Errorf("LRPROOF dest_type must be LINK (3), got %d", p.DestinationType)
	}

	out := &LRProof{LinkID: p.DestHash}
	switch len(p.Data) {
	case LRProofBodyLen:
		out.Signature = p.Data[0:64]
		out.ResponderX25519Pub = p.Data[64:96]
	case LRProofBodyLenSignalled:
		out.Signature = p.Data[0:64]
		out.ResponderX25519Pub = p.Data[64:96]
		s, err := DecodeLinkSignalling(p.Data[96:99])
		if err != nil {
			return nil, err
		}
		out.Signalling = &s
	default:
		return nil, fmt.Errorf("LRPROOF body must be %d or %d bytes, got %d",
			LRProofBodyLen, LRProofBodyLenSignalled, len(p.Data))
	}
	return out, nil
}

// Verify checks the LRPROOF signature against the responder's long-term
// Ed25519 public key (which the initiator already has from a prior
// announce). The signed data must reconstruct exactly per SPEC §6.2.
func (lr *LRProof) Verify(responderEd25519Pub []byte) error {
	if len(responderEd25519Pub) != 32 {
		return errors.New("responder Ed25519 pub must be 32 bytes")
	}
	signed := buildLRProofSignedData(lr.LinkID, lr.ResponderX25519Pub, responderEd25519Pub, lr.Signalling)
	if !Validate(responderEd25519Pub, signed, lr.Signature) {
		return errors.New("LRPROOF signature invalid")
	}
	return nil
}

func buildLRProofSignedData(linkID, responderX25519Pub, responderEd25519Pub []byte, sig *LinkSignalling) []byte {
	out := make([]byte, 0, IdentityHashLen+32+32+LinkSignallingLen)
	out = append(out, linkID...)
	out = append(out, responderX25519Pub...)
	out = append(out, responderEd25519Pub...)
	if sig != nil {
		s := sig.Encode()
		out = append(out, s[:]...)
	}
	return out
}
