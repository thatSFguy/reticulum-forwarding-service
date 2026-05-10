package rns

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/vmihailenco/msgpack/v5"
)

// Wire-format builders/parsers for RESOURCE_REQ, RESOURCE part,
// RESOURCE_HMU, RESOURCE_PRF, RESOURCE_ICL, RESOURCE_RCL.
// ADV lives in resource_adv.go because of its msgpack-dict shape.
//
// All builders produce *Packet values WITHOUT a destination hash —
// they assume the caller will fill in DestHash = link_id and
// Broadcast via the Transport. Keeping link_id out of these helpers
// lets unit tests assert wire body bytes without dragging a Link
// fixture around.

// --- RESOURCE_REQ -----------------------------------------------------

// ResourceRequest is the parsed view of a RESOURCE_REQ body
// (SPEC §10.5):
//
//	hashmap_exhausted_flag(1) [|| last_map_hash(4) if exhausted]
//	|| resource_hash(32)
//	|| requested_map_hashes(N × 4)
//
// `Exhausted` and `LastMapHash` are mutually consistent — when
// Exhausted=true LastMapHash is non-nil and 4 bytes; otherwise nil.
type ResourceRequest struct {
	Exhausted    bool
	LastMapHash  []byte // present when Exhausted; nil otherwise
	ResourceHash []byte // 32 bytes
	RequestedMap [][]byte
}

// BuildResourceReq packs a ResourceRequest into the body bytes for a
// Link DATA packet with context = RESOURCE_REQ.
func BuildResourceReq(req *ResourceRequest) ([]byte, error) {
	if req == nil {
		return nil, errors.New("resource req: nil")
	}
	if len(req.ResourceHash) != 32 {
		return nil, fmt.Errorf("resource req: resource_hash must be 32 bytes, got %d", len(req.ResourceHash))
	}
	if req.Exhausted && len(req.LastMapHash) != ResourceMapHashLen {
		return nil, fmt.Errorf("resource req: last_map_hash must be %d bytes when exhausted, got %d",
			ResourceMapHashLen, len(req.LastMapHash))
	}

	out := make([]byte, 0, 1+ResourceMapHashLen+32+len(req.RequestedMap)*ResourceMapHashLen)
	if req.Exhausted {
		out = append(out, HashmapExhausted)
		out = append(out, req.LastMapHash...)
	} else {
		out = append(out, HashmapNotExhausted)
	}
	out = append(out, req.ResourceHash...)
	for i, mh := range req.RequestedMap {
		if len(mh) != ResourceMapHashLen {
			return nil, fmt.Errorf("resource req: requested_map[%d] = %d bytes, want %d", i, len(mh), ResourceMapHashLen)
		}
		out = append(out, mh...)
	}
	return out, nil
}

// ParseResourceReq decodes the body of an inbound RESOURCE_REQ. Used
// by the sender to know which parts the receiver wants delivered next.
func ParseResourceReq(body []byte) (*ResourceRequest, error) {
	if len(body) < 1+32 {
		return nil, fmt.Errorf("resource req: body %d bytes < min %d", len(body), 1+32)
	}
	req := &ResourceRequest{}
	off := 0
	switch body[0] {
	case HashmapExhausted:
		req.Exhausted = true
		if len(body) < 1+ResourceMapHashLen+32 {
			return nil, fmt.Errorf("resource req: exhausted body %d bytes < min %d", len(body), 1+ResourceMapHashLen+32)
		}
		off = 1
		req.LastMapHash = append([]byte(nil), body[off:off+ResourceMapHashLen]...)
		off += ResourceMapHashLen
	case HashmapNotExhausted:
		off = 1
	default:
		return nil, fmt.Errorf("resource req: unknown exhausted flag 0x%02x", body[0])
	}
	req.ResourceHash = append([]byte(nil), body[off:off+32]...)
	off += 32
	tail := body[off:]
	if len(tail)%ResourceMapHashLen != 0 {
		return nil, fmt.Errorf("resource req: trailing %d bytes not multiple of MAPHASH_LEN=%d", len(tail), ResourceMapHashLen)
	}
	for i := 0; i < len(tail); i += ResourceMapHashLen {
		req.RequestedMap = append(req.RequestedMap, append([]byte(nil), tail[i:i+ResourceMapHashLen]...))
	}
	return req, nil
}

// --- RESOURCE part ---------------------------------------------------

// BuildResourcePart wraps one already-encrypted SDU-sized slice as a
// RESOURCE-context Link DATA packet body. Returned bytes are the
// packet body — caller still needs to wrap in a Packet with
// DestHash=link_id, PacketType=DATA, Context=ContextResource.
//
// The slice is NOT re-encrypted (SPEC §10.12) — the caller has
// already link.encrypt'd the whole concatenated body and sliced.
// Passing in a plaintext slice here will produce a packet the
// receiver can fingerprint via map_hash but never decrypt.
func BuildResourcePart(partCiphertext []byte) []byte {
	return append([]byte(nil), partCiphertext...)
}

// --- RESOURCE_HMU ----------------------------------------------------

// ResourceHmu is the parsed view of a hashmap-update packet body
// (SPEC §10.7):
//
//	resource_hash(32) || msgpack([segment_index, hashmap_segment_bytes])
//
// SegmentIndex starts at 1 (the original ADV's hashmap is segment 0
// implicitly; HMU delivers segments 1..N).
type ResourceHmu struct {
	ResourceHash []byte
	SegmentIndex int
	HashmapBytes []byte
}

// BuildResourceHmu packs a hashmap-update for a long resource where
// the hashmap doesn't fit in one ADV.
func BuildResourceHmu(h *ResourceHmu) ([]byte, error) {
	if h == nil {
		return nil, errors.New("resource hmu: nil")
	}
	if len(h.ResourceHash) != 32 {
		return nil, fmt.Errorf("resource hmu: resource_hash must be 32 bytes, got %d", len(h.ResourceHash))
	}
	if h.SegmentIndex < 1 {
		return nil, fmt.Errorf("resource hmu: segment_index must be >= 1, got %d", h.SegmentIndex)
	}
	if len(h.HashmapBytes) == 0 || len(h.HashmapBytes)%ResourceMapHashLen != 0 {
		return nil, fmt.Errorf("resource hmu: hashmap_bytes %d not positive multiple of %d",
			len(h.HashmapBytes), ResourceMapHashLen)
	}
	tail, err := msgpack.Marshal([]any{h.SegmentIndex, h.HashmapBytes})
	if err != nil {
		return nil, fmt.Errorf("resource hmu: msgpack: %w", err)
	}
	out := make([]byte, 0, 32+len(tail))
	out = append(out, h.ResourceHash...)
	out = append(out, tail...)
	return out, nil
}

// ParseResourceHmu decodes the body of an inbound RESOURCE_HMU.
func ParseResourceHmu(body []byte) (*ResourceHmu, error) {
	if len(body) < 32 {
		return nil, fmt.Errorf("resource hmu: body %d bytes < 32 (resource_hash)", len(body))
	}
	h := &ResourceHmu{
		ResourceHash: append([]byte(nil), body[:32]...),
	}
	var pair []any
	if err := msgpack.Unmarshal(body[32:], &pair); err != nil {
		return nil, fmt.Errorf("resource hmu: msgpack: %w", err)
	}
	if len(pair) != 2 {
		return nil, fmt.Errorf("resource hmu: msgpack list len = %d, want 2", len(pair))
	}
	switch v := pair[0].(type) {
	case int8:
		h.SegmentIndex = int(v)
	case int16:
		h.SegmentIndex = int(v)
	case int32:
		h.SegmentIndex = int(v)
	case int64:
		h.SegmentIndex = int(v)
	case uint8:
		h.SegmentIndex = int(v)
	case uint16:
		h.SegmentIndex = int(v)
	case uint32:
		h.SegmentIndex = int(v)
	case uint64:
		h.SegmentIndex = int(v)
	case int:
		h.SegmentIndex = v
	default:
		return nil, fmt.Errorf("resource hmu: segment_index has wrong msgpack type %T", v)
	}
	switch v := pair[1].(type) {
	case []byte:
		h.HashmapBytes = append([]byte(nil), v...)
	default:
		return nil, fmt.Errorf("resource hmu: hashmap has wrong msgpack type %T", v)
	}
	if h.SegmentIndex < 1 {
		return nil, fmt.Errorf("resource hmu: segment_index %d < 1", h.SegmentIndex)
	}
	if len(h.HashmapBytes) == 0 || len(h.HashmapBytes)%ResourceMapHashLen != 0 {
		return nil, fmt.Errorf("resource hmu: hashmap_bytes %d not positive multiple of %d",
			len(h.HashmapBytes), ResourceMapHashLen)
	}
	return h, nil
}

// --- RESOURCE_PRF ----------------------------------------------------

// ResourceProof is the body of a PROOF-type packet with context =
// RESOURCE_PRF (SPEC §10.8):
//
//	resource_hash(32) || full_proof(32)
//
// `FullProof` matches the SENDER-pre-computed expected_proof = SHA256
// (plaintext_body || resource_hash). Sender validates by constant-
// time compare against its stored expected_proof.
type ResourceProof struct {
	ResourceHash []byte
	FullProof    []byte
}

// BuildResourceProof packs a final-proof body for emission as a
// PROOF-type packet with context = RESOURCE_PRF.
func BuildResourceProof(p *ResourceProof) ([]byte, error) {
	if p == nil {
		return nil, errors.New("resource prf: nil")
	}
	if len(p.ResourceHash) != 32 || len(p.FullProof) != 32 {
		return nil, fmt.Errorf("resource prf: hash=%d proof=%d, want 32+32", len(p.ResourceHash), len(p.FullProof))
	}
	out := make([]byte, 0, 64)
	out = append(out, p.ResourceHash...)
	out = append(out, p.FullProof...)
	return out, nil
}

// ParseResourceProof decodes the body of an inbound RESOURCE_PRF.
func ParseResourceProof(body []byte) (*ResourceProof, error) {
	if len(body) != 64 {
		return nil, fmt.Errorf("resource prf: body %d bytes, want 64", len(body))
	}
	return &ResourceProof{
		ResourceHash: append([]byte(nil), body[:32]...),
		FullProof:    append([]byte(nil), body[32:]...),
	}, nil
}

// --- RESOURCE_ICL / RESOURCE_RCL -------------------------------------

// BuildResourceCancel emits the body for either RESOURCE_ICL
// (initiator cancel) or RESOURCE_RCL (receiver cancel/reject). Both
// have the same wire shape — just the resource_hash. Caller picks the
// context byte when wrapping in a Packet.
func BuildResourceCancel(resourceHash []byte) ([]byte, error) {
	if len(resourceHash) != 32 {
		return nil, fmt.Errorf("resource cancel: resource_hash must be 32 bytes, got %d", len(resourceHash))
	}
	return append([]byte(nil), resourceHash...), nil
}

// ParseResourceCancel extracts the resource_hash from an ICL or RCL
// body.
func ParseResourceCancel(body []byte) ([]byte, error) {
	if len(body) != 32 {
		return nil, fmt.Errorf("resource cancel: body %d bytes, want 32", len(body))
	}
	return append([]byte(nil), body...), nil
}

// --- helpers ---------------------------------------------------------

// ResourceHashShortHex is a debug helper — never used on the wire.
// Returns the first 8 hex chars of the hash for log lines.
func ResourceHashShortHex(h []byte) string {
	if len(h) < 4 {
		return "?"
	}
	return hex.EncodeToString(h[:4])
}

// proofEqualsConstantTime is a constant-time compare for the 32-byte
// expected_proof check. Avoids leaking the proof prefix that matched
// via timing; not strictly necessary for a self-link transfer but
// good practice in case the link is later observable.
func proofEqualsConstantTime(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// Compile-time guard: SHA-256 hash size matches what we hard-code as
// 32 in the packing helpers. Catches a hypothetical refactor that
// imported a different hash function.
var _ = [1]byte{}[sha256.Size-32]
