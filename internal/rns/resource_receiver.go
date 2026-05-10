package rns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceReceiver collects the parts of one inbound Resource transfer
// over an active Link, reassembles, validates, and emits the final
// proof. State machine per SPEC §10:
//
//	openResourceReceiver(ADV)
//	    ↓
//	  REQUESTING ──(parts arrive)──→ ASSEMBLING ──(hash OK)──→ COMPLETE
//	    ↓                                ↓
//	  TIMEOUT/CANCEL                  CORRUPT
//
// Lifecycle is driven by Run(ctx); inbound RESOURCE parts and HMU
// segments arrive via channels from the Transport dispatcher so
// dispatcher work never blocks on receiver state.
//
// fwdsvc itself is unlikely to receive a Resource as a relay (we
// only forward small command messages), but the receiver is needed
// for interop completeness — any LXMF DM whose direct body exceeds
// Link.MDU MUST come through this path. Without it, oversized inbound
// DMs would be RCL'd back to the sender and never delivered.

const (
	// ReceiverWindowMaxOutstanding caps how many parts the receiver
	// will request in one REQ. Conservative — upstream's WINDOW_MAX
	// scales by observed throughput; we pick the slow-rate cap as a
	// universal safe value. Stage 5 may add adaptive scaling.
	ReceiverWindowMaxOutstanding = WindowMaxSlow
)

// ResourceReceiver owns the per-resource state and the goroutine that
// drives reassembly. One receiver per inbound resource per Link. A
// completed receiver (success or failure) MUST unregister itself
// from the LinkManager so a dead transfer doesn't keep its slot.
type ResourceReceiver struct {
	transport *Transport
	link      *Link
	logger    Logger

	// Identification — captured from the ADV, immutable after.
	resourceHash    []byte
	randomR         []byte
	expectedSize    int
	dataSize        int
	flags           int
	multihopID      []byte

	linkSigning    []byte
	linkEncryption []byte

	// Hashmap is the concatenated map_hashes from the ADV. Receiver
	// scans this to find the slot for an inbound part by computing
	// SHA256(part || randomR)[:4] and matching.
	hashmap []byte

	// parts[i] = ciphertext slice for part i (nil until received).
	// Indexed by hashmap position (0-based).
	parts         [][]byte
	receivedCount int
	receivedFlags []bool // parts[i] arrived?

	// Channels: dispatcher → receiver goroutine.
	partCh   chan []byte
	cancelCh chan struct{}

	state atomic.Int32
	done  chan struct{}

	mu sync.Mutex // guards parts / receivedFlags / receivedCount

	// OnAssembled is called from the receiver goroutine with the
	// fully-assembled, decrypted, prefix-stripped body. Wired by the
	// caller of openResourceReceiver to plug into Delivery's normal
	// inbound-link-plaintext handler.
	OnAssembled func(body []byte)
}

// openResourceReceiver constructs a ResourceReceiver from a parsed
// ADV and starts its goroutine. Registers the receiver with the
// LinkManager so inbound parts can be routed by (link_id,
// resource_hash). Idempotency is enforced by registerResourceReceiver
// returning an error on duplicate registration.
func (t *Transport) openResourceReceiver(link *Link, adv *ResourceAdvertisement) error {
	link.mu.Lock()
	state := link.State
	signing := append([]byte(nil), link.Signing...)
	encryption := append([]byte(nil), link.Encryption...)
	cb := link.OnInboundData
	link.mu.Unlock()
	if state != LinkActive {
		return fmt.Errorf("resource receiver: link state %s, want active", state)
	}
	rr := &ResourceReceiver{
		transport:      t,
		link:           link,
		logger:         t.logger,
		resourceHash:   append([]byte(nil), adv.Hash...),
		randomR:        append([]byte(nil), adv.RandomHash...),
		expectedSize:   adv.TransferSize,
		dataSize:       adv.DataSize,
		flags:          adv.Flags,
		hashmap:        append([]byte(nil), adv.Hashmap...),
		parts:          make([][]byte, adv.NumParts),
		receivedFlags:  make([]bool, adv.NumParts),
		partCh:         make(chan []byte, 32),
		cancelCh:       make(chan struct{}, 1),
		done:           make(chan struct{}),
		linkSigning:    signing,
		linkEncryption: encryption,
		OnAssembled: func(body []byte) {
			if cb != nil {
				cb(body)
			}
		},
	}
	rr.state.Store(int32(ResourceStateTransferring))

	if err := t.linkManager.registerResourceReceiver(link.ID, rr.resourceHash, rr); err != nil {
		return err
	}

	// Run synchronously in a goroutine — caller (handleResourceAdv)
	// returns immediately.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), DefaultLinkSendTimeout)
		defer cancel()
		_ = rr.Run(ctx)
	}()
	return nil
}

// HandleCancel is invoked when the peer (initiator) sends RESOURCE_ICL
// or when CloseLink terminates the link.
func (rr *ResourceReceiver) HandleCancel() {
	select {
	case rr.cancelCh <- struct{}{}:
	default:
	}
}

// HandlePart is invoked by the Transport dispatcher when a RESOURCE
// (context = 0x01) packet arrives on the same link. The part body
// is the raw ciphertext slice; receiver matches by computing its
// 4-byte map_hash against its hashmap window.
func (rr *ResourceReceiver) HandlePart(partCiphertext []byte) {
	select {
	case rr.partCh <- append([]byte(nil), partCiphertext...):
	default:
		rr.logger.Printf("resource receiver: PART channel full for %s — dropping",
			ResourceHashShortHex(rr.resourceHash))
	}
}

// Run drives the receive state machine. Issues REQs for unreceived
// parts, processes inbound parts, and on completion validates +
// emits PRF. Returns nil on COMPLETE.
func (rr *ResourceReceiver) Run(ctx context.Context) error {
	defer close(rr.done)
	defer rr.transport.linkManager.unregisterResource(rr.link.ID, rr.resourceHash)

	// Initial request — ask for as many as fit our window.
	if err := rr.requestNextWindow(); err != nil {
		rr.logger.Printf("resource receiver: initial REQ: %v", err)
		rr.state.Store(int32(ResourceStateFailed))
		return err
	}

	const partTimeout = 12 * time.Second
	timer := time.NewTimer(partTimeout)
	defer timer.Stop()

	for rr.receivedCount < len(rr.parts) {
		select {
		case <-ctx.Done():
			rr.state.Store(int32(ResourceStateFailed))
			return ctx.Err()

		case <-rr.cancelCh:
			rr.state.Store(int32(ResourceStateCancelled))
			return ErrResourceCancelled

		case <-timer.C:
			// No parts arrived in the timeout window — re-request the
			// gaps. If we've used up MaxRetries worth of timeouts,
			// give up. (Very simple watchdog; stage 5 can add adaptive
			// RTT-based timing.)
			if err := rr.requestNextWindow(); err != nil {
				rr.logger.Printf("resource receiver: re-REQ: %v", err)
			}
			timer.Reset(partTimeout)

		case part := <-rr.partCh:
			if err := rr.placePart(part); err != nil {
				rr.logger.Printf("resource receiver: place part: %v", err)
				continue
			}
			// Whenever a part arrives, push the timer out — progress.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(partTimeout)

			// If we just filled a window's worth, request the next.
			if rr.windowComplete() && rr.receivedCount < len(rr.parts) {
				if err := rr.requestNextWindow(); err != nil {
					rr.logger.Printf("resource receiver: window REQ: %v", err)
				}
			}
		}
	}

	// All parts in. Reassemble + decrypt + verify.
	rr.state.Store(int32(ResourceStateAssembling))
	body, err := rr.assemble()
	if err != nil {
		rr.state.Store(int32(ResourceStateCorrupt))
		// Politely tell the sender we can't reassemble so they don't
		// keep retransmitting on watchdog.
		if cancelErr := rr.transport.broadcastResourceCancel(rr.link, rr.resourceHash, false); cancelErr != nil {
			rr.logger.Printf("resource receiver: RCL on assemble error: %v", cancelErr)
		}
		return err
	}
	rr.state.Store(int32(ResourceStateComplete))
	rr.logger.Printf("resource receiver: complete link=%x resource=%s body=%d bytes",
		rr.link.ID[:4], ResourceHashShortHex(rr.resourceHash), len(body))

	// Emit PRF before invoking the application callback so the sender
	// gets fast confirmation even if OnAssembled is slow.
	if err := rr.broadcastProof(); err != nil {
		rr.logger.Printf("resource receiver: PRF emit: %v", err)
		// Continue to deliver the body anyway — failing PRF emit
		// just means the sender will eventually time out, but we
		// already have the body.
	}

	if rr.OnAssembled != nil {
		// Run on a goroutine to avoid blocking the receive loop's
		// teardown if the application handler is slow.
		go rr.OnAssembled(body)
	}
	return nil
}

// placePart locates the part's hashmap slot via map_hash, drops it
// in. Idempotent on duplicate parts (they just no-op).
func (rr *ResourceReceiver) placePart(part []byte) error {
	mh := ResourceMapHash(part, rr.randomR)
	rr.mu.Lock()
	defer rr.mu.Unlock()
	for i := 0; i < len(rr.parts); i++ {
		if rr.receivedFlags[i] {
			continue
		}
		off := i * ResourceMapHashLen
		if bytesEqual(rr.hashmap[off:off+ResourceMapHashLen], mh) {
			rr.parts[i] = part
			rr.receivedFlags[i] = true
			rr.receivedCount++
			return nil
		}
	}
	// Either a duplicate (already-received slot) or a part with a
	// map_hash we don't know about (sender bug or malicious peer).
	// Either way, drop quietly — the legitimate parts will fill the
	// remaining slots eventually.
	return errors.New("part map_hash not in remaining hashmap (duplicate or unknown)")
}

// windowComplete returns true when no parts remain outstanding from
// the most recent REQ window — i.e. the next REQ should be issued.
func (rr *ResourceReceiver) windowComplete() bool {
	// Trivial heuristic: if we have any unreceived part, we have an
	// outstanding window slot. The receiver issues a REQ whenever a
	// gap exists. Stage 5 can add proper window tracking.
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return rr.receivedCount > 0 // any progress → consider window done
}

// requestNextWindow builds and sends a RESOURCE_REQ for the next
// batch of unreceived map_hashes, capped at ReceiverWindowMaxOutstanding.
func (rr *ResourceReceiver) requestNextWindow() error {
	rr.mu.Lock()
	requested := make([][]byte, 0, ReceiverWindowMaxOutstanding)
	for i := 0; i < len(rr.parts) && len(requested) < ReceiverWindowMaxOutstanding; i++ {
		if rr.receivedFlags[i] {
			continue
		}
		off := i * ResourceMapHashLen
		mh := append([]byte(nil), rr.hashmap[off:off+ResourceMapHashLen]...)
		requested = append(requested, mh)
	}
	rr.mu.Unlock()
	if len(requested) == 0 {
		return nil
	}

	body, err := BuildResourceReq(&ResourceRequest{
		ResourceHash: rr.resourceHash,
		RequestedMap: requested,
	})
	if err != nil {
		return fmt.Errorf("build REQ: %w", err)
	}
	ciphertext, err := LinkTokenEncrypt(body, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return fmt.Errorf("encrypt REQ: %w", err)
	}
	pkt, err := buildResourceCtxPacket(rr.link.ID, ciphertext, ContextResourceREQ, false)
	if err != nil {
		return err
	}
	applyMultihopRouting(pkt, rr.multihopID)
	return rr.transport.Broadcast(pkt)
}

// assemble concatenates the received parts in order, link-decrypts
// the result, strips the 4-byte body prefix, and verifies the SHA-256
// against the advertised hash. Returns the body or an error.
func (rr *ResourceReceiver) assemble() ([]byte, error) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	totalLen := 0
	for _, p := range rr.parts {
		totalLen += len(p)
	}
	if totalLen != rr.expectedSize {
		return nil, fmt.Errorf("%w: assembled %d bytes, ADV said %d",
			ErrResourceHashMismatch, totalLen, rr.expectedSize)
	}
	stream := make([]byte, 0, totalLen)
	for _, p := range rr.parts {
		stream = append(stream, p...)
	}
	plaintext, err := LinkTokenDecrypt(stream, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return nil, fmt.Errorf("link decrypt: %w", err)
	}
	if len(plaintext) < ResourceRandomHashSize {
		return nil, fmt.Errorf("decrypted %d bytes < prefix %d", len(plaintext), ResourceRandomHashSize)
	}
	body := plaintext[ResourceRandomHashSize:] // strip the 4-byte body prefix (SPEC §10.8 callout)

	// Belt-and-suspenders: compare actual body length to advertised.
	// dataSize is the original plaintext length per SPEC §10.4 `d`.
	if len(body) != rr.dataSize {
		return nil, fmt.Errorf("%w: body %d bytes, ADV.d said %d",
			ErrResourceHashMismatch, len(body), rr.dataSize)
	}

	// Hash check — exact match on advertised h.
	if calc := ResourceHash(body, rr.randomR); !bytesEqual(calc, rr.resourceHash) {
		return nil, ErrResourceHashMismatch
	}
	return body, nil
}

// broadcastProof emits the RESOURCE_PRF as a PROOF-type packet (NOT
// link-encrypted per SPEC §10.3).
func (rr *ResourceReceiver) broadcastProof() error {
	rr.mu.Lock()
	totalLen := 0
	for _, p := range rr.parts {
		totalLen += len(p)
	}
	stream := make([]byte, 0, totalLen)
	for _, p := range rr.parts {
		stream = append(stream, p...)
	}
	rr.mu.Unlock()

	plaintext, err := LinkTokenDecrypt(stream, rr.linkSigning, rr.linkEncryption)
	if err != nil {
		return fmt.Errorf("decrypt for PRF: %w", err)
	}
	body := plaintext[ResourceRandomHashSize:]
	fullProof := ResourceExpectedProof(body, rr.resourceHash)

	prfBody, err := BuildResourceProof(&ResourceProof{
		ResourceHash: rr.resourceHash,
		FullProof:    fullProof,
	})
	if err != nil {
		return err
	}
	pkt, err := buildResourceCtxPacket(rr.link.ID, prfBody, ContextResourcePRF, true /* PROOF type */)
	if err != nil {
		return err
	}
	applyMultihopRouting(pkt, rr.multihopID)
	return rr.transport.Broadcast(pkt)
}
