package rns

import "time"

// This file exposes a small surface of internals to test packages
// (lxmf, service) that need to drive scenarios deterministically. The
// helpers are named *ForTest so a casual reader sees they're not part
// of the production API. They are NOT marked `_test.go` because the
// test packages that import them live outside the rns package and
// cross-package test helpers must be in regular files.

// TestSetLinkLastActivity sets l.LastActivity under the link mutex.
// Used to age a link before invoking SweepLinks/RunLinkSweeper in
// tests without sleeping for real time.
func TestSetLinkLastActivity(l *Link, t time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.LastActivity = t
}

// TestGetLinkLastActivity reads l.LastActivity under the link mutex.
func TestGetLinkLastActivity(l *Link) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.LastActivity
}

// TestSetLinkState sets l.State under the link mutex. Used by negative
// tests that want to simulate a torn-down or pending state without
// driving the full handshake.
func TestSetLinkState(l *Link, s LinkState) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.State = s
}

// SweepLinksForTest is a public alias for the (unexported) sweepLinks
// pass. Callable from tests to trigger one cycle deterministically.
func (t *Transport) SweepLinksForTest() { t.sweepLinks() }

// TestDispatchRaw feeds raw wire bytes through the Transport's
// dispatcher just like an inbound interface would. Lets tests inject
// crafted packets (e.g., synthetic announces, forged proofs) without
// owning a real interface.
func TestDispatchRaw(t *Transport, raw []byte) { t.dispatch(raw) }
