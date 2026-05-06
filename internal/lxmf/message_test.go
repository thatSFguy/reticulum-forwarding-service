package lxmf

import (
	"bytes"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/rns"
)

func TestSignParseVerifyRoundTrip(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()

	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, err := SignAndPackOpportunistic(
		sender, senderDest, recipientDest,
		[]byte(""),
		[]byte("hello world"),
		nil,
	)
	if err != nil {
		t.Fatalf("SignAndPackOpportunistic: %v", err)
	}

	m, err := ParseOpportunisticBody(body, recipientDest)
	if err != nil {
		t.Fatalf("ParseOpportunisticBody: %v", err)
	}
	if !bytes.Equal(m.SourceHash, senderDest) {
		t.Errorf("source_hash mismatch")
	}
	if string(m.Content) != "hello world" {
		t.Errorf("content = %q, want %q", m.Content, "hello world")
	}

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hello"), nil)
	m, _ := ParseOpportunisticBody(body, recipientDest)

	// Tamper directly with the rawPayload bytes (preserved on the message).
	m.rawPayload = append([]byte(nil), m.rawPayload...)
	m.rawPayload[len(m.rawPayload)-1] ^= 0x01

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err == nil {
		t.Error("Verify accepted tampered payload")
	}
}

func TestVerifyRejectsForgedDestHash(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	body, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hello"), nil)

	bogusDest := bytes.Repeat([]byte{0xAA}, rns.IdentityHashLen)
	m, _ := ParseOpportunisticBody(body, bogusDest)
	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err == nil {
		t.Error("Verify accepted forged dest_hash")
	}
}

func TestVerifyAcceptsStampStrippedVariant(t *testing.T) {
	// Simulate a sender that signed over a 4-element payload, then
	// appended a stamp as element [4]. Receiver must strip and re-verify.
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	// Step 1: produce a normal 4-element body and capture its msgpack payload.
	body, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hi"), nil)
	headerEnd := rns.IdentityHashLen + signatureLen
	source := body[:rns.IdentityHashLen]
	sig := body[rns.IdentityHashLen:headerEnd]
	payload4 := body[headerEnd:]

	// Step 2: re-encode as a 5-element msgpack with a fake stamp.
	var elems []any
	for _, e := range mustDecodeArray(t, payload4) {
		elems = append(elems, e)
	}
	stamp := bytes.Repeat([]byte{0xBE}, 32)
	elems = append(elems, stamp)
	payload5, err := msgpack.Marshal(elems)
	if err != nil {
		t.Fatal(err)
	}

	body5 := make([]byte, 0, len(source)+len(sig)+len(payload5))
	body5 = append(body5, source...)
	body5 = append(body5, sig...)
	body5 = append(body5, payload5...)

	m, err := ParseOpportunisticBody(body5, recipientDest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Stamp, stamp) {
		t.Errorf("stamp not extracted: got %x want %x", m.Stamp, stamp)
	}
	if string(m.Content) != "hi" {
		t.Errorf("content = %q, want hi", m.Content)
	}

	senderEd := sender.PublicKey()[32:]
	if err := m.Verify(senderEd); err != nil {
		t.Errorf("Verify with stamp-stripped variant failed: %v", err)
	}
}

func TestRoundTripPreservesTimestamp(t *testing.T) {
	sender, _ := rns.NewIdentity()
	recipient, _ := rns.NewIdentity()
	senderDest := sender.DestinationHashFor(FullName())
	recipientDest := recipient.DestinationHashFor(FullName())

	before := time.Now().Truncate(time.Microsecond)
	body, _ := SignAndPackOpportunistic(sender, senderDest, recipientDest, nil, []byte("hi"), nil)
	after := time.Now()

	m, _ := ParseOpportunisticBody(body, recipientDest)
	if m.Timestamp.Before(before.Add(-time.Second)) || m.Timestamp.After(after.Add(time.Second)) {
		t.Errorf("timestamp %v not within [%v, %v]", m.Timestamp, before, after)
	}
}

func mustDecodeArray(t *testing.T, raw []byte) []any {
	t.Helper()
	var arr []any
	if err := msgpack.Unmarshal(raw, &arr); err != nil {
		t.Fatalf("decode array: %v", err)
	}
	return arr
}
