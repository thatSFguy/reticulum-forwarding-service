package service

import (
	"encoding/hex"
)

// forwardToRoster fans the body out to every ACTIVE (non-paused) roster
// member except the sender. Each Send drops silently with a log entry
// if the recipient hasn't announced yet (we can't encrypt to an unknown
// public key) or if a link delivery fails. Returns the count of
// recipients we successfully delivered to.
//
// Delivery.Send routes opportunistic vs link automatically — large
// bodies that overflow the opportunistic single-packet cap fall through
// to a per-recipient Reticulum Link send, which blocks for the
// responder's ack. With a large roster + large body, this loop is
// SERIAL and slow (PR3 will parallelize). Acceptable for now since the
// dominant case is short messages routing to opportunistic.
func (s *Service) forwardToRoster(senderHex, body string) int {
	hashes := s.roster.ActiveHashes()
	delivered := 0
	for _, h := range hashes {
		if h == senderHex {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			continue
		}
		if err := s.delivery.Send(raw, nil, []byte(body), nil); err != nil {
			s.logger.Printf("forward to %s: %v", h[:8], err)
			continue
		}
		delivered++
	}
	return delivered
}
