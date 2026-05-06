package service

import (
	"encoding/hex"
	"errors"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
)

// forwardToRoster fans the body out to every roster member except the
// sender. Each Send drops silently with a log entry if the recipient
// hasn't announced yet (we can't encrypt to an unknown public key).
// Returns the count of recipients we successfully queued sends for, plus
// the first lxmf.ErrPayloadTooLarge encountered (since that error is the
// same for every recipient — the body is identical — surfacing it lets
// the caller reply to the original sender once).
func (s *Service) forwardToRoster(senderHex, body string) (int, error) {
	hashes := s.roster.Hashes()
	delivered := 0
	var sizeErr error
	for _, h := range hashes {
		if h == senderHex {
			continue
		}
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != 16 {
			continue
		}
		if err := s.delivery.Send(raw, nil, []byte(body), nil); err != nil {
			if errors.Is(err, lxmf.ErrPayloadTooLarge) {
				// Identical body fails identically for everyone — abort
				// and let the caller reply to the sender.
				sizeErr = err
				break
			}
			s.logger.Printf("forward to %s: %v", h[:8], err)
			continue
		}
		delivered++
	}
	return delivered, sizeErr
}
