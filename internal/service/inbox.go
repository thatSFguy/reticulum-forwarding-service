package service

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/thatSFguy/reticulum-forwarding-service/internal/commands"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/history"
	"github.com/thatSFguy/reticulum-forwarding-service/internal/lxmf"
)

// onLXMFReceived is the lxmf.Delivery callback for verified inbound
// messages. Banlist drops happen here (post-verify so banned users still
// can't impersonate someone else), then commands route to the dispatcher
// and ordinary messages forward to the roster + append to history.
func (s *Service) onLXMFReceived(msg *lxmf.Message) {
	now := s.now()
	senderBytes := msg.SourceHash
	senderHex := hex.EncodeToString(senderBytes)

	if s.roster.IsBanned(senderBytes) {
		s.logger.Printf("dropping banned sender %s", senderHex[:8])
		return
	}

	content := strings.TrimRight(string(msg.Content), "\r\n")

	// Spam-prevention character limit (separate from wire-format size).
	// Commands aren't subject to it (they're short and bounded).
	if !commands.IsCommand(content) && s.cfg.Service.MaxInboundChars > 0 {
		if charCount := utf8.RuneCountInString(content); charCount > s.cfg.Service.MaxInboundChars {
			s.replyOverInboundLimit(senderBytes, charCount)
			return
		}
	}

	if commands.IsCommand(content) {
		parsed := commands.Parse(content)
		reply := s.dispatcher.Dispatch(senderHex, parsed)
		if reply != "" {
			if err := s.delivery.Send(senderBytes, nil, []byte(reply), nil); err != nil {
				s.logger.Printf("command reply send: %v", err)
			}
		}
		return
	}

	isNewOrReturning, err := s.roster.AddOrUpdate(senderBytes, now)
	if err != nil {
		s.logger.Printf("roster update: %v", err)
		return
	}

	if isNewOrReturning && s.cfg.Replay.Count > 0 {
		go s.replayHistoryTo(senderBytes, now)
	}

	senderUser, _ := s.roster.Get(senderHex)
	senderNick := senderUser.Nickname
	if senderNick == "" {
		senderNick = senderHex[:8]
	}

	body := "[" + senderNick + "] " + content

	// Pre-check that the prefixed body will fit in a single opportunistic
	// LXMF packet. If not, reply to the sender so they know their message
	// wasn't relayed (rather than silently dropping it). The check here
	// avoids iterating the whole roster just to fail identically every time.
	if err := lxmf.CheckOpportunisticSize(nil, []byte(body), nil); err != nil {
		if errors.Is(err, lxmf.ErrPayloadTooLarge) {
			s.replyTooLarge(senderBytes, len(content), len(senderNick))
			return
		}
		s.logger.Printf("size check: %v", err)
		return
	}

	delivered, sizeErr := s.forwardToRoster(senderHex, body)
	if sizeErr != nil {
		// Defensive: pre-check passed but a per-recipient send still saw
		// ErrPayloadTooLarge. Shouldn't happen given the body is identical,
		// but if a future change makes Send size-sensitive per recipient,
		// the user still gets feedback.
		s.replyTooLarge(senderBytes, len(content), len(senderNick))
		return
	}

	if delivered > 0 {
		_ = s.history.Append(history.Entry{
			At:         now,
			SenderHash: senderHex,
			SenderNick: senderNick,
			Content:    content,
		})
	}
}

// replyTooLarge sends a short error message back to the original sender
// telling them their message wasn't forwarded because, after the
// "[nick] " prefix was added, the forwarded packet wouldn't fit in a
// single-packet opportunistic LXMF body. Includes the approximate
// content budget they have so they can trim accordingly.
//
// Distinct from replyOverInboundLimit, which fires earlier on the
// configured spam-prevention character cap.
func (s *Service) replyTooLarge(senderBytes []byte, contentLen, nickLen int) {
	prefixOverhead := nickLen + 3 // "[" + nick + "] "
	// MaxOpportunisticPayload (295) - 16 (msgpack overhead with empty title +
	// empty fields, bin16 content prefix to be safe) - prefixOverhead.
	budget := lxmf.MaxOpportunisticPayload - 16 - prefixOverhead
	if budget < 0 {
		budget = 0
	}
	msg := fmt.Sprintf("Message not forwarded: with the [nick] prefix it exceeds the single-packet relay limit. "+
		"Try shortening to about %d bytes of content.", budget)
	if err := s.delivery.Send(senderBytes, nil, []byte(msg), nil); err != nil {
		s.logger.Printf("too-large notify send: %v", err)
	}
}

// replyOverInboundLimit notifies a sender that their message exceeded
// the configured per-message character cap (service.max_inbound_chars).
// The message is dropped — not forwarded, not added to history, and
// the sender is not joined to the roster on the strength of an
// oversized first message.
func (s *Service) replyOverInboundLimit(senderBytes []byte, charCount int) {
	limit := s.cfg.Service.MaxInboundChars
	msg := fmt.Sprintf("Message rejected: limit is %d characters per message, yours was %d. Please shorten and resend.",
		limit, charCount)
	if err := s.delivery.Send(senderBytes, nil, []byte(msg), nil); err != nil {
		s.logger.Printf("inbound-limit notify send: %v", err)
	}
}
