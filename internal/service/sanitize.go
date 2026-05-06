package service

import "strings"

// sanitizeForward strips byte values that would let a sender execute
// terminal-control tricks on receiving CLI clients via the forwarded
// body. SPEC §5.3 says LXMF content is opaque bytes — but in practice
// most clients render it on a TTY where C0 controls (BEL, BS, ESC, NUL)
// and the CSI introducer can clear lines, move the cursor, or
// impersonate other senders' output.
//
// Policy:
//   - Keep printable bytes (>= 0x20).
//   - Keep TAB (0x09), LF (0x0A), CR (0x0D) — common in legitimate
//     multi-line content.
//   - Replace every other C0 control (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F)
//     and DEL (0x7F) with '?'. ESC (0x1B) is in this range, so the
//     CSI sequence "\x1B[" can never reach a receiving terminal.
//
// Per-byte (not per-rune) so multi-byte UTF-8 sequences pass through
// unchanged. Replacement is single-byte to keep length predictable for
// the downstream wire-fit guard.
func sanitizeForward(s string) string {
	if !needsSanitize(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func needsSanitize(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
		if c == 0x7F {
			return true
		}
	}
	return false
}
