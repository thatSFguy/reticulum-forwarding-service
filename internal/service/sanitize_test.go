package service

import "testing"

func TestSanitizeForwardKeepsPrintable(t *testing.T) {
	in := "Hello, world! Émoji: \U0001F600 — and €"
	if got := sanitizeForward(in); got != in {
		t.Errorf("printable text mutated\n got %q\nwant %q", got, in)
	}
}

func TestSanitizeForwardKeepsCommonWhitespace(t *testing.T) {
	in := "line one\nline two\twith tab\r\nand windows newline"
	if got := sanitizeForward(in); got != in {
		t.Errorf("whitespace mutated\n got %q\nwant %q", got, in)
	}
}

func TestSanitizeForwardStripsAnsiCSI(t *testing.T) {
	// "\x1B[2J" is "clear screen" — would let a sender wipe the receiver's
	// terminal display. Both ESC and CSI introducer must be neutered.
	in := "before\x1B[2Jafter"
	got := sanitizeForward(in)
	if got == in {
		t.Errorf("CSI sequence not sanitized: %q", got)
	}
	for _, c := range []byte(got) {
		if c == 0x1B {
			t.Errorf("ESC byte still present: %q", got)
		}
	}
}

func TestSanitizeForwardStripsBell(t *testing.T) {
	in := "wake up\x07"
	got := sanitizeForward(in)
	if got == in || len(got) != len(in) {
		t.Errorf("BEL not replaced 1:1: %q", got)
	}
}

func TestSanitizeForwardLeavesUTF8Continuations(t *testing.T) {
	// Multi-byte UTF-8 has continuation bytes 0x80-0xBF — those must
	// pass through unchanged or we'd corrupt every emoji and
	// non-ASCII character.
	in := "\xE2\x82\xAC\xF0\x9F\x98\x80" // "€😀" as raw UTF-8
	got := sanitizeForward(in)
	if got != in {
		t.Errorf("UTF-8 continuation bytes mutated: got %x, want %x", got, in)
	}
}

func TestSanitizeForwardStripsDEL(t *testing.T) {
	in := "abc\x7Fdef"
	got := sanitizeForward(in)
	if got != "abc?def" {
		t.Errorf("DEL not replaced: got %q", got)
	}
}
