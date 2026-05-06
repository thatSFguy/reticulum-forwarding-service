package rns

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
)

// Link-form Token cipher (SPEC §3.1). Same authenticated AES-256-CBC +
// HMAC-SHA256 envelope as opportunistic Token, but the session keys are
// already derived from the link handshake (§6.4) so the wire form omits
// the ephemeral X25519 public key prefix:
//
//	IV(16) || AES-256-CBC ciphertext(N*16) || HMAC-SHA256(32)
//
// Encrypt-then-MAC; verify HMAC before decrypting (defends against
// padding-oracle attacks). The signing/encryption keys come from
// DeriveLinkSessionKeys.
const (
	linkTokenOverhead = tokenIVLen + tokenHMACLen // IV + HMAC; ciphertext is variable
)

// LinkTokenEncrypt encrypts plaintext under the given link session keys.
// Both `signing` and `encryption` must be 32 bytes (the halves returned
// by DeriveLinkSessionKeys).
func LinkTokenEncrypt(plaintext, signing, encryption []byte) ([]byte, error) {
	if len(signing) != tokenHMACKeyLen {
		return nil, fmt.Errorf("signing key must be %d bytes", tokenHMACKeyLen)
	}
	if len(encryption) != tokenAESKeyLen {
		return nil, fmt.Errorf("encryption key must be %d bytes", tokenAESKeyLen)
	}
	iv := make([]byte, tokenIVLen)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("IV randomness: %w", err)
	}
	return linkTokenEncryptWithIV(plaintext, signing, encryption, iv)
}

// linkTokenEncryptWithIV is the testable form: deterministic IV input.
func linkTokenEncryptWithIV(plaintext, signing, encryption, iv []byte) ([]byte, error) {
	if len(iv) != tokenIVLen {
		return nil, fmt.Errorf("IV must be %d bytes", tokenIVLen)
	}
	ciphertext, err := aesCBCEncrypt(encryption, iv, plaintext)
	if err != nil {
		return nil, err
	}
	mac := hmacSHA256(signing, iv, ciphertext)

	out := make([]byte, 0, linkTokenOverhead+len(ciphertext))
	out = append(out, iv...)
	out = append(out, ciphertext...)
	out = append(out, mac...)
	return out, nil
}

// LinkTokenDecrypt verifies the HMAC and AES-CBC-decrypts a link-form
// Token ciphertext.
func LinkTokenDecrypt(wire, signing, encryption []byte) ([]byte, error) {
	if len(signing) != tokenHMACKeyLen {
		return nil, fmt.Errorf("signing key must be %d bytes", tokenHMACKeyLen)
	}
	if len(encryption) != tokenAESKeyLen {
		return nil, fmt.Errorf("encryption key must be %d bytes", tokenAESKeyLen)
	}
	if len(wire) < linkTokenOverhead+aes.BlockSize {
		return nil, fmt.Errorf("link token too short: %d bytes (need >= %d)", len(wire), linkTokenOverhead+aes.BlockSize)
	}
	if (len(wire)-linkTokenOverhead)%aes.BlockSize != 0 {
		return nil, errors.New("link token ciphertext not block-aligned")
	}

	iv := wire[:tokenIVLen]
	mac := wire[len(wire)-tokenHMACLen:]
	ciphertext := wire[tokenIVLen : len(wire)-tokenHMACLen]

	expectedMAC := hmacSHA256(signing, iv, ciphertext)
	if !hmac.Equal(mac, expectedMAC) {
		return nil, errors.New("link token HMAC mismatch")
	}
	plaintext, err := aesCBCDecrypt(encryption, iv, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// stretch ensures cipher.Stream constructors don't get optimized out (Go
// linker hint: keep aes import alive when only used inside helpers).
var _ = cipher.Stream(nil)
