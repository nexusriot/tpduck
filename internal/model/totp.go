package model

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"
)

// normalizeBase32 strips the separators providers like to show secrets with
// (spaces, tabs, dashes) and upper-cases the result. It deliberately does not
// add "=" padding: decodeBase32 decodes without padding, so storing it would
// only put noise in the vault file.
func normalizeBase32(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', '-', '_':
			continue
		case '=':
			continue
		}
		if r >= 'a' && r <= 'z' {
			r -= 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

func decodeBase32(s string) ([]byte, error) {
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	return dec.DecodeString(normalizeBase32(s))
}

func Hotp(secret []byte, counter uint64, algo Algo) (uint32, error) {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	var mac hash.Hash
	switch algo {
	case AlgoSHA1:
		mac = hmac.New(sha1.New, secret)
	case AlgoSHA256:
		mac = hmac.New(sha256.New, secret)
	case AlgoSHA512:
		mac = hmac.New(sha512.New, secret)
	default:
		return 0, fmt.Errorf("unsupported algo: %s", algo)
	}
	mac.Write(msg)
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0F)
	if offset+4 > len(sum) {
		return 0, errors.New("bad hmac length")
	}
	p := (uint32(sum[offset])&0x7F)<<24 |
		(uint32(sum[offset+1])&0xFF)<<16 |
		(uint32(sum[offset+2])&0xFF)<<8 |
		(uint32(sum[offset+3]) & 0xFF)
	return p, nil
}

// Totp returns (code, secondsRemaining, error)
func Totp(secretB32 string, algo Algo, period, digits int, t time.Time) (string, int, error) {
	raw, remain, err := totpRaw(secretB32, algo, period, t)
	if err != nil {
		return "", 0, err
	}
	if digits != 6 && digits != 8 {
		digits = DefaultDigits
	}
	return truncateCode(raw, digits), remain, nil
}

// totpRaw returns the 31-bit dynamic-truncation value and the seconds left in
// the window, before it is rendered as digits or as Steam's alphabet.
func totpRaw(secretB32 string, algo Algo, period int, t time.Time) (uint32, int, error) {
	if period <= 0 {
		period = DefaultPeriod
	}
	sec := t.Unix()
	counter := uint64(sec / int64(period))
	remain := int(period - int(sec%int64(period)))

	key, err := decodeBase32(secretB32)
	if err != nil {
		return 0, 0, fmt.Errorf("secret decode: %w", err)
	}
	if len(key) == 0 {
		return 0, 0, errEmptySecret
	}
	raw, err := Hotp(key, counter, algo)
	if err != nil {
		return 0, 0, err
	}
	return raw, remain, nil
}

// errEmptySecret is shared by the TOTP and HOTP paths.
var errEmptySecret = errors.New("secret is empty")

// truncateCode reduces the 31-bit dynamic-truncation value to the requested
// number of decimal digits, zero-padded.
func truncateCode(raw uint32, digits int) string {
	if digits != 6 && digits != 8 {
		digits = DefaultDigits
	}
	return fmt.Sprintf("%0*d", digits, raw%uint32(math.Pow10(digits)))
}

// ValidateSecret reports whether b32 decodes to a usable HMAC key. An empty
// secret is rejected: HMAC accepts a zero-length key and would otherwise
// produce plausible-looking codes that no server will ever accept.
func ValidateSecret(b32 string) error {
	key, err := decodeBase32(b32)
	if err != nil {
		return err
	}
	if len(key) == 0 {
		return errEmptySecret
	}
	return nil
}

func NormalizeSecret(b32 string) string { return normalizeBase32(b32) }
