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
	"math"
	"strings"
	"time"
)

func normalizeBase32(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if r := len(s) % 8; r != 0 {
		s += strings.Repeat("=", 8-r)
	}
	return s
}

func decodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	dec := base32.StdEncoding.WithPadding(base32.NoPadding)
	return dec.DecodeString(strings.TrimRight(s, "="))
}

func Hotp(secret []byte, counter uint64, algo Algo) (uint32, error) {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint64(msg, counter)

	var mac hashLike
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

type hashLike interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// Totp returns (code, secondsRemaining, error)
func Totp(secretB32 string, algo Algo, period, digits int, t time.Time) (string, int, error) {
	if period <= 0 {
		period = 30
	}
	if digits != 6 && digits != 8 {
		digits = 6
	}
	sec := t.Unix()
	counter := uint64(sec / int64(period))
	remain := int(period - int(sec%int64(period)))

	key, err := decodeBase32(secretB32)
	if err != nil {
		return "", 0, fmt.Errorf("secret decode: %w", err)
	}
	code31, err := Hotp(key, counter, algo)
	if err != nil {
		return "", 0, err
	}
	mod := uint32(math.Pow10(digits))
	code := code31 % mod
	return fmt.Sprintf("%0*d", digits, code), remain, nil
}

func ValidateSecret(b32 string) error {
	_, err := decodeBase32(normalizeBase32(b32))
	return err
}

func NormalizeSecret(b32 string) string { return normalizeBase32(b32) }
