// Package yubikey speaks the YubiKey OATH applet protocol (YKOATH).
//
// Credentials stored on the key never leave it: the host sends a challenge and
// the key returns a truncated HMAC, so the secret is not on disk anywhere.
//
// The protocol is implemented against a Transport so it can be exercised
// without hardware. The PC/SC transport that talks to a real key lives in
// transport_pcsc.go and is behind the "pcsc" build tag, because it needs cgo
// and libpcsclite; the default build stays pure Go and cross-compilable.
package yubikey

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Transport carries APDUs to a card and returns the response, including the
// two status bytes.
type Transport interface {
	Transmit([]byte) ([]byte, error)
	Close() error
}

// AID is the YubiKey OATH applet identifier.
var AID = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}

const (
	insSelect        = 0xA4
	insList          = 0xA1
	insCalculate     = 0xA2
	insValidate      = 0xA3
	insCalculateAll  = 0xA4
	insSendRemaining = 0xA5
)

const (
	tagName      = 0x71
	tagNameList  = 0x72
	tagChallenge = 0x74
	tagResponse  = 0x75
	tagTruncated = 0x76
	tagHOTP      = 0x77
	tagVersion   = 0x79
	tagTouch     = 0x7C
)

const (
	swSuccess        = 0x9000
	swMoreData       = 0x6100 // low byte is the remaining length
	swAuthRequired   = 0x6982
	swNoSuchObject   = 0x6984
	swWrongSyntax    = 0x6A80
	swGenericError   = 0x6581
	swNotFound       = 0x6A82
	swTouchTimeout   = 0x6985
	swWrongSignature = 0x6300
)

// ErrAuthRequired means the OATH applet is protected by a password that must
// be validated before credentials can be read.
var ErrAuthRequired = errors.New("yubikey OATH applet is password-protected")

// ErrTouchRequired means the credential is configured to need a physical touch.
var ErrTouchRequired = errors.New("credential requires touching the key")

// Type distinguishes the two OATH credential kinds a key can hold.
type Type string

const (
	TypeTOTP Type = "totp"
	TypeHOTP Type = "hotp"
)

// Credential is one entry stored on the key.
type Credential struct {
	// Name is the raw credential name as the key stores it, e.g.
	// "30/GitHub:alice". It is what Calculate must be given.
	Name   string
	Issuer string
	// Account is the name with the issuer and period prefixes removed.
	Account string
	Type    Type
	Algo    string
	Period  int
	// Touch is set when the key will only answer after a physical touch. The
	// applet's LIST response does not carry this bit, so it is populated by
	// CalculateAll and left false by List.
	Touch bool
}

// Label renders a credential the way a person refers to it.
func (c Credential) Label() string {
	if c.Issuer == "" {
		return c.Account
	}
	return c.Issuer + ":" + c.Account
}

// Session is an opened conversation with the OATH applet.
type Session struct {
	t       Transport
	Version string
	// DeviceID identifies the key; it is the salt for a password-protected
	// applet's access key.
	deviceID []byte
	// challenge is sent by a locked applet and is non-empty until Unlock runs.
	challenge []byte
	unlocked  bool
}

// DeviceID returns the key's identifier, as reported when the applet was
// selected.
func (s *Session) DeviceID() []byte { return s.deviceID }

// Open selects the OATH applet on the card behind t.
func Open(t Transport) (*Session, error) {
	s := &Session{t: t}
	resp, err := s.send(0x00, insSelect, 0x04, 0x00, AID)
	if err != nil {
		return nil, fmt.Errorf("select OATH applet: %w", err)
	}
	for _, item := range parseTLVs(resp) {
		switch item.tag {
		case tagVersion:
			if len(item.value) >= 3 {
				s.Version = fmt.Sprintf("%d.%d.%d", item.value[0], item.value[1], item.value[2])
			}
		case tagName:
			s.deviceID = append([]byte(nil), item.value...)
		case tagChallenge:
			// Present only when the applet is password-protected.
			s.challenge = append([]byte(nil), item.value...)
		}
	}
	return s, nil
}

// Close releases the transport.
func (s *Session) Close() error {
	if s == nil || s.t == nil {
		return nil
	}
	return s.t.Close()
}

// List returns the credentials stored on the key. Secrets are never returned;
// they cannot leave the key.
func (s *Session) List() ([]Credential, error) {
	resp, err := s.send(0x00, insList, 0x00, 0x00, nil)
	if err != nil {
		return nil, err
	}
	var out []Credential
	for _, tlv := range parseTLVs(resp) {
		if tlv.tag != tagNameList || len(tlv.value) < 1 {
			continue
		}
		c := parseName(string(tlv.value[1:]))
		c.Type, c.Algo = decodeAlgoByte(tlv.value[0])
		out = append(out, c)
	}
	return out, nil
}

// Calculate asks the key for the current code of one credential. `name` is the
// raw Credential.Name.
func (s *Session) Calculate(name string, digits int, at time.Time, period int) (string, error) {
	if period <= 0 {
		period = 30
	}
	data := append(tlv(tagName, []byte(name)), tlv(tagChallenge, challenge(at, period))...)
	resp, err := s.send(0x00, insCalculate, 0x00, 0x01 /* truncate */, data)
	if err != nil {
		return "", err
	}
	for _, t := range parseTLVs(resp) {
		switch t.tag {
		case tagTruncated, tagResponse, tagHOTP:
			return formatTruncated(t.value, digits)
		case tagTouch:
			return "", ErrTouchRequired
		}
	}
	return "", errors.New("key returned no code")
}

// CalculateAll returns a code for every TOTP credential in one round trip.
// Credentials needing a touch are reported with Touch set and no code.
func (s *Session) CalculateAll(at time.Time) (map[string]string, []Credential, error) {
	resp, err := s.send(0x00, insCalculateAll, 0x00, 0x01, tlv(tagChallenge, challenge(at, 30)))
	if err != nil {
		return nil, nil, err
	}
	codes := map[string]string{}
	var creds []Credential
	var cur *Credential
	for _, t := range parseTLVs(resp) {
		switch t.tag {
		case tagName:
			c := parseName(string(t.value))
			creds = append(creds, c)
			cur = &creds[len(creds)-1]
		case tagTruncated, tagResponse:
			if cur == nil {
				continue
			}
			cur.Type = TypeTOTP
			code, err := formatTruncated(t.value, 0)
			if err != nil {
				return nil, nil, err
			}
			codes[cur.Name] = code
		case tagHOTP:
			if cur != nil {
				cur.Type = TypeHOTP
			}
		case tagTouch:
			if cur != nil {
				cur.Touch = true
			}
		}
	}
	return codes, creds, nil
}

// Validate sends a raw VALIDATE. Prefer Unlock, which derives the response
// from a password and checks the key's counter-response.
func (s *Session) Validate(response, challengeValue []byte) error {
	data := append(tlv(tagResponse, response), tlv(tagChallenge, challengeValue)...)
	_, err := s.send(0x00, insValidate, 0x00, 0x00, data)
	return err
}

// --- wire helpers ---

// send transmits one APDU and reassembles a response split across 61xx
// continuations.
func (s *Session) send(cla, ins, p1, p2 byte, data []byte) ([]byte, error) {
	apdu := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		if len(data) > 255 {
			return nil, fmt.Errorf("apdu payload too long (%d bytes)", len(data))
		}
		apdu = append(apdu, byte(len(data)))
		apdu = append(apdu, data...)
	}
	var out []byte
	for {
		resp, err := s.t.Transmit(apdu)
		if err != nil {
			return nil, err
		}
		if len(resp) < 2 {
			return nil, errors.New("short response from card")
		}
		body, sw := resp[:len(resp)-2], binary.BigEndian.Uint16(resp[len(resp)-2:])
		out = append(out, body...)
		switch {
		case sw == swSuccess:
			return out, nil
		case sw&0xFF00 == swMoreData:
			apdu = []byte{0x00, insSendRemaining, 0x00, 0x00}
			continue
		default:
			return nil, statusError(sw)
		}
	}
}

func statusError(sw uint16) error {
	switch sw {
	case swAuthRequired:
		return ErrAuthRequired
	case swTouchTimeout:
		return ErrTouchRequired
	case swNoSuchObject, swNotFound:
		return errors.New("no such credential on the key")
	case swWrongSyntax:
		return errors.New("key rejected the request (wrong syntax)")
	case swWrongSignature:
		return errors.New("key rejected the password")
	case swGenericError:
		return errors.New("key reported a generic error")
	default:
		return fmt.Errorf("card returned status 0x%04X", sw)
	}
}

type tlvItem struct {
	tag   byte
	value []byte
}

func tlv(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

// parseTLVs decodes a BER-style TLV sequence, stopping at the first malformed
// item rather than guessing.
func parseTLVs(b []byte) []tlvItem {
	var out []tlvItem
	for len(b) >= 2 {
		tag := b[0]
		n := int(b[1])
		rest := b[2:]
		switch b[1] {
		case 0x81:
			if len(b) < 3 {
				return out
			}
			n, rest = int(b[2]), b[3:]
		case 0x82:
			if len(b) < 4 {
				return out
			}
			n, rest = int(b[2])<<8|int(b[3]), b[4:]
		}
		if n > len(rest) {
			return out
		}
		out = append(out, tlvItem{tag: tag, value: rest[:n]})
		b = rest[n:]
	}
	return out
}

func challenge(at time.Time, period int) []byte {
	if period <= 0 {
		period = 30
	}
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, uint64(at.Unix()/int64(period)))
	return c
}

// formatTruncated turns the key's [digits][4 bytes] answer into a code. When
// digits is 0 the key's own digit count is used.
func formatTruncated(v []byte, digits int) (string, error) {
	if len(v) < 5 {
		return "", fmt.Errorf("truncated response is %d bytes, want 5", len(v))
	}
	if digits <= 0 {
		digits = int(v[0])
	}
	if digits != 6 && digits != 8 {
		return "", fmt.Errorf("key reported %d digits", digits)
	}
	raw := binary.BigEndian.Uint32(v[1:5]) & 0x7FFFFFFF
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, raw%mod), nil
}

// decodeAlgoByte splits the type/algorithm byte the key prefixes names with.
func decodeAlgoByte(b byte) (Type, string) {
	typ := TypeTOTP
	if b&0xF0 == 0x10 {
		typ = TypeHOTP
	}
	algo := "SHA1"
	switch b & 0x0F {
	case 0x02:
		algo = "SHA256"
	case 0x03:
		algo = "SHA512"
	}
	return typ, algo
}

// parseName splits the key's credential naming convention,
// "[period/][issuer:]account".
func parseName(raw string) Credential {
	c := Credential{Name: raw, Account: raw, Period: 30}
	rest := raw
	if slash := strings.Index(rest, "/"); slash > 0 {
		if n, err := strconv.Atoi(rest[:slash]); err == nil && n > 0 {
			c.Period = n
			rest = rest[slash+1:]
		}
	}
	if colon := strings.Index(rest, ":"); colon >= 0 {
		c.Issuer, c.Account = rest[:colon], rest[colon+1:]
	} else {
		c.Account = rest
	}
	return c
}
