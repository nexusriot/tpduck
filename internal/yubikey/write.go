package yubikey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	insPut    = 0x01
	insDelete = 0x02
	insSetPwd = 0x03
	insReset  = 0x04
	insRename = 0x05
)

const (
	tagKey           = 0x73
	tagProperty      = 0x78
	tagIMF           = 0x7A
	propRequireTouch = 0x02
)

// algoByte packs the type and algorithm the way the applet stores them.
func algoByte(typ Type, algo string) (byte, error) {
	var t byte
	switch typ {
	case TypeHOTP:
		t = 0x10
	case TypeTOTP:
		t = 0x20
	default:
		return 0, fmt.Errorf("unsupported credential type %q", typ)
	}
	var a byte
	switch strings.ToUpper(algo) {
	case "", "SHA1":
		a = 0x01
	case "SHA256":
		a = 0x02
	case "SHA512":
		a = 0x03
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", algo)
	}
	return t | a, nil
}

// CredentialName builds the name the applet stores, "[period/][issuer:]account".
// A non-default period has to be in the name because the applet has nowhere
// else to keep it.
func CredentialName(issuer, account string, period int, typ Type) string {
	var b strings.Builder
	if typ == TypeTOTP && period > 0 && period != 30 {
		fmt.Fprintf(&b, "%d/", period)
	}
	if issuer != "" {
		b.WriteString(issuer)
		b.WriteByte(':')
	}
	b.WriteString(account)
	return b.String()
}

// PutOptions describes a credential to store on the key.
type PutOptions struct {
	Name    string
	Secret  string // Base32
	Type    Type
	Algo    string
	Digits  int
	Counter uint64 // HOTP only
	Touch   bool
}

// Put writes a credential to the key. The secret is sent once and then lives
// only on the key; nothing is written to disk.
func (s *Session) Put(o PutOptions) error {
	if strings.TrimSpace(o.Name) == "" {
		return errors.New("credential name is required")
	}
	// The applet stores names in a fixed-size slot.
	if len(o.Name) > 64 {
		return fmt.Errorf("credential name is %d bytes; the key allows 64", len(o.Name))
	}
	if o.Digits != 6 && o.Digits != 8 {
		return fmt.Errorf("digits must be 6 or 8, got %d", o.Digits)
	}
	ab, err := algoByte(o.Type, o.Algo)
	if err != nil {
		return err
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(o.Secret)))
	if err != nil {
		return fmt.Errorf("decode secret: %w", err)
	}
	if len(key) == 0 {
		return errors.New("secret is empty")
	}
	// The applet expects at least 14 bytes of key material and pads shorter
	// secrets itself in ykman; do the same so short secrets are accepted.
	if len(key) < 14 {
		padded := make([]byte, 14)
		copy(padded, key)
		key = padded
	}

	data := tlv(tagName, []byte(o.Name))
	data = append(data, tlv(tagKey, append([]byte{ab, byte(o.Digits)}, key...))...)
	if o.Touch {
		data = append(data, tlv(tagProperty, []byte{propRequireTouch})...)
	}
	if o.Type == TypeHOTP && o.Counter > 0 {
		imf := []byte{
			byte(o.Counter >> 24), byte(o.Counter >> 16),
			byte(o.Counter >> 8), byte(o.Counter),
		}
		data = append(data, tlv(tagIMF, imf)...)
	}
	_, err = s.send(0x00, insPut, 0x00, 0x00, data)
	return err
}

// Delete removes a credential from the key. This is irreversible: the key
// holds the only copy of the secret.
func (s *Session) Delete(name string) error {
	_, err := s.send(0x00, insDelete, 0x00, 0x00, tlv(tagName, []byte(name)))
	return err
}

// Rename changes a credential's name, and so its issuer, account or period.
func (s *Session) Rename(from, to string) error {
	if strings.TrimSpace(to) == "" {
		return errors.New("new name is required")
	}
	data := append(tlv(tagName, []byte(from)), tlv(tagName, []byte(to))...)
	_, err := s.send(0x00, insRename, 0x00, 0x00, data)
	return err
}

// --- the applet password ----------------------------------------------------

// accessKeyAlgo is the algorithm byte the applet stores an access key under:
// the TOTP type marker plus HMAC-SHA1, which is what the key derivation above
// produces and the only combination the applet accepts for a password.
const accessKeyAlgo = 0x21 // 0x20 TOTP | 0x01 HMAC-SHA1

// SetPassword protects the OATH applet with a password, so the credentials on
// the key cannot be read by anyone who merely has the key in their hand.
//
// The password is never sent: what goes to the applet is the derived access
// key, plus a challenge and our HMAC over it, which proves we can compute the
// responses it will ask for later.
func (s *Session) SetPassword(password string) error {
	if password == "" {
		return errors.New("password is empty (use RemovePassword to take it off)")
	}
	if len(s.deviceID) == 0 {
		return errors.New("key did not report a device id")
	}
	access := deriveAccessKey(password, s.deviceID)

	challenge := make([]byte, 8)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	mac := hmac.New(sha1.New, access)
	mac.Write(challenge)

	data := tlv(tagKey, append([]byte{accessKeyAlgo}, access...))
	data = append(data, tlv(tagChallenge, challenge)...)
	data = append(data, tlv(tagResponse, mac.Sum(nil))...)
	_, err := s.send(0x00, insSetPwd, 0x00, 0x00, data)
	return err
}

// RemovePassword takes the password off the applet, which is an empty key TLV
// and nothing else. The applet must already be unlocked.
func (s *Session) RemovePassword() error {
	_, err := s.send(0x00, insSetPwd, 0x00, 0x00, tlv(tagKey, nil))
	return err
}

// Reset wipes the OATH applet: every credential and the password. There is no
// undo and the key holds the only copy of each secret, so callers must have
// asked first.
func (s *Session) Reset() error {
	_, err := s.send(0x00, insReset, 0xDE, 0xAD, nil)
	if err != nil {
		return err
	}
	// Whatever we were authenticated against is gone.
	s.challenge, s.unlocked = nil, false
	return nil
}

// --- password-protected applets --------------------------------------------

// deriveAccessKey turns a password into the applet's access key, salted with
// the key's own device identifier. The parameters are fixed by the applet.
func deriveAccessKey(password string, deviceID []byte) []byte {
	return pbkdf2.Key([]byte(password), deviceID, 1000, 16, sha1.New)
}

// Unlock authenticates against a password-protected applet.
//
// The applet sends a challenge when it is locked; the response is an HMAC-SHA1
// of that challenge under a key derived from the password and the device id.
// Without this, a key with a password set cannot be read at all.
func (s *Session) Unlock(password string) error {
	if len(s.challenge) == 0 {
		return errors.New("this key is not password-protected")
	}
	if len(s.deviceID) == 0 {
		return errors.New("key did not report a device id")
	}
	access := deriveAccessKey(password, s.deviceID)

	mac := hmac.New(sha1.New, access)
	mac.Write(s.challenge)
	response := mac.Sum(nil)

	// The applet verifies our response and proves itself with ours in return.
	ourChallenge := make([]byte, 8)
	if _, err := rand.Read(ourChallenge); err != nil {
		return err
	}
	data := append(tlv(tagResponse, response), tlv(tagChallenge, ourChallenge)...)
	resp, err := s.send(0x00, insValidate, 0x00, 0x00, data)
	if err != nil {
		return err
	}
	// Verify the key's counter-response, so a hostile reader cannot pose as
	// the key and convince us it accepted an arbitrary password.
	expect := hmac.New(sha1.New, access)
	expect.Write(ourChallenge)
	want := expect.Sum(nil)
	for _, t := range parseTLVs(resp) {
		if t.tag == tagResponse {
			if !hmac.Equal(t.value, want) {
				return errors.New("key failed to prove it knows the password")
			}
			s.unlocked = true
			return nil
		}
	}
	return errors.New("key did not answer the mutual challenge")
}

// NeedsPassword reports whether the applet asked for authentication.
func (s *Session) NeedsPassword() bool { return len(s.challenge) > 0 && !s.unlocked }
