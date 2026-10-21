package yubikey

import (
	"errors"
	"fmt"
)

// The OTP applet is a different applet from OATH, with its own AID. It is the
// one that answers HMAC-SHA1 challenge-response, which is what lets a YubiKey
// stand in for -- or stand alongside -- a vault passphrase: the slot's secret
// never leaves the key, so the vault cannot be opened by copying a file.
//
// This is the same protocol `ykchalresp` speaks and the one KeePassXC uses
// over PC/SC. The slot must already be programmed for HMAC-SHA1
// challenge-response; tpduck deliberately cannot program it, because writing a
// slot is destructive and belongs to ykman.
var otpAID = []byte{0xA0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}

const (
	// insAPIRequest is the OTP applet's single "do a thing" instruction; P1
	// selects which thing.
	insAPIRequest = 0x01

	// p1ChalHMAC1 and p1ChalHMAC2 ask slot 1 or slot 2 for HMAC-SHA1 over the
	// challenge.
	p1ChalHMAC1 = 0x30
	p1ChalHMAC2 = 0x38

	// ResponseLen is the length of an HMAC-SHA1 challenge response.
	ResponseLen = 20

	// MaxChallengeLen is what the applet accepts in one APDU. A slot
	// programmed for fixed 64-byte input pads anything shorter itself, which
	// is still deterministic because tpduck always sends the same challenge.
	MaxChallengeLen = 64
)

// ErrSlotEmpty means the slot is not programmed for challenge-response.
var ErrSlotEmpty = errors.New("this YubiKey slot is not programmed for HMAC-SHA1 challenge-response (set one up with: ykman otp chalresp --touch <slot>)")

// OTPSession is an opened conversation with the OTP applet.
type OTPSession struct {
	t Transport
}

// OpenOTP selects the OTP applet on the card behind t.
func OpenOTP(t Transport) (*OTPSession, error) {
	s := &Session{t: t}
	if _, err := s.send(0x00, insSelect, 0x04, 0x00, otpAID); err != nil {
		return nil, fmt.Errorf("select OTP applet: %w", err)
	}
	return &OTPSession{t: t}, nil
}

// Close releases the transport.
func (o *OTPSession) Close() error {
	if o == nil || o.t == nil {
		return nil
	}
	return o.t.Close()
}

// ValidSlot reports whether n names a challenge-response slot.
func ValidSlot(n int) bool { return n == 1 || n == 2 }

// ChallengeResponse asks the key for HMAC-SHA1 of challenge under the secret
// in slot 1 or 2. A slot configured to require a touch will not answer until
// the key is touched, so callers should say so before calling.
func (o *OTPSession) ChallengeResponse(slot int, challenge []byte) ([]byte, error) {
	var p1 byte
	switch slot {
	case 1:
		p1 = p1ChalHMAC1
	case 2:
		p1 = p1ChalHMAC2
	default:
		return nil, fmt.Errorf("slot must be 1 or 2, got %d", slot)
	}
	if len(challenge) == 0 || len(challenge) > MaxChallengeLen {
		return nil, fmt.Errorf("challenge must be 1..%d bytes, got %d", MaxChallengeLen, len(challenge))
	}
	sess := &Session{t: o.t}
	resp, err := sess.send(0x00, insAPIRequest, p1, 0x00, challenge)
	if err != nil {
		// An unprogrammed slot answers "no such object" rather than failing
		// in a way that says what to do about it.
		if err.Error() == "no such credential on the key" {
			return nil, ErrSlotEmpty
		}
		return nil, err
	}
	if len(resp) != ResponseLen {
		return nil, fmt.Errorf("key returned %d bytes, want an %d-byte HMAC-SHA1", len(resp), ResponseLen)
	}
	return resp, nil
}
