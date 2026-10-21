package yubikey

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"testing"
)

func wantHMAC(t *testing.T, secret, challenge string) []byte {
	t.Helper()
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(challenge))
	return mac.Sum(nil)
}

func TestChallengeResponse(t *testing.T) {
	card := NewSimCard()
	card.SetHMACSlot(1, []byte("slot-one"), false)
	card.SetHMACSlot(2, []byte("slot-two"), false)
	o, err := OpenOTP(card)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		slot   int
		secret string
	}{{1, "slot-one"}, {2, "slot-two"}} {
		got, err := o.ChallengeResponse(tc.slot, []byte("a challenge"))
		if err != nil {
			t.Fatalf("slot %d: %v", tc.slot, err)
		}
		if want := wantHMAC(t, tc.secret, "a challenge"); !bytes.Equal(got, want) {
			t.Errorf("slot %d: got %x, want %x", tc.slot, got, want)
		}
		if len(got) != ResponseLen {
			t.Errorf("slot %d returned %d bytes, want %d", tc.slot, len(got), ResponseLen)
		}
	}
	// The same challenge must always give the same answer, or a vault sealed
	// to the key would only open once.
	a, _ := o.ChallengeResponse(2, []byte("stable"))
	b, _ := o.ChallengeResponse(2, []byte("stable"))
	if !bytes.Equal(a, b) {
		t.Error("the same challenge gave two different responses")
	}
}

// An unprogrammed slot must say what to do about it, not just fail.
func TestChallengeResponseEmptySlot(t *testing.T) {
	card := NewSimCard()
	card.SetHMACSlot(2, []byte("only-two"), false)
	o, err := OpenOTP(card)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.ChallengeResponse(1, []byte("x")); !errors.Is(err, ErrSlotEmpty) {
		t.Errorf("empty slot gave %v, want ErrSlotEmpty", err)
	}
}

func TestChallengeResponseRejectsBadInput(t *testing.T) {
	card := NewSimCard()
	card.SetHMACSlot(2, []byte("s"), false)
	o, _ := OpenOTP(card)
	for _, tc := range []struct {
		name      string
		slot      int
		challenge []byte
	}{
		{"slot 0", 0, []byte("x")},
		{"slot 3", 3, []byte("x")},
		{"empty challenge", 2, nil},
		{"oversized challenge", 2, make([]byte, MaxChallengeLen+1)},
	} {
		if _, err := o.ChallengeResponse(tc.slot, tc.challenge); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

// A slot that wants a touch must be reported as such rather than hanging.
func TestChallengeResponseTouch(t *testing.T) {
	card := NewSimCard()
	card.SetHMACSlot(2, []byte("s"), true)
	o, _ := OpenOTP(card)
	if _, err := o.ChallengeResponse(2, []byte("x")); !errors.Is(err, ErrTouchRequired) {
		t.Errorf("got %v, want ErrTouchRequired", err)
	}
}

// Selecting the OTP applet must not leave the OATH applet selected, and vice
// versa: they share a card and only one is current.
func TestAppletsAreSeparate(t *testing.T) {
	card := NewSimCard(SimCredential{
		Name: "Acme:alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Type: TypeTOTP, Algo: "SHA1"})
	card.SetHMACSlot(2, []byte("s"), false)
	if _, err := OpenOTP(card); err != nil {
		t.Fatal(err)
	}
	// With OTP selected, OATH instructions are not answered.
	oath := &Session{t: card}
	if _, err := oath.List(); err == nil {
		t.Error("OATH list worked while the OTP applet was selected")
	}
	// Selecting OATH again brings it back.
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.List()
	if err != nil || len(creds) != 1 {
		t.Fatalf("after re-selecting OATH: %v, %d credentials", err, len(creds))
	}
}
