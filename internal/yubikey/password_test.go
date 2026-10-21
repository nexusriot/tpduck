package yubikey

import (
	"strings"
	"testing"
)

// oneCredCard keeps the password tests independent of the shared fixture: a
// single credential is all they need, and counting what a reset wiped is
// clearer with one.
func oneCredCard() *SimCard {
	return NewSimCard(SimCredential{
		Name: "Acme:alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Type: TypeTOTP, Algo: "SHA1"})
}

// Setting a password must actually lock the applet, and the password that was
// set must be the one that opens it.
func TestSetAndRemovePassword(t *testing.T) {
	card := oneCredCard()
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if s.NeedsPassword() {
		t.Fatal("a fresh applet should not need a password")
	}
	if err := s.SetPassword("hunter2"); err != nil {
		t.Fatal(err)
	}

	// Power-cycle: what a real key does when it is unplugged.
	card.Reset()
	locked, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if !locked.NeedsPassword() {
		t.Fatal("the applet is not locked after setting a password")
	}
	if _, err := locked.List(); err == nil {
		t.Error("credentials were readable without the password")
	}
	if err := locked.Unlock("not-it"); err == nil {
		t.Error("the wrong password was accepted")
	}
	if err := locked.Unlock("hunter2"); err != nil {
		t.Fatalf("the right password was refused: %v", err)
	}
	if creds, err := locked.List(); err != nil || len(creds) != 1 {
		t.Fatalf("after unlocking: %v, %d credentials", err, len(creds))
	}

	if err := locked.RemovePassword(); err != nil {
		t.Fatal(err)
	}
	card.Reset()
	open, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if open.NeedsPassword() {
		t.Error("the password was not removed")
	}
}

func TestSetPasswordRejectsEmpty(t *testing.T) {
	s, _ := Open(oneCredCard())
	if err := s.SetPassword(""); err == nil {
		t.Error("an empty password was accepted")
	} else if !strings.Contains(err.Error(), "RemovePassword") {
		t.Errorf("error %q does not say what to do instead", err)
	}
}

// Reset wipes everything. It is the only way back into a key whose password
// has been forgotten, and it destroys every secret on it.
func TestReset(t *testing.T) {
	card := oneCredCard()
	s, _ := Open(card)
	if err := s.SetPassword("hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	card.Reset()
	after, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if after.NeedsPassword() {
		t.Error("reset left the password in place")
	}
	if creds, err := after.List(); err != nil || len(creds) != 0 {
		t.Errorf("reset left %d credentials (%v)", len(creds), err)
	}
}

// A reset must not be reachable by a stray APDU with the wrong parameters: the
// applet guards it with a fixed P1/P2, and so does the simulator.
func TestResetNeedsItsMagicParameters(t *testing.T) {
	card := oneCredCard()
	s := &Session{t: card}
	if _, err := s.send(0x00, insReset, 0x00, 0x00, nil); err == nil {
		t.Error("a reset without the guard bytes was accepted")
	}
	if creds, _ := s.List(); len(creds) != 1 {
		t.Error("the credential was wiped anyway")
	}
}
