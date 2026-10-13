package yubikey

import (
	"errors"
	"testing"
	"time"
)

func TestPutAndCalculate(t *testing.T) {
	card := NewSimCard()
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	name := CredentialName("Acme", "alice", 30, TypeTOTP)
	if name != "Acme:alice" {
		t.Fatalf("name = %q", name)
	}
	if err := s.Put(PutOptions{
		Name: name, Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP,
		Algo: "SHA1", Digits: 6,
	}); err != nil {
		t.Fatal(err)
	}
	creds, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 1 || creds[0].Issuer != "Acme" || creds[0].Account != "alice" {
		t.Fatalf("after Put: %+v", creds)
	}
	// The key must now produce the same code the secret implies.
	at := time.Unix(1234567890, 0)
	got, err := s.Calculate(name, 6, at, 30)
	if err != nil {
		t.Fatal(err)
	}
	// The fake pads short secrets exactly as Put does, so compare against what
	// the card holds rather than the original Base32.
	if want := expectedCode(card.Credentials()[0].Secret, at, 30, 6); got != want {
		t.Errorf("code = %s, want %s", got, want)
	}
}

func TestCredentialNameCarriesPeriod(t *testing.T) {
	if got := CredentialName("Acme", "bob", 60, TypeTOTP); got != "60/Acme:bob" {
		t.Errorf("got %q", got)
	}
	if got := CredentialName("", "bob", 30, TypeTOTP); got != "bob" {
		t.Errorf("got %q", got)
	}
	// HOTP has no period, so it is never prefixed.
	if got := CredentialName("Acme", "bob", 60, TypeHOTP); got != "Acme:bob" {
		t.Errorf("got %q", got)
	}
}

func TestPutValidation(t *testing.T) {
	s, _ := Open(NewSimCard())
	bad := map[string]PutOptions{
		"no name":      {Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP, Digits: 6},
		"empty secret": {Name: "x", Type: TypeTOTP, Digits: 6},
		"bad secret":   {Name: "x", Secret: "1111", Type: TypeTOTP, Digits: 6},
		"bad digits":   {Name: "x", Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP, Digits: 7},
		"bad algo":     {Name: "x", Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP, Digits: 6, Algo: "MD5"},
		"bad type":     {Name: "x", Secret: "JBSWY3DPEHPK3PXP", Type: Type("steam"), Digits: 6},
		"long name": {Name: string(make([]byte, 100)), Secret: "JBSWY3DPEHPK3PXP",
			Type: TypeTOTP, Digits: 6},
	}
	for name, o := range bad {
		if err := s.Put(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPutTouchAndOverwrite(t *testing.T) {
	card := NewSimCard()
	s, _ := Open(card)
	o := PutOptions{Name: "Acme:alice", Secret: "JBSWY3DPEHPK3PXP", Type: TypeTOTP, Algo: "SHA256", Digits: 8, Touch: true}
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	creds, _ := s.List()
	if len(creds) != 1 || creds[0].Algo != "SHA256" {
		t.Fatalf("got %+v", creds)
	}
	// LIST carries no touch bit; CALCULATE ALL is where the applet reports it.
	_, all, err := s.CalculateAll(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || !all[0].Touch {
		t.Errorf("touch flag not reported by CalculateAll: %+v", all)
	}
	if _, err := s.Calculate("Acme:alice", 8, time.Now(), 30); !errors.Is(err, ErrTouchRequired) {
		t.Errorf("touch credential returned %v", err)
	}
	// Putting the same name again replaces rather than duplicating.
	o.Touch = false
	if err := s.Put(o); err != nil {
		t.Fatal(err)
	}
	if creds, _ = s.List(); len(creds) != 1 {
		t.Errorf("Put duplicated the credential: %+v", creds)
	}
}

func TestDeleteAndRename(t *testing.T) {
	s, _ := Open(sampleCard())
	if err := s.Rename("30/GitHub:alice", "30/GitHub:alice2"); err != nil {
		t.Fatal(err)
	}
	creds, _ := s.List()
	found := false
	for _, c := range creds {
		if c.Account == "alice2" {
			found = true
		}
	}
	if !found {
		t.Errorf("rename did not take: %+v", creds)
	}
	if err := s.Rename("nope", "x"); err == nil {
		t.Error("renamed a credential that does not exist")
	}
	if err := s.Rename("30/GitHub:alice2", " "); err == nil {
		t.Error("renamed to an empty name")
	}
	if err := s.Delete("30/GitHub:alice2"); err != nil {
		t.Fatal(err)
	}
	if creds, _ = s.List(); len(creds) != 2 {
		t.Errorf("after delete: %d credentials, want 2", len(creds))
	}
	if err := s.Delete("nope"); err == nil {
		t.Error("deleted a credential that does not exist")
	}
}

// A password-protected applet must be unusable until Unlock, and Unlock must
// verify the key's counter-response rather than trusting it.
func TestPasswordUnlock(t *testing.T) {
	card := sampleCard()
	card.SetPassword("hunter2", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 9, 9, 9, 9, 9, 9, 9})

	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if !s.NeedsPassword() {
		t.Fatal("NeedsPassword() is false on a protected applet")
	}
	if len(s.DeviceID()) != 8 {
		t.Errorf("device id = %v", s.DeviceID())
	}
	if _, err := s.List(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("list before unlock: %v", err)
	}
	if err := s.Unlock("wrong"); err == nil {
		t.Fatal("a wrong password unlocked the applet")
	}
	if err := s.Unlock("hunter2"); err != nil {
		t.Fatalf("correct password rejected: %v", err)
	}
	if s.NeedsPassword() {
		t.Error("NeedsPassword() still true after unlocking")
	}
	if _, err := s.List(); err != nil {
		t.Fatalf("list after unlock: %v", err)
	}
}

// A key that cannot prove it knows the password must be rejected, so a hostile
// reader cannot claim any password was accepted.
func TestUnlockRejectsBadCounterResponse(t *testing.T) {
	sim := sampleCard()
	sim.SetPassword("hunter2", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 9, 9, 9, 9, 9, 9, 9})
	card := &liarCard{SimCard: sim}
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Unlock("hunter2"); err == nil {
		t.Fatal("accepted a key that could not prove itself")
	}
}

func TestUnlockOnUnprotectedApplet(t *testing.T) {
	s, _ := Open(sampleCard())
	if err := s.Unlock("anything"); err == nil {
		t.Error("Unlock succeeded on an applet with no password")
	}
}

// liarCard answers VALIDATE with a wrong counter-response.
type liarCard struct{ *SimCard }

func (l *liarCard) Transmit(apdu []byte) ([]byte, error) {
	resp, err := l.SimCard.Transmit(apdu)
	if err != nil || len(apdu) < 2 || apdu[1] != insValidate {
		return resp, err
	}
	return append(tlv(tagResponse, []byte("not the right mac")), 0x90, 0x00), nil
}
