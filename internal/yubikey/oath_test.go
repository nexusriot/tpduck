package yubikey

import (
	"errors"
	"testing"
	"time"
)

func TestOpenAndList(t *testing.T) {
	card := sampleCard()
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != "5.4.3" {
		t.Errorf("version = %q", s.Version)
	}
	creds, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 3 {
		t.Fatalf("got %d credentials", len(creds))
	}
	if creds[0].Issuer != "GitHub" || creds[0].Account != "alice" || creds[0].Period != 30 ||
		creds[0].Type != TypeTOTP || creds[0].Algo != "SHA1" {
		t.Errorf("cred 0 = %+v", creds[0])
	}
	if creds[1].Type != TypeHOTP || creds[1].Algo != "SHA256" || creds[1].Issuer != "Bank" {
		t.Errorf("cred 1 = %+v", creds[1])
	}
	if creds[2].Period != 60 || creds[2].Algo != "SHA512" || creds[2].Label() != "Touchy:carol" {
		t.Errorf("cred 2 = %+v", creds[2])
	}
	if err := s.Close(); err != nil || !card.Closed() {
		t.Errorf("close: %v closed=%v", err, card.Closed())
	}
}

func TestCalculateMatchesTheKey(t *testing.T) {
	s, err := Open(sampleCard())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1234567890, 0)
	got, err := s.Calculate("30/GitHub:alice", 6, at, 30)
	if err != nil {
		t.Fatal(err)
	}
	if want := expectedCode("JBSWY3DPEHPK3PXP", at, 30, 6); got != want {
		t.Errorf("code = %s, want %s", got, want)
	}
	// A 60-second credential must use a different window.
	got60, err := s.Calculate("60/Other:x", 6, at, 60)
	if err == nil {
		t.Fatalf("unknown credential returned %s", got60)
	}
}

func TestCalculateUnknownCredential(t *testing.T) {
	s, _ := Open(sampleCard())
	if _, err := s.Calculate("nope", 6, time.Now(), 30); err == nil {
		t.Fatal("unknown credential accepted")
	}
}

func TestTouchRequired(t *testing.T) {
	s, _ := Open(sampleCard())
	_, err := s.Calculate("60/Touchy:carol", 6, time.Now(), 60)
	if !errors.Is(err, ErrTouchRequired) {
		t.Fatalf("got %v, want ErrTouchRequired", err)
	}
}

func TestCalculateAll(t *testing.T) {
	s, _ := Open(sampleCard())
	at := time.Unix(1234567890, 0)
	codes, creds, err := s.CalculateAll(at)
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 3 {
		t.Fatalf("got %d credentials", len(creds))
	}
	if want := expectedCode("JBSWY3DPEHPK3PXP", at, 30, 6); codes["30/GitHub:alice"] != want {
		t.Errorf("totp code = %s, want %s", codes["30/GitHub:alice"], want)
	}
	// HOTP and touch-required credentials yield no code here.
	if _, ok := codes["Bank:bob"]; ok {
		t.Error("CalculateAll returned a code for an HOTP credential")
	}
	if _, ok := codes["60/Touchy:carol"]; ok {
		t.Error("CalculateAll returned a code for a touch credential")
	}
	for _, c := range creds {
		if c.Name == "60/Touchy:carol" && !c.Touch {
			t.Error("touch credential not flagged")
		}
		if c.Name == "Bank:bob" && c.Type != TypeHOTP {
			t.Error("hotp credential not flagged")
		}
	}
}

// Long responses arrive in pieces ending 61xx; the client must reassemble them.
func TestChunkedResponseReassembly(t *testing.T) {
	held := sampleCard().Credentials()
	for i := 0; i < 20; i++ {
		held = append(held, SimCredential{
			Name: "30/Filler:user" + string(rune('a'+i)), Secret: "JBSWY3DPEHPK3PXP",
			Digits: 6, Type: TypeTOTP, Algo: "SHA1",
		})
	}
	card := NewSimCard(held...)
	card.Chunk = 16
	s, err := Open(card)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(creds) != 23 {
		t.Fatalf("got %d credentials across chunks, want 23", len(creds))
	}
	if creds[22].Issuer != "Filler" {
		t.Errorf("last credential = %+v", creds[22])
	}
}

func TestPasswordProtectedApplet(t *testing.T) {
	card := sampleCard()
	card.SetPassword("pw", []byte{1, 2, 3, 4, 5, 6, 7, 8}, []byte{9, 9, 9, 9, 9, 9, 9, 9})
	s, err := Open(card)
	if err != nil {
		t.Fatalf("select should still work on a locked applet: %v", err)
	}
	if _, err := s.List(); !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("got %v, want ErrAuthRequired", err)
	}
	if err := s.Unlock("pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err != nil {
		t.Fatalf("list after validate: %v", err)
	}
}

func TestParseName(t *testing.T) {
	for raw, want := range map[string]Credential{
		"30/GitHub:alice": {Period: 30, Issuer: "GitHub", Account: "alice"},
		"GitHub:alice":    {Period: 30, Issuer: "GitHub", Account: "alice"},
		"alice":           {Period: 30, Issuer: "", Account: "alice"},
		"60/bob":          {Period: 60, Issuer: "", Account: "bob"},
		"notanum/bob":     {Period: 30, Issuer: "", Account: "notanum/bob"},
	} {
		got := parseName(raw)
		if got.Period != want.Period || got.Issuer != want.Issuer || got.Account != want.Account {
			t.Errorf("parseName(%q) = %+v, want period=%d issuer=%q account=%q",
				raw, got, want.Period, want.Issuer, want.Account)
		}
		if got.Name != raw {
			t.Errorf("parseName(%q) lost the raw name: %q", raw, got.Name)
		}
	}
}

func TestTLVRoundTripAndMalformed(t *testing.T) {
	// Lengths across the 0x80 and 0x100 boundaries use longer length forms.
	for _, n := range []int{0, 1, 0x7F, 0x80, 0xFF, 0x100, 0x123} {
		body := make([]byte, n)
		for i := range body {
			body[i] = byte(i)
		}
		items := parseTLVs(tlv(0x71, body))
		if len(items) != 1 || items[0].tag != 0x71 || len(items[0].value) != n {
			t.Fatalf("n=%d: round trip failed: %+v", n, items)
		}
	}
	// A truncated item is dropped rather than read past the end.
	if items := parseTLVs([]byte{0x71, 0x05, 0x01, 0x02}); len(items) != 0 {
		t.Errorf("truncated TLV was accepted: %+v", items)
	}
	if items := parseTLVs([]byte{0x71, 0x82, 0x01}); len(items) != 0 {
		t.Errorf("truncated long-form TLV was accepted: %+v", items)
	}
}

func TestFormatTruncated(t *testing.T) {
	v := []byte{6, 0x7F, 0xFF, 0xFF, 0xFF}
	got, err := formatTruncated(v, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Errorf("got %q, want 6 digits", got)
	}
	if _, err := formatTruncated([]byte{1, 2}, 6); err == nil {
		t.Error("short response accepted")
	}
	if _, err := formatTruncated([]byte{7, 0, 0, 0, 0}, 0); err == nil {
		t.Error("7-digit credential accepted")
	}
}

func TestStatusErrors(t *testing.T) {
	for sw, want := range map[uint16]string{
		swAuthRequired: "password-protected",
		swNoSuchObject: "no such credential",
		swWrongSyntax:  "wrong syntax",
	} {
		if err := statusError(sw); err == nil || !contains(err.Error(), want) {
			t.Errorf("status 0x%04X -> %v, want something about %q", sw, err, want)
		}
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})())
}
