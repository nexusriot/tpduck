package test

import (
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

func TestParseOtpauthURI(t *testing.T) {
	raw := "otpauth://totp/GitHub:you@mail?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
	acc, err := m.ParseOtpauthURI(raw)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if acc.Issuer != "GitHub" || acc.Name != "you@mail" {
		t.Fatalf("issuer/name wrong: %+v", acc)
	}
	if acc.Digits != 6 || acc.Period != 30 || acc.Algo != m.AlgoSHA1 {
		t.Fatalf("digits/period/algo wrong: %+v", acc)
	}
	if err := m.ValidateSecret(acc.Secret); err != nil {
		t.Fatalf("secret not valid base32: %v", err)
	}
}

func TestParseOtpauthLabelNotDoubleUnescaped(t *testing.T) {
	// "%2520" decodes once to the literal text "%20"; decoding twice turns it
	// into a space and corrupts the issuer.
	acc, err := m.ParseOtpauthURI("otpauth://totp/ACME%2520Co:bob?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Issuer != "ACME%20Co" {
		t.Errorf("issuer = %q, want ACME%%20Co", acc.Issuer)
	}
	if acc.Name != "bob" {
		t.Errorf("name = %q, want bob", acc.Name)
	}
}

func TestParseOtpauthCaseInsensitiveScheme(t *testing.T) {
	if _, err := m.ParseOtpauthURI("OTPAUTH://TOTP/x?secret=JBSWY3DPEHPK3PXP"); err != nil {
		t.Errorf("uppercase scheme/host rejected: %v", err)
	}
}

func TestParseOtpauthRejectsBadInput(t *testing.T) {
	for name, raw := range map[string]string{
		"hotp no counter": "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
		"bad counter":     "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=nope",
		"unknown type":    "otpauth://yubico/x?secret=JBSWY3DPEHPK3PXP",
		"no secret":       "otpauth://totp/x",
		"bad secret":      "otpauth://totp/x?secret=11111111",
		"empty secret":    "otpauth://totp/x?secret=",
		"no name":         "otpauth://totp/?secret=JBSWY3DPEHPK3PXP",
		"bad digits":      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=7",
		"bad period":      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=0",
		"neg period":      "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=-5",
		"bad algorithm":   "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
	} {
		if acc, err := m.ParseOtpauthURI(raw); err == nil {
			t.Errorf("%s: accepted %q -> %+v", name, raw, acc)
		}
	}
}

func TestParseOtpauthIssuerPrecedence(t *testing.T) {
	// Query issuer wins; label issuer is the fallback.
	acc, err := m.ParseOtpauthURI("otpauth://totp/Label:bob?secret=JBSWY3DPEHPK3PXP&issuer=Query")
	if err != nil || acc.Issuer != "Query" {
		t.Errorf("got %+v (%v), want issuer=Query", acc, err)
	}
	acc, err = m.ParseOtpauthURI("otpauth://totp/Label:bob?secret=JBSWY3DPEHPK3PXP")
	if err != nil || acc.Issuer != "Label" {
		t.Errorf("got %+v (%v), want issuer=Label", acc, err)
	}
}
