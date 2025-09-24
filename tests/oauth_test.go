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
