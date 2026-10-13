package test

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"

	m "github.com/nexusriot/tpduck/internal/model"
)

// b32 encodes the RFC 6238 ASCII seeds the way an authenticator would store them.
func b32(ascii string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(ascii))
}

// RFC 6238, Appendix B. These vectors were never exercised before; they pin the
// counter derivation, the dynamic truncation and all three HMAC algorithms.
func TestTotpRFC6238Vectors(t *testing.T) {
	const (
		seed1   = "12345678901234567890"
		seed256 = "12345678901234567890123456789012"
		seed512 = "1234567890123456789012345678901234567890123456789012345678901234"
	)
	cases := []struct {
		unix int64
		algo m.Algo
		seed string
		want string
	}{
		{59, m.AlgoSHA1, seed1, "94287082"},
		{59, m.AlgoSHA256, seed256, "46119246"},
		{59, m.AlgoSHA512, seed512, "90693936"},
		{1111111109, m.AlgoSHA1, seed1, "07081804"},
		{1111111111, m.AlgoSHA1, seed1, "14050471"},
		{1234567890, m.AlgoSHA1, seed1, "89005924"},
		{1234567890, m.AlgoSHA256, seed256, "91819424"},
		{1234567890, m.AlgoSHA512, seed512, "93441116"},
		{2000000000, m.AlgoSHA1, seed1, "69279037"},
		{20000000000, m.AlgoSHA1, seed1, "65353130"},
		{20000000000, m.AlgoSHA256, seed256, "77737706"},
		{20000000000, m.AlgoSHA512, seed512, "47863826"},
	}
	for _, c := range cases {
		got, _, err := m.Totp(b32(c.seed), c.algo, 30, 8, time.Unix(c.unix, 0))
		if err != nil {
			t.Fatalf("T=%d %s: %v", c.unix, c.algo, err)
		}
		if got != c.want {
			t.Errorf("T=%d %s: got %s want %s", c.unix, c.algo, got, c.want)
		}
	}
}

func TestTotpRemainingSeconds(t *testing.T) {
	for _, tc := range []struct{ unix, want int64 }{
		{0, 30}, {1, 29}, {29, 1}, {30, 30}, {59, 1},
	} {
		_, remain, err := m.Totp(b32("12345678901234567890"), m.AlgoSHA1, 30, 6, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatal(err)
		}
		if int64(remain) != tc.want {
			t.Errorf("t=%d: remain=%d want %d", tc.unix, remain, tc.want)
		}
	}
}

// An empty secret decodes to a zero-length HMAC key, which produces a
// perfectly plausible code that no server will ever accept.
func TestEmptySecretRejected(t *testing.T) {
	for _, s := range []string{"", "   ", "=", "----"} {
		if err := m.ValidateSecret(s); err == nil {
			t.Errorf("ValidateSecret(%q) accepted an empty key", s)
		}
		if _, _, err := m.Totp(s, m.AlgoSHA1, 30, 6, time.Now()); err == nil {
			t.Errorf("Totp(%q) produced a code from an empty key", s)
		}
	}
}

func TestNormalizeSecret(t *testing.T) {
	// Providers display secrets in spaced groups, lower case, sometimes dashed.
	want := "JBSWY3DPEHPK3PXP"
	for _, in := range []string{
		"JBSWY3DPEHPK3PXP", "jbswy3dp ehpk3pxp", "JBSW-Y3DP-EHPK-3PXP", "JBSWY3DPEHPK3PXP====",
	} {
		if got := m.NormalizeSecret(in); got != want {
			t.Errorf("NormalizeSecret(%q) = %q, want %q", in, got, want)
		}
	}
	// Normalization must not change the generated code.
	ref, _, _ := m.Totp(want, m.AlgoSHA1, 30, 6, time.Unix(1234567890, 0))
	got, _, err := m.Totp("jbsw y3dp-ehpk 3pxp", m.AlgoSHA1, 30, 6, time.Unix(1234567890, 0))
	if err != nil || got != ref {
		t.Errorf("formatted secret gave %q (%v), want %q", got, err, ref)
	}
	// And no padding leaks into the stored value.
	if strings.Contains(m.NormalizeSecret("JBSWY3DPEHPK3PX"), "=") {
		t.Error("NormalizeSecret stored padding")
	}
}

func TestUnsupportedAlgoRejected(t *testing.T) {
	if _, _, err := m.Totp("JBSWY3DPEHPK3PXP", m.Algo("MD5"), 30, 6, time.Now()); err == nil {
		t.Error("expected an error for an unsupported algorithm")
	}
}
