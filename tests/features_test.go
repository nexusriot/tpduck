package test

import (
	"encoding/base32"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	m "github.com/nexusriot/tpduck/internal/model"
)

// RFC 4226 Appendix D: HOTP values for the ASCII seed "12345678901234567890".
func TestHotpRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	secret := b32("12345678901234567890")
	for i, w := range want {
		acc := m.Account{Secret: secret, Algo: m.AlgoSHA1, Digits: 6, Type: m.TypeHOTP, Counter: uint64(i)}
		got, err := m.Generate(acc, time.Now())
		if err != nil {
			t.Fatalf("counter %d: %v", i, err)
		}
		if got.Value != w {
			t.Errorf("counter %d: got %s want %s", i, got.Value, w)
		}
		if !got.Static {
			t.Errorf("counter %d: HOTP reported a countdown", i)
		}
	}
}

func TestAdvanceHOTP(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{
		{ID: "h", Name: "h", Secret: b32("12345678901234567890"), Algo: m.AlgoSHA1, Digits: 6, Type: m.TypeHOTP},
		{ID: "t", Name: "t", Secret: b32("12345678901234567890"), Algo: m.AlgoSHA1, Digits: 6, Period: 30},
	}}
	first, _ := m.Generate(s.Accounts[0], time.Now())
	if err := s.AdvanceHOTP("h"); err != nil {
		t.Fatal(err)
	}
	second, _ := m.Generate(s.Accounts[0], time.Now())
	if first.Value == second.Value {
		t.Error("advancing the counter did not change the code")
	}
	if s.Accounts[0].Counter != 1 {
		t.Errorf("counter = %d, want 1", s.Accounts[0].Counter)
	}
	if err := s.AdvanceHOTP("t"); err == nil {
		t.Error("advanced the counter of a time-based account")
	}
}

func TestHotpURIRequiresCounter(t *testing.T) {
	if _, err := m.ParseOtpauthURI("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"); err == nil {
		t.Error("hotp uri without a counter was accepted")
	}
	acc, err := m.ParseOtpauthURI("otpauth://hotp/Acme:bob?secret=JBSWY3DPEHPK3PXP&counter=7")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Kind() != m.TypeHOTP || acc.Counter != 7 {
		t.Errorf("got %+v", acc)
	}
}

// Export must round-trip through the importer unchanged, or migrating out of
// tpduck silently corrupts accounts.
func TestExportRoundTrip(t *testing.T) {
	for _, want := range []m.Account{
		{Issuer: "Acme", Name: "alice@example.com", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{Issuer: "Beta Corp", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Period: 60, Algo: m.AlgoSHA512},
		{Issuer: "", Name: "no-issuer", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA256},
		{Issuer: "Ctr", Name: "hotp-user", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 42},
	} {
		uri := want.URI()
		got, err := m.ParseOtpauthURI(uri)
		if err != nil {
			t.Fatalf("%s: re-import failed: %v", uri, err)
		}
		if got.Issuer != want.Issuer || got.Name != want.Name || got.Secret != want.Secret ||
			got.Digits != want.Digits || got.Algo != want.Algo || got.Kind() != want.Kind() ||
			got.Counter != want.Counter {
			t.Errorf("round trip changed the account:\n uri  %s\n want %+v\n got  %+v", uri, want, got)
		}
		if want.Kind() == m.TypeTOTP && got.Period != want.Period {
			t.Errorf("%s: period %d != %d", uri, got.Period, want.Period)
		}
	}
}

func TestQRBlocksRenders(t *testing.T) {
	out, err := m.QRBlocks("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 10 {
		t.Fatalf("QR too small: %d lines", len(lines))
	}
	if !strings.ContainsAny(out, "█▀▄") {
		t.Error("QR contains no block characters")
	}
	// A quiet zone of 2 modules means the first row is blank.
	if strings.TrimSpace(lines[0]) != "" {
		t.Errorf("QR has no quiet zone: %q", lines[0])
	}
}

// buildMigrationURI hand-encodes a Google Authenticator export payload.
func buildMigrationURI(t *testing.T, accs []m.Account) string {
	t.Helper()
	varint := func(v uint64) []byte {
		var out []byte
		for v >= 0x80 {
			out = append(out, byte(v)|0x80)
			v >>= 7
		}
		return append(out, byte(v))
	}
	field := func(num, typ int, body []byte) []byte {
		out := varint(uint64(num)<<3 | uint64(typ))
		if typ == 2 {
			out = append(out, varint(uint64(len(body)))...)
		}
		return append(out, body...)
	}
	var payload []byte
	for _, a := range accs {
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(a.Secret)
		if err != nil {
			t.Fatal(err)
		}
		var p []byte
		p = append(p, field(1, 2, raw)...)
		p = append(p, field(2, 2, []byte(a.Name))...)
		p = append(p, field(3, 2, []byte(a.Issuer))...)
		algo := map[m.Algo]uint64{m.AlgoSHA1: 1, m.AlgoSHA256: 2, m.AlgoSHA512: 3}[a.Algo]
		p = append(p, field(4, 0, varint(algo))...)
		digits := uint64(1)
		if a.Digits == 8 {
			digits = 2
		}
		p = append(p, field(5, 0, varint(digits))...)
		typ := uint64(2)
		if a.Kind() == m.TypeHOTP {
			typ = 1
		}
		p = append(p, field(6, 0, varint(typ))...)
		p = append(p, field(7, 0, varint(a.Counter))...)
		payload = append(payload, field(1, 2, p)...)
	}
	payload = append(payload, field(2, 0, varint(1))...) // version
	payload = append(payload, field(3, 0, varint(1))...) // batch_size
	payload = append(payload, field(4, 0, varint(0))...) // batch_index
	return "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString(payload)
}

// buildMigrationURIEscaped percent-encodes the payload, which is how a real
// Google Authenticator export QR carries it.
func buildMigrationURIEscaped(t *testing.T, accs []m.Account) string {
	t.Helper()
	raw := strings.TrimPrefix(buildMigrationURI(t, accs), "otpauth-migration://offline?data=")
	return "otpauth-migration://offline?data=" + url.QueryEscape(raw)
}

func TestParseMigrationURI(t *testing.T) {
	want := []m.Account{
		{Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Algo: m.AlgoSHA1},
		{Issuer: "Beta", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Algo: m.AlgoSHA512, Type: m.TypeHOTP, Counter: 9},
	}
	uri := buildMigrationURI(t, want)
	if !m.IsMigrationURI(uri) {
		t.Fatal("IsMigrationURI said no")
	}
	got, err := m.ParseMigrationURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d accounts, want 2", len(got))
	}
	for i := range want {
		if got[i].Issuer != want[i].Issuer || got[i].Name != want[i].Name ||
			got[i].Secret != want[i].Secret || got[i].Digits != want[i].Digits ||
			got[i].Algo != want[i].Algo || got[i].Kind() != want[i].Kind() ||
			got[i].Counter != want[i].Counter {
			t.Errorf("account %d:\n want %+v\n got  %+v", i, want[i], got[i])
		}
	}
}

// A payload containing "+" must survive: url.Query() would turn it into a
// space and break the base64.
func TestParseMigrationHandlesPlusInPayload(t *testing.T) {
	accs := make([]m.Account, 0, 40)
	for i := 0; i < 40; i++ {
		accs = append(accs, m.Account{
			Issuer: "Issuer", Name: "user", Secret: "JBSWY3DPEHPK3PXP",
			Digits: 6, Algo: m.AlgoSHA1,
		})
	}
	raw := buildMigrationURI(t, accs)
	if !strings.Contains(raw, "+") && !strings.Contains(raw, "/") {
		t.Skip("generated payload happened to contain no + or /")
	}
	for name, uri := range map[string]string{
		"raw":     raw,
		"escaped": buildMigrationURIEscaped(t, accs),
	} {
		got, err := m.ParseMigrationURI(uri)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if len(got) != len(accs) {
			t.Errorf("%s: got %d accounts, want %d", name, len(got), len(accs))
		}
	}
}

func TestParseMigrationRejectsGarbage(t *testing.T) {
	for name, uri := range map[string]string{
		"not migration": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
		"no data":       "otpauth-migration://offline",
		"bad base64":    "otpauth-migration://offline?data=!!!!",
		"truncated":     "otpauth-migration://offline?data=" + base64.StdEncoding.EncodeToString([]byte{0x0a, 0x7f}),
		"empty payload": "otpauth-migration://offline?data=",
	} {
		if _, err := m.ParseMigrationURI(uri); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAccountMatchesAndFind(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{
		{ID: "github:alice", Issuer: "GitHub", Name: "alice"},
		{ID: "gitlab:bob", Issuer: "GitLab", Name: "bob"},
	}}
	if _, err := s.Find("github:alice"); err != nil {
		t.Errorf("exact ID lookup failed: %v", err)
	}
	if _, err := s.Find("GitHub:alice"); err != nil {
		t.Errorf("label lookup failed: %v", err)
	}
	if a, err := s.Find("bob"); err != nil || a.ID != "gitlab:bob" {
		t.Errorf("substring lookup failed: %v", err)
	}
	// An ambiguous query must refuse rather than silently pick one.
	_, err := s.Find("git")
	if err == nil || !strings.Contains(err.Error(), "matches 2") {
		t.Errorf("ambiguous query was not refused: %v", err)
	}
	if _, err := s.Find("nope"); err == nil {
		t.Error("missing account was found")
	}
}

func TestSkewVerdict(t *testing.T) {
	for _, tc := range []struct {
		skew time.Duration
		bad  bool
	}{
		{0, false}, {500 * time.Millisecond, false}, {-500 * time.Millisecond, false},
		{5 * time.Second, false}, {20 * time.Second, true}, {-20 * time.Second, true},
	} {
		text, bad := m.SkewVerdict(tc.skew, 30)
		if bad != tc.bad {
			t.Errorf("skew %v: bad=%v want %v (%s)", tc.skew, bad, tc.bad, text)
		}
		if text == "" {
			t.Errorf("skew %v: empty verdict", tc.skew)
		}
	}
}
