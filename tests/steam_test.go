package test

import (
	"testing"
	"time"

	m "github.com/nexusriot/tpduck/internal/model"
)

// Steam Guard vectors produced by an independent transcription of the
// published algorithm (the one steamguard-cli and python-steam implement),
// not by tpduck itself.
func TestSteamGuardVectors(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	acc := m.Account{
		Issuer: "Steam", Name: "player", Secret: secret,
		Algo: m.AlgoSHA1, Period: 30, Digits: m.SteamDigits, Type: m.TypeSteam,
	}
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{0, "VH8YJ"},
		{59, "2YXGV"},
		{1234567890, "K8G5W"},
		{1111111109, "CWDGV"},
		{2000000000, "HNCVQ"},
	} {
		got, err := m.Generate(acc, time.Unix(tc.unix, 0))
		if err != nil {
			t.Fatalf("t=%d: %v", tc.unix, err)
		}
		if got.Value != tc.want {
			t.Errorf("t=%d: got %s, want %s", tc.unix, got.Value, tc.want)
		}
		if len(got.Value) != m.SteamDigits {
			t.Errorf("t=%d: code %q is not %d characters", tc.unix, got.Value, m.SteamDigits)
		}
		if got.Static {
			t.Errorf("t=%d: steam code reported as static", tc.unix)
		}
	}
}

func TestSteamCodeAlphabet(t *testing.T) {
	const alphabet = "23456789BCDFGHJKMNPQRTVWXY"
	acc := m.Account{
		Name: "p", Secret: "JBSWY3DPEHPK3PXP", Algo: m.AlgoSHA1,
		Period: 30, Digits: m.SteamDigits, Type: m.TypeSteam,
	}
	for i := int64(0); i < 200; i++ {
		got, err := m.Generate(acc, time.Unix(i*30, 0))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got.Value {
			found := false
			for _, a := range alphabet {
				if r == a {
					found = true
				}
			}
			if !found {
				t.Fatalf("code %q contains %q, which is not in Steam's alphabet", got.Value, r)
			}
		}
	}
}

func TestSteamURIRoundTrip(t *testing.T) {
	want := m.Account{
		Issuer: "Steam", Name: "player", Secret: "JBSWY3DPEHPK3PXP",
		Algo: m.AlgoSHA1, Period: 30, Digits: m.SteamDigits, Type: m.TypeSteam,
	}
	uri := want.URI()
	got, err := m.ParseOtpauthURI(uri)
	if err != nil {
		t.Fatalf("%s: %v", uri, err)
	}
	if got.Kind() != m.TypeSteam || got.Digits != m.SteamDigits ||
		got.Issuer != want.Issuer || got.Name != want.Name {
		t.Errorf("round trip changed the account: %s -> %+v", uri, got)
	}
	// The code must survive the round trip too.
	at := time.Unix(1234567890, 0)
	a, _ := m.Generate(want, at)
	b, _ := m.Generate(*got, at)
	if a.Value != b.Value {
		t.Errorf("code changed across the round trip: %s vs %s", a.Value, b.Value)
	}
}

// Aegis exports Steam entries; we used to reject the whole file over them.
func TestSteamImportFromAegis(t *testing.T) {
	const doc = `{"db":{"entries":[
	 {"type":"steam","uuid":"s1","name":"player","issuer":"Steam",
	  "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":5,"period":30}}]}}`
	accs, format, err := m.ParseBackup([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if format != "Aegis" || len(accs) != 1 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	if accs[0].Kind() != m.TypeSteam {
		t.Errorf("imported as %q, want steam", accs[0].Kind())
	}
	got, err := m.Generate(accs[0], time.Unix(1234567890, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "K8G5W" {
		t.Errorf("imported steam account produced %s, want K8G5W", got.Value)
	}
}

// Steam Guard is time-based, so an export that leaves the period out wants the
// same default every other time-based entry gets. Refusing it instead reported
// a well-formed credential as an unrecognised backup.
func TestSteamImportWithoutAPeriod(t *testing.T) {
	const doc = `{"db":{"entries":[
	 {"type":"steam","uuid":"s1","name":"player","issuer":"Steam",
	  "info":{"secret":"JBSWY3DPEHPK3PXP"}}]}}`
	accs, format, err := m.ParseBackup([]byte(doc))
	if err != nil {
		t.Fatalf("a Steam entry with no period was refused: %v", err)
	}
	if format != "Aegis" || len(accs) != 1 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	if accs[0].Period != m.DefaultPeriod {
		t.Errorf("period = %d, want the default %d", accs[0].Period, m.DefaultPeriod)
	}
	// And it produces the same code an explicit period=30 would.
	got, err := m.Generate(accs[0], time.Unix(1234567890, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "K8G5W" {
		t.Errorf("produced %s, want K8G5W", got.Value)
	}
}

// A steam account with a nonsense digit count must be normalised, not rejected.
func TestSteamDigitsNormalised(t *testing.T) {
	acc := m.Account{
		Name: "p", Secret: "JBSWY3DPEHPK3PXP", Algo: m.AlgoSHA1,
		Period: 30, Digits: 6, Type: m.TypeSteam,
	}
	if err := acc.Validate(); err != nil {
		t.Fatalf("steam account rejected: %v", err)
	}
	if acc.Digits != m.SteamDigits {
		t.Errorf("digits = %d, want %d", acc.Digits, m.SteamDigits)
	}
}
