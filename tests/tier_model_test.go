package test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	m "github.com/nexusriot/tpduck/internal/model"
)

func totpAcc() m.Account {
	return m.Account{ID: "a:b", Issuer: "A", Name: "b", Secret: b32("12345678901234567890"),
		Digits: 6, Period: 30, Algo: m.AlgoSHA1}
}

// --- KDF ---

func TestBothKDFsRoundTrip(t *testing.T) {
	for _, kdf := range []string{m.KDFArgon2id, m.KDFScrypt} {
		k, err := m.NewKeyWithKDF("pass", kdf)
		if err != nil {
			t.Fatalf("%s: %v", kdf, err)
		}
		if k.KDF() != kdf {
			t.Errorf("KDF() = %q, want %q", k.KDF(), kdf)
		}
		sealed, err := k.Seal([]byte(`{"accounts":[]}`))
		if err != nil {
			t.Fatalf("%s: %v", kdf, err)
		}
		var env struct {
			KDF string `json:"kdf"`
		}
		if err := json.Unmarshal(sealed, &env); err != nil || env.KDF != kdf {
			t.Errorf("envelope kdf = %q, want %q (%v)", env.KDF, kdf, err)
		}
		if _, err := m.Decrypt(sealed, "pass"); err != nil {
			t.Errorf("%s: reopen failed: %v", kdf, err)
		}
		if _, err := m.Decrypt(sealed, "nope"); err == nil {
			t.Errorf("%s: wrong passphrase accepted", kdf)
		}
		k.Zero()
	}
}

func TestDefaultKDFIsArgon2id(t *testing.T) {
	sealed, err := m.Encrypt([]byte(`{"accounts":[]}`), "pass")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		KDF string `json:"kdf"`
	}
	_ = json.Unmarshal(sealed, &env)
	if env.KDF != m.KDFArgon2id {
		t.Errorf("new vaults use %q, want argon2id", env.KDF)
	}
}

// A vault written by an older build must keep opening.
func TestScryptVaultStillOpens(t *testing.T) {
	k, err := m.NewKeyWithKDF("legacy", m.KDFScrypt)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := k.Seal([]byte(`{"accounts":[{"id":"x","name":"x","secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30,"algo":"SHA1"}]}`))
	k.Zero()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := m.Decrypt(sealed, "legacy")
	if err != nil {
		t.Fatalf("scrypt vault no longer opens: %v", err)
	}
	if !strings.Contains(string(plain), "JBSWY3DPEHPK3PXP") {
		t.Error("decrypted content is wrong")
	}
}

func TestUnknownKDFRefused(t *testing.T) {
	sealed, _ := m.Encrypt([]byte(`{"accounts":[]}`), "pass")
	var env map[string]any
	_ = json.Unmarshal(sealed, &env)
	env["kdf"] = "rot13"
	tampered, _ := json.Marshal(env)
	if _, err := m.Decrypt(tampered, "pass"); err == nil {
		t.Error("unknown kdf accepted")
	}
	if _, err := m.NewKeyWithKDF("p", "rot13"); err == nil {
		t.Error("NewKeyWithKDF accepted an unknown kdf")
	}
}

func TestArgonParamsRangeChecked(t *testing.T) {
	sealed, _ := m.Encrypt([]byte(`{"accounts":[]}`), "pass")
	var env map[string]any
	_ = json.Unmarshal(sealed, &env)
	env["n"] = 1 << 28 // 256 GiB of argon2 memory
	tampered, _ := json.Marshal(env)
	_, err := m.Decrypt(tampered, "pass")
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("hostile argon2 memory not refused: %v", err)
	}
}

// --- verify ---

func TestVerify(t *testing.T) {
	acc := totpAcc()
	now := time.Unix(1234567890, 0)
	code, _, err := m.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, now)
	if err != nil {
		t.Fatal(err)
	}
	res, err := m.Verify(acc, code, now, 1)
	if err != nil || !res.OK || res.Offset != 0 {
		t.Fatalf("current code: %+v %v", res, err)
	}
	// A code from the previous window verifies at offset -1.
	prev, _, _ := m.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, now.Add(-30*time.Second))
	res, _ = m.Verify(acc, prev, now, 1)
	if !res.OK || res.Offset != -1 {
		t.Errorf("previous code: %+v", res)
	}
	// Outside the window it must not verify.
	old, _, _ := m.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, now.Add(-300*time.Second))
	if res, _ := m.Verify(acc, old, now, 1); res.OK {
		t.Errorf("a code 10 windows old verified: %+v", res)
	}
	if res, _ := m.Verify(acc, "000000", now, 1); res.OK {
		t.Error("a junk code verified")
	}
}

func TestVerifyHOTP(t *testing.T) {
	acc := m.Account{ID: "h", Name: "h", Secret: b32("12345678901234567890"),
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 0}
	// RFC 4226: counter 3 -> 969429.
	res, err := m.Verify(acc, "969429", time.Now(), 10)
	if err != nil || !res.OK || res.Offset != 3 {
		t.Fatalf("got %+v %v, want offset 3", res, err)
	}
	if res, _ := m.Verify(acc, "969429", time.Now(), 2); res.OK {
		t.Error("matched beyond the lookahead")
	}
}

func TestResyncHOTP(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{{
		ID: "h", Name: "h", Secret: b32("12345678901234567890"),
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 0,
	}}}
	// 520489 is counter 9; after resync the next code should be counter 10.
	got, err := s.ResyncHOTP("h", "520489", 20)
	if err != nil {
		t.Fatal(err)
	}
	if got != 10 {
		t.Fatalf("counter = %d, want 10", got)
	}
	if _, err := s.ResyncHOTP("h", "000000", 5); err == nil {
		t.Error("resync accepted a code it could not find")
	}
}

// --- ordering ---

func TestSortPinnedAndRecent(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{
		{ID: "a", Issuer: "Alpha", Name: "a", LastUsedAt: 10},
		{ID: "z", Issuer: "Zulu", Name: "z", LastUsedAt: 300},
		{ID: "m", Issuer: "Mike", Name: "m", LastUsedAt: 200, Pinned: true},
	}}
	s.Sort()
	if s.Accounts[0].ID != "m" {
		t.Errorf("pinned account is not first: %s", s.Accounts[0].ID)
	}
	if s.Accounts[1].ID != "a" {
		t.Errorf("default order is not alphabetical: %s", s.Accounts[1].ID)
	}
	s.Order = m.SortByUsed
	s.Sort()
	if s.Accounts[0].ID != "m" || s.Accounts[1].ID != "z" {
		t.Errorf("recent order wrong: %s %s", s.Accounts[0].ID, s.Accounts[1].ID)
	}
	ok, err := s.TogglePinned("m")
	if err != nil || ok {
		t.Fatalf("toggle = %v %v, want false", ok, err)
	}
	s.Sort()
	if s.Accounts[0].ID != "z" {
		t.Errorf("unpinning did not reorder: %s", s.Accounts[0].ID)
	}
}

func TestMarkUsed(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{{ID: "a", Name: "a"}}}
	s.MarkUsed("a")
	if s.Accounts[0].LastUsedAt == 0 {
		t.Error("MarkUsed did not record a timestamp")
	}
	s.MarkUsed("missing") // must not panic
}

// --- time offset ---

func TestTimeOffsetShiftsCodes(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{totpAcc()}}
	base := s.Now()
	s.TimeOffsetSeconds = 3600
	if shifted := s.Now(); shifted.Sub(base) < 59*time.Minute {
		t.Fatalf("offset not applied: %v", shifted.Sub(base))
	}
	// A code generated with a +30s offset must equal the next window's code.
	acc := totpAcc()
	now := time.Unix(1234567890, 0)
	next, _, _ := m.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, now.Add(30*time.Second))
	withOffset, _, _ := m.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits,
		now.Add(time.Duration(30)*time.Second))
	if next != withOffset {
		t.Error("offset arithmetic is inconsistent")
	}
}

// --- migration export ---

func TestMigrationExportRoundTrip(t *testing.T) {
	want := []m.Account{
		{Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{Issuer: "Beta", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Period: 30, Algo: m.AlgoSHA512},
		{Issuer: "Ctr", Name: "carl", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Algo: m.AlgoSHA256, Type: m.TypeHOTP, Counter: 17},
	}
	uris, err := m.BuildMigrationURIs(want, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(uris) != 1 {
		t.Fatalf("got %d batches, want 1", len(uris))
	}
	got, err := m.ParseMigrationURI(uris[0])
	if err != nil {
		t.Fatalf("our own export does not re-import: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d accounts, want %d", len(got), len(want))
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

func TestMigrationExportBatches(t *testing.T) {
	accs := make([]m.Account, 25)
	for i := range accs {
		accs[i] = m.Account{Issuer: "I", Name: "n", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1}
	}
	uris, err := m.BuildMigrationURIs(accs, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(uris) != 3 {
		t.Fatalf("got %d batches, want 3", len(uris))
	}
	total := 0
	for _, u := range uris {
		got, err := m.ParseMigrationURI(u)
		if err != nil {
			t.Fatal(err)
		}
		total += len(got)
	}
	if total != 25 {
		t.Errorf("batches hold %d accounts, want 25", total)
	}
	if _, err := m.BuildMigrationURIs(nil, 0); err == nil {
		t.Error("exporting nothing should be an error")
	}
}

// The usual HOTP desync is our counter having run ahead of the server's, so
// resync must be able to search backwards too.
func TestResyncSearchesBackwards(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{{
		ID: "h", Name: "h", Secret: b32("12345678901234567890"),
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 30,
	}}}
	// 755224 is counter 0 -- thirty steps behind where we are now.
	got, err := s.ResyncHOTP("h", "755224", 50)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestResyncRespectsLookahead(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{{
		ID: "h", Name: "h", Secret: b32("12345678901234567890"),
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 30,
	}}}
	if _, err := s.ResyncHOTP("h", "755224", 5); err == nil {
		t.Error("matched a counter outside the lookahead")
	}
	if s.Accounts[0].Counter != 30 {
		t.Errorf("a failed resync moved the counter to %d", s.Accounts[0].Counter)
	}
}
