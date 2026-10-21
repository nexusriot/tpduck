package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nexusriot/tpduck/internal/model"
)

// captureStdout runs f with os.Stdout redirected, so a command's printed code
// can be checked without changing how it writes one.
func captureStdout(t *testing.T, f func() error) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	runErr := f()
	os.Stdout = saved
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	return string(out), runErr
}

func seedCodeVault(t *testing.T, accounts ...model.Account) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	if err := (&model.Store{Accounts: accounts}).Save(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func hotpAccount() model.Account {
	return model.Account{
		ID: "ctr:ian", Issuer: "Ctr", Name: "ian", Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Algo: model.AlgoSHA1, Type: model.TypeHOTP, Counter: 7,
	}
}

func counterOf(t *testing.T, path, id string) uint64 {
	t.Helper()
	s, err := model.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	i := s.FindIndexByID(id)
	if i < 0 {
		t.Fatalf("no account %q in %s", id, path)
	}
	return s.Accounts[i].Counter
}

// An ordinary read of a counter-based account spends a counter step, because
// the code is single-use.
func TestCodeAdvancesAnHOTPCounter(t *testing.T) {
	path := seedCodeVault(t, hotpAccount())
	f := &flags{}
	out, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"ctr"}) })
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Error("no code was printed")
	}
	if got := counterOf(t, path, "ctr:ian"); got != 8 {
		t.Errorf("counter is %d, want 8", got)
	}
}

// -peek is a pure read: the same code comes back twice and the counter stays
// where it was.
func TestPeekDoesNotSpendAnHOTPCounter(t *testing.T) {
	path := seedCodeVault(t, hotpAccount())
	f := &flags{peek: true}

	first, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"ctr"}) })
	if err != nil {
		t.Fatal(err)
	}
	second, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"ctr"}) })
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("peeking twice gave %q then %q", first, second)
	}
	if got := counterOf(t, path, "ctr:ian"); got != 7 {
		t.Errorf("counter moved to %d; a peek must not spend one", got)
	}
	// And the code really is the one for the stored counter. HOTP ignores the
	// time entirely, so any moment will do.
	want, err := model.Generate(hotpAccount(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if first != want.Value+"\n" {
		t.Errorf("peeked %q, want the code for counter 7 (%s)", first, want.Value)
	}
}

// A peek must not write the vault at all, so it is safe against a vault
// something else is writing and against a read-only one.
func TestPeekDoesNotWriteTheVault(t *testing.T) {
	path := seedCodeVault(t, hotpAccount(), model.Account{
		ID: "acme:alice", Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Period: 30, Algo: model.AlgoSHA1,
	})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := &flags{peek: true}
	for _, query := range []string{"ctr", "acme"} {
		if _, err := captureStdout(t, func() error { return cmdCode(f, path, []string{query}) }); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("peeking rewrote the vault")
	}
	// Nothing was recorded as used either, so `order used` is not disturbed.
	s, err := model.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range s.Accounts {
		if a.LastUsedAt != 0 {
			t.Errorf("%s was marked used by a peek", a.Label())
		}
	}
}

// An ordinary read does record the use, which is what `order used` sorts on.
func TestOrdinaryReadRecordsTheUse(t *testing.T) {
	path := seedCodeVault(t, model.Account{
		ID: "acme:alice", Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Period: 30, Algo: model.AlgoSHA1,
	})
	f := &flags{}
	if _, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"acme"}) }); err != nil {
		t.Fatal(err)
	}
	s, err := model.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Accounts[0].LastUsedAt == 0 {
		t.Error("an ordinary read did not record the use")
	}
}

// Peeking still resolves a query the same way, and still refuses an ambiguous
// one rather than guessing.
func TestPeekStillResolvesQueries(t *testing.T) {
	path := seedCodeVault(t,
		model.Account{ID: "acme:alice", Issuer: "Acme", Name: "alice",
			Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: model.AlgoSHA1},
		model.Account{ID: "acme:bob", Issuer: "Acme", Name: "bob",
			Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: model.AlgoSHA1},
	)
	f := &flags{peek: true}
	if _, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"acme"}) }); err == nil {
		t.Error("an ambiguous query was resolved")
	}
	if _, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"alice"}) }); err != nil {
		t.Errorf("a unique query failed: %v", err)
	}
	if _, err := captureStdout(t, func() error { return cmdCode(f, path, []string{"nope"}) }); err == nil {
		t.Error("a query matching nothing was resolved")
	}
	if _, err := captureStdout(t, func() error { return cmdCode(f, path, nil) }); err == nil {
		t.Error("code with no query was accepted")
	}
}
