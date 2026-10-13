package test

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

func seedVault(t *testing.T, path string, accounts ...m.Account) {
	t.Helper()
	s := &m.Store{Accounts: accounts}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
}

func acc(id string) m.Account {
	return m.Account{ID: id, Issuer: id, Name: id, Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Period: 30, Algo: m.AlgoSHA1}
}

// The original bug: two readers, both save, and the second silently destroys
// the first's work.
func TestStaleWriteIsRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))

	first, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}

	first.Accounts = append(first.Accounts, acc("b"))
	if err := first.Save(path); err != nil {
		t.Fatalf("first writer: %v", err)
	}

	// `second` still believes the file holds only "a".
	second.Accounts = append(second.Accounts, acc("c"))
	err = second.Save(path)
	if !errors.Is(err, m.ErrVaultChanged) {
		t.Fatalf("stale write returned %v, want ErrVaultChanged", err)
	}

	// The first writer's account must still be there, and nothing of the
	// second's may have landed.
	got, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.FindIndexByID("b") < 0 {
		t.Error("the first writer's account was lost")
	}
	if got.FindIndexByID("c") >= 0 {
		t.Error("the refused write landed anyway")
	}
	if len(got.Accounts) != 2 {
		t.Errorf("vault holds %d accounts, want 2", len(got.Accounts))
	}
}

// After a refusal the caller can reload and redo its change.
func TestReloadAfterConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))

	stale, _ := m.LoadStore(path)
	winner, _ := m.LoadStore(path)
	winner.Accounts = append(winner.Accounts, acc("b"))
	if err := winner.Save(path); err != nil {
		t.Fatal(err)
	}

	if err := stale.Save(path); !errors.Is(err, m.ErrVaultChanged) {
		t.Fatalf("want ErrVaultChanged, got %v", err)
	}
	fresh, err := stale.Reload(nil)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Accounts = append(fresh.Accounts, acc("c"))
	if err := fresh.Save(path); err != nil {
		t.Fatalf("save after reload: %v", err)
	}
	got, _ := m.LoadStore(path)
	if len(got.Accounts) != 3 {
		t.Fatalf("vault holds %d accounts, want 3 (a, b, c)", len(got.Accounts))
	}
}

// Force is the escape hatch once the user has chosen to discard the other
// version.
func TestForceSaveOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	stale, _ := m.LoadStore(path)
	other, _ := m.LoadStore(path)
	other.Accounts = append(other.Accounts, acc("b"))
	if err := other.Save(path); err != nil {
		t.Fatal(err)
	}
	stale.Accounts = append(stale.Accounts, acc("c"))
	if err := stale.ForceSaveWithKey(path, nil); err != nil {
		t.Fatalf("force save: %v", err)
	}
	got, _ := m.LoadStore(path)
	if got.FindIndexByID("b") >= 0 {
		t.Error("force save did not replace the other version")
	}
	if got.FindIndexByID("c") < 0 {
		t.Error("force save did not write our version")
	}
	// A forced save re-anchors the store, so the next ordinary save works.
	stale.Accounts = append(stale.Accounts, acc("d"))
	if err := stale.Save(path); err != nil {
		t.Errorf("save after a forced save: %v", err)
	}
}

// Repeated saves from one owner must keep working: each save re-anchors the
// store to what it just wrote.
func TestRepeatedSavesFromOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := m.LoadStore(path) // vault does not exist yet
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		s.Accounts = append(s.Accounts, acc(string(rune('a'+i))))
		if err := s.Save(path); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	got, _ := m.LoadStore(path)
	if len(got.Accounts) != 5 {
		t.Errorf("vault holds %d accounts, want 5", len(got.Accounts))
	}
}

// A vault created by somebody else between our read and our first write must
// not be silently replaced.
func TestVaultCreatedUnderneathUs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := m.LoadStore(path) // nothing there yet
	if err != nil {
		t.Fatal(err)
	}
	seedVault(t, path, acc("theirs"))
	s.Accounts = append(s.Accounts, acc("ours"))
	if err := s.Save(path); !errors.Is(err, m.ErrVaultChanged) {
		t.Fatalf("want ErrVaultChanged, got %v", err)
	}
	got, _ := m.LoadStore(path)
	if got.FindIndexByID("theirs") < 0 {
		t.Error("the other writer's vault was destroyed")
	}
}

func TestDeletedVaultIsNoticed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	s, _ := m.LoadStore(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	err := s.Save(path)
	if !errors.Is(err, m.ErrVaultChanged) {
		t.Fatalf("want ErrVaultChanged, got %v", err)
	}
}

// A store built in memory is a deliberate "write this here", not an update of
// something we read, so it is not subject to the check.
func TestInMemoryStoreWritesFreely(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	fresh := &m.Store{Accounts: []m.Account{acc("b")}}
	if err := fresh.Save(path); err != nil {
		t.Fatalf("in-memory store refused to write: %v", err)
	}
}

// Saving a loaded store to a *different* path is a copy, not an update.
func TestSaveToAnotherPathIsAllowed(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.json")
	dst := filepath.Join(dir, "b.json")
	seedVault(t, src, acc("a"))
	seedVault(t, dst, acc("other"))
	s, _ := m.LoadStore(src)
	if err := s.Save(dst); err != nil {
		t.Fatalf("copying to another path was refused: %v", err)
	}
}

// Encrypted vaults get the same protection; the fingerprint is of the
// envelope, which is what a later read sees.
func TestStaleWriteRefusedWhenEncrypted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	if err := (&m.Store{Accounts: []m.Account{acc("a")}}).SaveWithPass(path, "pw"); err != nil {
		t.Fatal(err)
	}
	stale, k1, err := m.OpenVaultFile(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer k1.Zero()
	winner, k2, err := m.OpenVaultFile(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer k2.Zero()

	winner.Accounts = append(winner.Accounts, acc("b"))
	if err := winner.SaveWithKey(path, k2); err != nil {
		t.Fatal(err)
	}
	stale.Accounts = append(stale.Accounts, acc("c"))
	if err := stale.SaveWithKey(path, k1); !errors.Is(err, m.ErrVaultChanged) {
		t.Fatalf("want ErrVaultChanged, got %v", err)
	}
	got, k3, err := m.OpenVaultFile(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer k3.Zero()
	if got.FindIndexByID("b") < 0 || got.FindIndexByID("c") >= 0 {
		t.Errorf("encrypted vault lost an update: %+v", got.Accounts)
	}
}

// Concurrent writers must not interleave: every one either writes cleanly or
// is told the vault moved. None may silently vanish.
func TestConcurrentWritersNeverLoseSilently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("base"))

	const writers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := map[string]bool{}

	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := m.LoadStore(path)
			if err != nil {
				return
			}
			id := string(rune('a' + i))
			s.Accounts = append(s.Accounts, acc(id))
			if err := s.Save(path); err == nil {
				mu.Lock()
				succeeded[id] = true
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	got, err := m.LoadStore(path)
	if err != nil {
		t.Fatalf("vault is unreadable after concurrent writes: %v", err)
	}
	if got.FindIndexByID("base") < 0 {
		t.Error("the original account was lost")
	}
	// Every writer that was told it succeeded must be in the file.
	for id := range succeeded {
		if got.FindIndexByID(id) < 0 {
			t.Errorf("writer %q was told it succeeded but is not in the vault", id)
		}
	}
	if len(succeeded) == 0 {
		t.Error("no writer succeeded at all")
	}
	t.Logf("%d of %d writers committed; the rest were refused", len(succeeded), writers)
}
