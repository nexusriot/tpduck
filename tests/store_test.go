package test

import (
	"os"
	"path/filepath"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	s := &m.Store{Accounts: []m.Account{
		{ID: "b:2", Issuer: "B", Name: "2", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{ID: "a:1", Issuer: "A", Name: "1", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
	}}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("vault mode = %v, want 0600", fi.Mode().Perm())
	}
	// The temp file written before the rename must not survive. The lock file
	// is expected and is deliberately left in place.
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		switch name := e.Name(); {
		case name == "accounts.json", name == "accounts.json.lock":
		case m.IsVersionFile(path, name):
		default:
			t.Errorf("save left %q behind", name)
		}
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Errorf("no lock file was created: %v", err)
	}
	if s.Accounts[0].Issuer != "A" {
		t.Error("Save did not sort accounts")
	}
}

func TestUniqueIDPreventsCollisions(t *testing.T) {
	s := &m.Store{Accounts: []m.Account{{ID: "github:me"}, {ID: "github:me#2"}}}
	if got := s.UniqueID("github:me", -1); got != "github:me#3" {
		t.Errorf("UniqueID = %q, want github:me#3", got)
	}
	// Editing an account in place must be allowed to keep its own ID.
	if got := s.UniqueID("github:me", 0); got != "github:me" {
		t.Errorf("UniqueID(except=0) = %q, want github:me", got)
	}
}

func TestValidate(t *testing.T) {
	ok := m.Account{Name: "me", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid account rejected: %v", err)
	}
	bad := map[string]func(a *m.Account){
		"empty name":   func(a *m.Account) { a.Name = "  " },
		"empty secret": func(a *m.Account) { a.Secret = "" },
		"bad secret":   func(a *m.Account) { a.Secret = "11111111" },
		"digits 7":     func(a *m.Account) { a.Digits = 7 },
		"period 0":     func(a *m.Account) { a.Period = 0 },
		"period huge":  func(a *m.Account) { a.Period = 99999 },
		"bad algo":     func(a *m.Account) { a.Algo = m.Algo("MD5") },
	}
	for name, mutate := range bad {
		a := ok
		mutate(&a)
		if err := a.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadStoreMissingFile(t *testing.T) {
	s := &m.Store{}
	if err := s.Save(filepath.Join(t.TempDir(), "x.json")); err != nil {
		t.Fatalf("saving an empty store failed: %v", err)
	}
}

// The config directory was renamed from "totp-tui" to "tpduck". An existing
// install must not silently come up with an empty vault.
func TestLegacyConfigDirMigrated(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)

	legacyDir := filepath.Join(home, "totp-tui")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	old := &m.Store{Accounts: []m.Account{{
		ID: "legacy:user", Issuer: "Legacy", Name: "user",
		Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1,
	}}}
	legacyPath := filepath.Join(legacyDir, "accounts.json")
	if err := old.Save(legacyPath); err != nil {
		t.Fatal(err)
	}

	path, err := m.DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(filepath.Dir(path)) != "tpduck" {
		t.Fatalf("config path is not under tpduck: %s", path)
	}
	got, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Accounts) != 1 || got.Accounts[0].ID != "legacy:user" {
		t.Fatalf("legacy vault was not carried over: %+v", got.Accounts)
	}
	// The original must survive, so a failed migration cannot lose the vault.
	if _, err := os.Stat(legacyPath); err != nil {
		t.Errorf("legacy vault was removed: %v", err)
	}
	// The migrated copy must keep owner-only permissions.
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("migrated vault mode = %v, want 0600", fi.Mode().Perm())
	}
}

// Migration must not clobber a vault that already exists under the new name.
func TestLegacyMigrationDoesNotOverwrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)
	for dir, id := range map[string]string{"totp-tui": "old:one", "tpduck": "new:one"} {
		d := filepath.Join(home, dir)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		s := &m.Store{Accounts: []m.Account{{
			ID: id, Name: id, Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1,
		}}}
		if err := s.Save(filepath.Join(d, "accounts.json")); err != nil {
			t.Fatal(err)
		}
	}
	path, err := m.DefaultConfigPath()
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Accounts[0].ID != "new:one" {
		t.Fatalf("migration overwrote the current vault: %+v", got.Accounts)
	}
}
