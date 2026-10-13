package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

func TestVersionsRotate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// Each save keeps the previous state.
	for i := 0; i < 8; i++ {
		s.Accounts = append(s.Accounts, acc(string(rune('a'+i))))
		if err := s.Save(path); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	versions, err := m.Versions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != m.KeptVersions {
		t.Fatalf("kept %d versions, want %d", len(versions), m.KeptVersions)
	}
	// Version 1 is the most recent previous state: seven accounts, not eight.
	prev, err := m.LoadStore(versions[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Accounts) != 7 {
		t.Errorf("version 1 holds %d accounts, want 7", len(prev.Accounts))
	}
	// And they get older as the number rises.
	oldest, err := m.LoadStore(versions[len(versions)-1].Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(oldest.Accounts) >= len(prev.Accounts) {
		t.Errorf("version %d is not older than version 1 (%d vs %d accounts)",
			versions[len(versions)-1].N, len(oldest.Accounts), len(prev.Accounts))
	}
}

// Deleting an account must be recoverable, which is the whole point.
func TestUndoRecoversADeletedAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, _ := m.LoadStore(path)
	s.Accounts = append(s.Accounts, acc("keepme"), acc("other"))
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	// Delete one and save.
	s.Accounts = s.Accounts[1:]
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	after, _ := m.LoadStore(path)
	if after.FindIndexByID("keepme") >= 0 {
		t.Fatal("test setup: the account was not deleted")
	}
	if err := m.RestoreVersion(path, 1); err != nil {
		t.Fatal(err)
	}
	restored, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.FindIndexByID("keepme") < 0 {
		t.Error("undo did not bring the deleted account back")
	}
	// The restore itself is undoable.
	if err := m.RestoreVersion(path, 1); err != nil {
		t.Fatal(err)
	}
	again, _ := m.LoadStore(path)
	if again.FindIndexByID("keepme") >= 0 {
		t.Error("undoing the undo did not take")
	}
}

func TestRestoreVersionErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	if err := m.RestoreVersion(path, 0); err == nil {
		t.Error("version 0 accepted")
	}
	if err := m.RestoreVersion(path, 99); err == nil {
		t.Error("version 99 accepted")
	}
	if err := m.RestoreVersion(path, 3); err == nil {
		t.Error("restored a version that does not exist")
	}
}

func TestPruneVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s, _ := m.LoadStore(path)
	for i := 0; i < 3; i++ {
		s.Accounts = append(s.Accounts, acc(string(rune('a'+i))))
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
	}
	if v, _ := m.Versions(path); len(v) == 0 {
		t.Fatal("no versions to prune")
	}
	if err := m.PruneVersions(path); err != nil {
		t.Fatal(err)
	}
	if v, _ := m.Versions(path); len(v) != 0 {
		t.Errorf("%d versions survived the prune", len(v))
	}
	// The live vault is untouched.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("prune removed the vault: %v", err)
	}
}

// An encrypted vault's retained copies stay encrypted.
func TestVersionsOfEncryptedVault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := &m.Store{Accounts: []m.Account{acc("a")}}
	if err := s.SaveWithPass(path, "pw"); err != nil {
		t.Fatal(err)
	}
	live, key, err := m.OpenVaultFile(path, "pw")
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	live.Accounts = append(live.Accounts, acc("b"))
	if err := live.SaveWithKey(path, key); err != nil {
		t.Fatal(err)
	}
	versions, _ := m.Versions(path)
	if len(versions) == 0 {
		t.Fatal("no retained versions")
	}
	if !versions[0].Encrypted {
		t.Error("a retained copy of an encrypted vault is not encrypted")
	}
	data, _ := os.ReadFile(versions[0].Path)
	if strings.Contains(string(data), "JBSWY3DPEHPK3PXP") {
		t.Error("retained copy leaks the secret")
	}
}

func TestIsVersionFile(t *testing.T) {
	vault := "/tmp/accounts.json"
	for _, name := range []string{"accounts.json.1", "accounts.json.5"} {
		if !m.IsVersionFile(vault, name) {
			t.Errorf("%s not recognised as a version file", name)
		}
	}
	for _, name := range []string{"accounts.json", "accounts.json.lock", "accounts.json.9", "other.json.1"} {
		if m.IsVersionFile(vault, name) {
			t.Errorf("%s wrongly recognised as a version file", name)
		}
	}
}

// --- profiles ---

func TestProfilePaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)

	def, err := m.ProfilePath("")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(def) != "accounts.json" {
		t.Errorf("default profile is %s", def)
	}
	work, err := m.ProfilePath("work")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(work, filepath.Join("tpduck", "profiles", "work.json")) {
		t.Errorf("work profile is %s", work)
	}
	if work == def {
		t.Error("a named profile shares the default vault")
	}
}

// A profile name must not be able to escape its directory.
func TestProfileNameValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	// An empty name is not invalid -- it means the default vault, checked above.
	for _, bad := range []string{"../escape", "a/b", `a\b`, ".hidden", "with space", "   ", "sem;colon"} {
		if p, err := m.ProfilePath(bad); err == nil {
			t.Errorf("accepted profile name %q -> %s", bad, p)
		}
	}
	for _, good := range []string{"work", "Personal", "test-1", "a_b"} {
		if _, err := m.ProfilePath(good); err != nil {
			t.Errorf("rejected profile name %q: %v", good, err)
		}
	}
}

func TestListProfiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", home)

	def, _ := m.ProfilePath("")
	seedVault(t, def, acc("a"), acc("b"))
	work, _ := m.ProfilePath("work")
	seedVault(t, work, acc("c"))
	enc, _ := m.ProfilePath("secret")
	if err := (&m.Store{Accounts: []m.Account{acc("d")}}).SaveWithPass(enc, "pw"); err != nil {
		t.Fatal(err)
	}

	profiles, err := m.ListProfiles()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]m.Profile{}
	for _, p := range profiles {
		byName[p.Name] = p
	}
	if got := byName["(default)"]; got.Accounts != 2 {
		t.Errorf("default profile reports %d accounts, want 2", got.Accounts)
	}
	if got := byName["work"]; got.Accounts != 1 {
		t.Errorf("work profile reports %d accounts, want 1", got.Accounts)
	}
	if got := byName["secret"]; !got.Encrypted {
		t.Error("encrypted profile not reported as encrypted")
	}
	if got := byName["secret"]; got.Accounts != 0 {
		t.Error("an encrypted profile should not report a count without the passphrase")
	}
}
