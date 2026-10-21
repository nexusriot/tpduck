package test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/nexusriot/tpduck/internal/controller"
	m "github.com/nexusriot/tpduck/internal/model"
)

// Taking a code rewrites the vault, to record that it was used. When every
// write rotated the retained copies, five code reads -- one afternoon -- spent
// the whole history on identical snapshots, and `tpduck undo` could no longer
// reach the deletion it exists for.
func TestReadingCodesDoesNotSpendTheUndoHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("keepme"), acc("other"))

	// Delete one account, the way `tpduck rm` does.
	s, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Accounts = s.Accounts[1:]
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}

	// Then use the survivor a few more times than there are retained copies.
	for i := 0; i < m.KeptVersions+3; i++ {
		s, err := m.LoadStore(path)
		if err != nil {
			t.Fatal(err)
		}
		s.MarkUsed("other")
		if err := s.Save(path); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	if err := m.RestoreVersion(path, 1); err != nil {
		t.Fatal(err)
	}
	restored, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if restored.FindIndexByID("keepme") < 0 {
		t.Error("undo could not reach the deletion: reading codes pushed it out of the history")
	}
}

// ...but the usage really is written down, or `order used` would be a lie.
func TestMarkUsedIsStillPersisted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	s, _ := m.LoadStore(path)
	s.MarkUsed("a")
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := m.LoadStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.Accounts[0].LastUsedAt == 0 {
		t.Error("last-used was not written to disk")
	}
}

// A change to the accounts themselves must still be kept.
func TestRealEditStillRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	for _, name := range []string{"b", "c"} {
		s, _ := m.LoadStore(path)
		s.Accounts = append(s.Accounts, acc(name))
		if err := s.Save(path); err != nil {
			t.Fatal(err)
		}
	}
	versions, err := m.Versions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 {
		t.Fatalf("kept %d versions after two edits, want 2", len(versions))
	}
	prev, err := m.LoadStore(versions[0].Path)
	if err != nil {
		t.Fatal(err)
	}
	if len(prev.Accounts) != 2 {
		t.Errorf("version 1 holds %d accounts, want the 2 from before the last edit", len(prev.Accounts))
	}
}

// Tags, notes and pinning are typed by hand and nowhere else, so they count as
// material even though no code depends on them.
func TestTagChangeRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("a"))
	s, _ := m.LoadStore(path)
	if err := s.SetTags("a", []string{"work"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	versions, err := m.Versions(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 1 {
		t.Fatalf("kept %d versions after setting a tag, want 1", len(versions))
	}
}

// Steam Guard is time-based, so an import that leaves the period out must get
// the default rather than being rejected for having a period of zero.
func TestSteamImportFromAndOTPWithoutPeriod(t *testing.T) {
	data := []byte(`[{"secret":"JBSWY3DPEHPK3PXP","label":"steamacct",` +
		`"issuer":"Steam","type":"STEAM","algorithm":"SHA1","digits":5}]`)
	accounts, format, err := m.ParseBackup(data)
	if err != nil {
		t.Fatalf("a Steam entry with no period was refused: %v", err)
	}
	if format != "andOTP" {
		t.Errorf("recognised as %q, want andOTP", format)
	}
	if len(accounts) != 1 {
		t.Fatalf("got %d accounts, want 1", len(accounts))
	}
	got := accounts[0]
	if got.Period != m.DefaultPeriod {
		t.Errorf("period is %d, want the default %d", got.Period, m.DefaultPeriod)
	}
	if got.Kind() != m.TypeSteam || got.Digits != m.SteamDigits {
		t.Errorf("got %s/%d digits, want steam/%d", got.Kind(), got.Digits, m.SteamDigits)
	}
	code, err := m.Generate(got, time.Now())
	if err != nil {
		t.Fatalf("the imported account cannot produce a code: %v", err)
	}
	if len(code.Value) != m.SteamDigits {
		t.Errorf("code %q is %d characters, want %d", code.Value, len(code.Value), m.SteamDigits)
	}
}

// The migration protobuf has no Steam Guard, and the encoder used to write one
// out as a six-digit TOTP -- an account that imports cleanly and then produces
// codes Steam will never accept.
func TestMigrationExportSkipsSteam(t *testing.T) {
	accounts := []m.Account{
		{Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{Issuer: "Steam", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 5, Period: 30, Algo: m.AlgoSHA1, Type: m.TypeSteam},
	}
	uris, skipped, err := m.BuildMigrationURIs(accounts, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(skipped) != 1 || skipped[0].Name != "bob" {
		t.Fatalf("skipped %+v, want just the Steam account", skipped)
	}
	got, err := m.ParseMigrationURI(uris[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "alice" {
		t.Errorf("exported %+v, want only the TOTP account", got)
	}
}

// Exporting nothing but Steam accounts is an error with a reason, not an empty
// QR code.
func TestMigrationExportOfOnlySteamExplainsItself(t *testing.T) {
	accounts := []m.Account{
		{Issuer: "Steam", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 5, Period: 30, Algo: m.AlgoSHA1, Type: m.TypeSteam},
	}
	_, skipped, err := m.BuildMigrationURIs(accounts, 0)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "Steam") {
		t.Errorf("error %q does not say why", err)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped %d accounts, want 1", len(skipped))
	}
}

// An account whose period never got set must still export to a URI that can be
// read back; "period=0" is rejected by every reader, including ours.
func TestURIWithNoPeriodStillReimports(t *testing.T) {
	a := m.Account{Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Algo: m.AlgoSHA1}
	back, err := m.ParseOtpauthURI(a.URI())
	if err != nil {
		t.Fatalf("our own URI does not re-import: %v (%s)", err, a.URI())
	}
	if back.Period != m.DefaultPeriod || back.Digits != m.DefaultDigits {
		t.Errorf("got %d digits / %ds, want the defaults", back.Digits, back.Period)
	}
}

// The vault is written on every save, so a conflict dialog can appear while a
// form is still up. Restoring the root view after the save -- which is what
// every handler used to do -- took that dialog away before it could be read,
// so the user never saw the choice and the write was simply lost.
func TestConflictDialogSurvivesAnImport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	seedVault(t, path, acc("acme"))
	h := newHarnessOpts(t, nil, controller.Options{Path: path})

	// Something else writes to the vault while the UI is up.
	seedVault(t, path, acc("acme"), acc("written-by-someone-else"))

	h.typeStr("i")
	h.waitFor("opening the import form", "Import")
	h.typeStr("otpauth://totp/Discord:carol?secret=JBSWY3DPEHPK3PXP")
	h.key(tcell.KeyTab)   // onto the Import button
	h.key(tcell.KeyEnter) // and submit

	screen := h.waitFor("saving over a vault somebody else changed", "changed on disk")
	if !strings.Contains(screen, "Overwrite") {
		t.Errorf("the conflict dialog offers no choice:\n%s", screen)
	}
	if strings.Contains(screen, "imported 1 account") {
		t.Error("the UI claimed the import was saved while the conflict was still unresolved")
	}
}
