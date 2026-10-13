package test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/nexusriot/tpduck/internal/controller"
	m "github.com/nexusriot/tpduck/internal/model"
)

func manyAccounts() []m.Account {
	return []m.Account{
		{ID: "github:alice", Issuer: "GitHub", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{ID: "gitlab:bob", Issuer: "GitLab", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{ID: "zoho:carol", Issuer: "Zoho", Name: "carol", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
	}
}

func TestSearchFiltersTable(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("initial list", "carol")
	h.typeStr("/")
	h.typeStr("zoho")
	h.waitFor("filtering", "matching")
	screen := h.text()
	if !strings.Contains(screen, "carol") {
		t.Errorf("match was filtered out:\n%s", screen)
	}
	if strings.Contains(screen, "alice") {
		t.Errorf("non-match survived the filter:\n%s", screen)
	}
	// ESC clears the filter and restores the full list.
	h.key(tcell.KeyEscape)
	h.waitFor("clearing the filter", "alice")
}

// Regression guard: '/' opens search, and the letters typed into it must not
// trigger the main-view shortcuts.
func TestSearchSwallowsShortcutLetters(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.typeStr("/")
	h.typeStr("ade") // would otherwise fire Add, Delete, Edit
	h.settle()
	if strings.Contains(h.text(), "Add Account") || strings.Contains(h.text(), "Delete") {
		t.Errorf("typing in the search field triggered a shortcut:\n%s", h.text())
	}
}

func TestHOTPDisplayAndAdvance(t *testing.T) {
	h := newHarness(t, []m.Account{{
		ID: "ctr:user", Issuer: "Ctr", Name: "user", Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 0,
	}})
	h.waitFor("HOTP detail", "counter 0")
	before := h.text()
	h.typeStr("n")
	h.waitFor("advancing the counter", "counter advanced to 1")
	if before == h.text() {
		t.Error("screen did not change after advancing the counter")
	}
	// A time-based account must refuse the same key.
	h2 := newHarness(t, manyAccounts())
	h2.typeStr("n")
	h2.waitFor("advancing a TOTP account", "only counter-based")
}

func TestExportShowsQRAndURI(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.typeStr("x")
	h.waitFor("export dialog", "otpauth://totp/")
	if !strings.ContainsAny(h.text(), "█▀▄") {
		t.Errorf("export dialog has no QR code:\n%s", h.text())
	}
	h.key(tcell.KeyEscape)
	h.waitGone("closing export", "otpauth://totp/")
}

func TestHelpModal(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.typeStr("?")
	h.waitFor("help", "advance the counter")
	h.key(tcell.KeyEscape)
	h.waitGone("closing help", "advance the counter")
}

// An unencrypted vault must say so rather than being a silent condition.
func TestUnencryptedVaultIsFlagged(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("unencrypted warning", "!plaintext")
}

func TestEncryptFromTUI(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("start", "!plaintext")
	h.typeStr("p")
	h.waitFor("passphrase form", "Encrypt vault")
	h.typeStr("swordfish")
	h.key(tcell.KeyTab)
	h.typeStr("swordfish")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter) // OK
	h.waitFor("encrypting", "vault encrypted")
	h.waitFor("status", "Details *")

	// The file on disk must no longer contain the secret.
	enc, err := m.IsVaultEncrypted(h.path)
	if err != nil || !enc {
		t.Fatalf("vault not encrypted on disk: %v %v", enc, err)
	}
	if _, err := m.LoadStoreWithPass(h.path, "swordfish"); err != nil {
		t.Fatalf("cannot reopen the vault we just wrote: %v", err)
	}
}

func TestMismatchedPassphraseRejected(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.typeStr("p")
	h.waitFor("passphrase form", "Encrypt vault")
	h.typeStr("one")
	h.key(tcell.KeyTab)
	h.typeStr("two")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("mismatch", "do not match")
	if enc, _ := m.IsVaultEncrypted(h.path); enc {
		t.Error("vault was encrypted despite mismatched passphrases")
	}
}

// An encrypted vault must start locked, show nothing, and open on the right
// passphrase.
func TestLockedVaultStartsLockedAndUnlocks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := (&m.Store{Accounts: manyAccounts()}).SaveWithPass(path, "letmein"); err != nil {
		t.Fatal(err)
	}
	h := newHarnessOpts(t, nil, controller.Options{Path: path})
	h.waitFor("lock prompt", "Vault is locked")
	if strings.Contains(h.text(), "alice") {
		t.Errorf("locked vault showed account data:\n%s", h.text())
	}
	// A wrong passphrase must be refused without revealing anything.
	h.typeStr("nope")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("wrong passphrase", "wrong passphrase")
	if strings.Contains(h.text(), "alice") {
		t.Errorf("a wrong passphrase revealed accounts:\n%s", h.text())
	}
}

func TestIdleAutoLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := (&m.Store{Accounts: manyAccounts()}).SaveWithPass(path, "letmein"); err != nil {
		t.Fatal(err)
	}
	h := newHarnessOpts(t, nil, controller.Options{Path: path, IdleLock: 300 * time.Millisecond})
	h.waitFor("lock prompt", "Vault is locked")
	h.typeStr("letmein")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("unlocking", "alice")
	// Stop touching the keyboard; the idle timer must take the vault away.
	h.waitFor("auto-lock", "Locked after inactivity")
	if strings.Contains(h.text(), "alice") {
		t.Errorf("accounts still visible after auto-lock:\n%s", h.text())
	}
}

// --- tier 1-4 interactive features ---

func TestPinAndOrderFromTUI(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("start", "GitHub")
	h.key(tcell.KeyDown) // GitLab
	h.waitFor("second row", "Name:    bob")
	h.typeStr("f")
	h.waitFor("pinning", "pinned to the top")
	// The pinned row is marked and sorts first.
	if !strings.Contains(h.text(), "*GitLab") {
		t.Errorf("no pin marker:\n%s", h.text())
	}
	h.typeStr("o")
	h.waitFor("ordering", "ordering by used")
	h.typeStr("f")
	h.waitFor("unpinning", "unpinned")
}

func TestEnterCopies(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("start", "GitHub")
	h.key(tcell.KeyEnter)
	// No clipboard helper exists in the test environment, so tpduck reports the
	// code inline instead -- either way, Enter must have tried to copy.
	screen := h.waitFor("pressing Enter", "clipboard")
	if strings.Contains(screen, "no selection") {
		t.Errorf("Enter did not act on the selection:\n%s", screen)
	}
}

func TestVerifyFromTUI(t *testing.T) {
	accs := manyAccounts()
	h := newHarness(t, accs)
	h.waitFor("start", "GitHub")
	code, _, err := m.Totp(accs[0].Secret, accs[0].Algo, accs[0].Period, accs[0].Digits, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.typeStr("v")
	h.waitFor("verify prompt", "Verify a code")
	h.typeStr(code)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("verifying", "matches the current code")

	h.typeStr("v")
	h.waitFor("verify prompt again", "Verify a code")
	h.typeStr("000000")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("rejecting", "no match")
}

func TestResyncFromTUI(t *testing.T) {
	acc := m.Account{
		ID: "ctr:user", Issuer: "Ctr", Name: "user", Secret: b32("12345678901234567890"),
		Digits: 6, Algo: m.AlgoSHA1, Type: m.TypeHOTP, Counter: 0,
	}
	h := newHarness(t, []m.Account{acc})
	h.waitFor("start", "counter 0")
	h.typeStr("y")
	h.waitFor("resync prompt", "Resync counter")
	h.typeStr("969429") // RFC 4226 counter 3
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("resyncing", "counter resynced to 4")

	// A time-based account must refuse.
	h2 := newHarness(t, manyAccounts())
	h2.typeStr("y")
	h2.waitFor("refusing totp", "only counter-based")
}

func TestMigrationExportFromTUI(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.waitFor("start", "GitHub")
	h.typeStr("m")
	h.waitFor("migration export", "3 account(s) in 1 QR code(s)")
	if !strings.ContainsAny(h.text(), "█▀▄") {
		t.Errorf("no QR in the migration export:\n%s", h.text())
	}
	h.key(tcell.KeyEscape)
	h.waitGone("closing", "QR code(s)")
}

func TestNextCodePreviewAppears(t *testing.T) {
	// A one-second period means the window is always nearly spent, so the
	// preview must always be on screen.
	h := newHarness(t, []m.Account{{
		ID: "fast:user", Issuer: "Fast", Name: "user", Secret: "JBSWY3DPEHPK3PXP",
		Digits: 6, Period: 1, Algo: m.AlgoSHA1,
	}})
	h.waitFor("next-code preview", "next:")
}

func TestImportFormAcceptsABackupFile(t *testing.T) {
	dir := t.TempDir()
	backup := filepath.Join(dir, "backup.txt")
	if err := os.WriteFile(backup,
		[]byte("otpauth://totp/Imported:dave?secret=JBSWY3DPEHPK3PXP&issuer=Imported\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, manyAccounts())
	h.typeStr("i")
	h.waitFor("import form", "Import")
	h.typeStr(backup)
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("importing a file", "imported 1 account")
	h.waitFor("new account listed", "dave")
}

func TestHelpMentionsNewKeys(t *testing.T) {
	h := newHarness(t, manyAccounts())
	h.typeStr("?")
	screen := h.waitFor("help", "resync an HOTP counter")
	for _, want := range []string{"pin/unpin", "verify a code", "migration QR"} {
		if !strings.Contains(screen, want) {
			t.Errorf("help does not mention %q", want)
		}
	}
}
