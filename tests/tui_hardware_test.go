package test

import (
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gdamore/tcell/v2"

	"github.com/nexusriot/tpduck/internal/controller"
	m "github.com/nexusriot/tpduck/internal/model"
)

// sealedHarness seeds a vault bound to a token and drives the real TUI against
// it, with `respond` standing in for the key. asked counts the touches.
func sealedHarness(t *testing.T, passphrase, sealSecret, respondSecret string, slot int) (*harness, *int32) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := &m.Store{Accounts: sample()}
	key, err := m.NewHardwareKey(m.Unlock{Passphrase: passphrase, Hardware: token(sealSecret)}, slot)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveWithKey(path, key); err != nil {
		t.Fatal(err)
	}
	key.Zero()

	var asked int32
	opts := controller.Options{
		Path: path,
		Hardware: func(gotSlot int) m.HardwareResponder {
			if gotSlot != slot {
				t.Errorf("the controller asked for slot %d, want %d", gotSlot, slot)
			}
			return func(challenge []byte) ([]byte, error) {
				atomic.AddInt32(&asked, 1)
				return token(respondSecret)(challenge)
			}
		},
	}
	return newHarnessOpts(t, nil, opts), &asked
}

// A vault whose only factor is the key must open with nothing typed: there is
// no passphrase, so prompting for one would be asking a question with no
// answer.
func TestTUIOpensAKeyOnlyVault(t *testing.T) {
	h, asked := sealedHarness(t, "", "the-token", "the-token", 2)
	h.waitFor("unlocking from the key alone", "Acme")
	if n := atomic.LoadInt32(asked); n != 1 {
		t.Errorf("the key was asked %d times, want 1", n)
	}
	if screen := h.text(); strings.Contains(screen, "Passphrase") {
		t.Errorf("a key-only vault asked for a passphrase:\n%s", screen)
	}
}

// With both factors the passphrase is still asked for, and the key is used
// alongside it.
func TestTUIOpensAVaultWithBothFactors(t *testing.T) {
	h, asked := sealedHarness(t, "hunter2", "the-token", "the-token", 1)
	screen := h.waitFor("the unlock prompt", "Passphrase")
	if !strings.Contains(screen, "slot 1") {
		t.Errorf("the prompt does not say a key is needed:\n%s", screen)
	}
	h.typeStr("hunter2")
	h.key(tcell.KeyTab) // onto OK
	h.key(tcell.KeyEnter)
	h.waitFor("unlocking with the passphrase and the key", "Acme")
	if n := atomic.LoadInt32(asked); n != 1 {
		t.Errorf("the key was asked %d times, want 1", n)
	}
}

// The wrong key must be refused and must leave a way to try again rather than
// a dead screen -- there is no form to put back up when nothing was typed.
func TestTUIRefusesTheWrongKey(t *testing.T) {
	h, _ := sealedHarness(t, "", "the-token", "a-different-token", 2)
	screen := h.waitFor("the failure", "Try again")
	if strings.Contains(screen, "Acme") {
		t.Errorf("the wrong key opened the vault:\n%s", screen)
	}
}

// A wrong passphrase on a sealed vault puts the form back, as it does for an
// ordinary one.
func TestTUIRefusesTheWrongPassphraseOnASealedVault(t *testing.T) {
	h, _ := sealedHarness(t, "hunter2", "the-token", "the-token", 2)
	h.waitFor("the unlock prompt", "Passphrase")
	h.typeStr("wrong")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("the rejection", "try again")
	if strings.Contains(h.text(), "Acme") {
		t.Error("the wrong passphrase opened the vault")
	}
	// And the form is usable again.
	h.typeStr("hunter2")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("retrying with the right passphrase", "Acme")
}

// Changing the passphrase must keep the vault sealed to the key. Deriving a
// plain key here would quietly drop the hardware factor and leave a vault that
// a copied file plus a guessed passphrase would open.
func TestTUIPassphraseChangeKeepsTheHardwareBinding(t *testing.T) {
	h, asked := sealedHarness(t, "hunter2", "the-token", "the-token", 2)
	h.waitFor("the unlock prompt", "Passphrase")
	h.typeStr("hunter2")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("unlocking", "Acme")

	h.typeStr("p") // change the passphrase
	h.waitFor("the change-passphrase form", "Change passphrase")
	h.typeStr("newpass")
	h.key(tcell.KeyTab)
	h.typeStr("newpass")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("the change landing", "passphrase changed")

	if hw := m.VaultHardware(h.path); !hw.Needed || hw.Slot != 2 {
		t.Fatalf("after changing the passphrase the vault reports %+v", hw)
	}
	if n := atomic.LoadInt32(asked); n != 2 {
		t.Errorf("the key was asked %d times; once to open and once to re-seal", n)
	}
	// The new passphrase and the key together open it; neither alone does.
	if _, _, err := m.OpenVaultFileUnlocked(h.path,
		m.Unlock{Passphrase: "newpass", Hardware: token("the-token")}); err != nil {
		t.Errorf("the re-sealed vault does not open with the new passphrase: %v", err)
	}
	if _, _, err := m.OpenVaultFile(h.path, "newpass"); err == nil {
		t.Error("the re-sealed vault opened without the key")
	}
}

// Removing encryption from a sealed vault must take the key binding off with
// it, not leave a plaintext file that still claims to need hardware.
func TestTUIDecryptDropsTheHardwareBinding(t *testing.T) {
	h, _ := sealedHarness(t, "", "the-token", "the-token", 2)
	h.waitFor("unlocking from the key alone", "Acme")

	h.typeStr("p")
	h.waitFor("the change-passphrase form", "Change passphrase")
	h.key(tcell.KeyTab) // leave both fields empty
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	h.waitFor("the confirmation", "Remove encryption")
	h.key(tcell.KeyEnter) // "Remove" is the default button
	h.waitFor("the removal", "plaintext")

	if hw := m.VaultHardware(h.path); hw.Needed {
		t.Errorf("the decrypted vault still reports %+v", hw)
	}
	store, err := m.LoadStore(h.path)
	if err != nil {
		t.Fatalf("the decrypted vault does not read back: %v", err)
	}
	if len(store.Accounts) != len(sample()) {
		t.Errorf("the decrypted vault holds %d accounts, want %d", len(store.Accounts), len(sample()))
	}
}

// A build that cannot reach a key must say so rather than deriving a plain key
// and silently unsealing the vault.
func TestTUIWithoutSmartCardSupport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	store := &m.Store{Accounts: sample()}
	key, err := m.NewHardwareKey(m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveWithKey(path, key); err != nil {
		t.Fatal(err)
	}
	key.Zero()

	// Options.Hardware is nil, as it is in a build with no PC/SC transport.
	h := newHarnessOpts(t, nil, controller.Options{Path: path})
	h.waitFor("the unlock prompt", "Passphrase")
	h.typeStr("hunter2")
	h.key(tcell.KeyTab)
	h.key(tcell.KeyEnter)
	screen := h.waitFor("the refusal", "YubiKey")
	if strings.Contains(screen, "Acme") {
		t.Errorf("a sealed vault opened without any key:\n%s", screen)
	}
}
