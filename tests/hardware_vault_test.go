package test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

// token stands in for a YubiKey slot: the same HMAC-SHA1 a real one computes,
// which is all the vault format ever asks of it.
func token(secret string) m.HardwareResponder {
	return func(challenge []byte) ([]byte, error) {
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write(challenge)
		return mac.Sum(nil), nil
	}
}

func sealedVault(t *testing.T, passphrase, secret string, slot int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := &m.Store{Accounts: []m.Account{acc("keepme")}}
	key, err := m.NewHardwareKey(m.Unlock{Passphrase: passphrase, Hardware: token(secret)}, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	if err := s.SaveWithKey(path, key); err != nil {
		t.Fatal(err)
	}
	return path
}

// The whole point: the file alone is not enough.
func TestHardwareVaultNeedsBothFactors(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)

	if raw, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(raw), "JBSWY3DPEHPK3PXP") {
		t.Fatal("the sealed vault leaks its secrets")
	}

	// No token.
	if _, _, err := m.OpenVaultFile(path, "hunter2"); !errors.Is(err, m.ErrHardwareRequired) {
		t.Errorf("without a token: %v, want ErrHardwareRequired", err)
	}
	// A different token.
	if _, _, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: token("another-token")}); err == nil {
		t.Error("a different token opened the vault")
	}
	// Right token, wrong passphrase.
	if _, _, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "wrong", Hardware: token("the-token")}); err == nil {
		t.Error("the wrong passphrase opened the vault")
	}
	// Both.
	store, key, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")})
	if err != nil {
		t.Fatalf("the right token and passphrase failed: %v", err)
	}
	defer key.Zero()
	if store.FindIndexByID("keepme") < 0 {
		t.Error("the vault opened but its accounts are missing")
	}
	if !key.NeedsHardware() || key.HardwareSlot() != 2 {
		t.Errorf("key reports hardware=%v slot=%d", key.NeedsHardware(), key.HardwareSlot())
	}
}

// A vault whose only factor is the token opens with nothing typed, and the
// header says so, so nothing is prompted for.
func TestHardwareOnlyVault(t *testing.T) {
	path := sealedVault(t, "", "the-token", 1)
	hw := m.VaultHardware(path)
	if !hw.Needed || hw.Slot != 1 || !hw.NoPassphrase {
		t.Fatalf("VaultHardware = %+v", hw)
	}
	if _, _, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Hardware: token("the-token")}); err != nil {
		t.Errorf("a key-only vault did not open with the key: %v", err)
	}
	if _, _, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Hardware: token("wrong")}); err == nil {
		t.Error("the wrong key opened it")
	}
}

// A passphrase-only vault must not start demanding hardware.
func TestOrdinaryVaultReportsNoHardware(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := &m.Store{Accounts: []m.Account{acc("a")}}
	if err := s.SaveWithPass(path, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if hw := m.VaultHardware(path); hw.Needed {
		t.Errorf("a passphrase vault reported %+v", hw)
	}
	if _, _, err := m.OpenVaultFile(path, "hunter2"); err != nil {
		t.Errorf("a passphrase vault stopped opening: %v", err)
	}
}

// Stripping the hardware factor out of the header must fail as a forgery, not
// fall back to a passphrase-only vault.
func TestHardwareBindingCannotBeStripped(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	for _, tamper := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"kdf downgraded", func(e map[string]any) { e["kdf"] = "argon2id" }},
		{"challenge swapped", func(e map[string]any) { e["hw_challenge"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ=" }},
		{"slot swapped", func(e map[string]any) { e["hw_slot"] = 1 }},
	} {
		edited := map[string]any{}
		for k, v := range env {
			edited[k] = v
		}
		tamper.edit(edited)
		body, err := json.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(t.TempDir(), "tampered.json")
		if err := os.WriteFile(bad, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := m.OpenVaultFileUnlocked(bad,
			m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")}); err == nil {
			t.Errorf("%s: the tampered vault opened", tamper.name)
		}
	}
}

// Re-sealing with the key already derived must not ask the token again, and
// must keep producing a vault the token opens.
func TestHardwareKeyReusedAcrossSaves(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)
	asked := 0
	counting := func(challenge []byte) ([]byte, error) {
		asked++
		return token("the-token")(challenge)
	}
	store, key, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: counting})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	if asked != 1 {
		t.Fatalf("opening asked the token %d times, want 1", asked)
	}
	store.Accounts = append(store.Accounts, acc("another"))
	for i := 0; i < 3; i++ {
		if err := store.SaveWithKey(path, key); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	if asked != 1 {
		t.Errorf("saving asked the token %d more times; the derived key should be enough", asked-1)
	}
	back, k2, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")})
	if err != nil {
		t.Fatalf("the re-sealed vault no longer opens: %v", err)
	}
	defer k2.Zero()
	if back.FindIndexByID("another") < 0 {
		t.Error("the re-sealed vault lost the new account")
	}
}

// The agent caches a derived key; for a sealed vault that is what turns "touch
// the key for every command" into "touch it once". The binding has to survive
// the round trip or the cached key silently stops matching.
func TestHardwareKeySurvivesTheAgentRoundTrip(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)
	_, key, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := key.Export()
	if err != nil {
		t.Fatal(err)
	}
	key.Zero()

	cached, err := m.ImportKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if !cached.NeedsHardware() || cached.HardwareSlot() != 2 {
		t.Error("the cached key forgot it was bound to hardware")
	}
	if !cached.MatchesVault(path) {
		t.Fatal("the cached key no longer matches the vault it came from")
	}
	store, err := m.LoadStoreWithKey(path, cached)
	if err != nil {
		t.Fatalf("the cached key cannot open the vault: %v", err)
	}
	if store.FindIndexByID("keepme") < 0 {
		t.Error("the cached key opened the vault but the accounts are missing")
	}
	// A cached key from a different vault must be a miss, not a confusing
	// decryption failure.
	other := sealedVault(t, "hunter2", "the-token", 2)
	if cached.MatchesVault(other) {
		t.Error("a key from one sealed vault claimed to match another")
	}
}

func TestHardwareKeyRejectsBadInput(t *testing.T) {
	if _, err := m.NewHardwareKey(m.Unlock{Passphrase: "x"}, 2); !errors.Is(err, m.ErrHardwareRequired) {
		t.Errorf("no responder gave %v, want ErrHardwareRequired", err)
	}
	for _, slot := range []int{0, 3, -1} {
		if _, err := m.NewHardwareKey(m.Unlock{Hardware: token("t")}, slot); err == nil {
			t.Errorf("slot %d was accepted", slot)
		}
	}
	short := func([]byte) ([]byte, error) { return []byte("too short"), nil }
	if _, err := m.NewHardwareKey(m.Unlock{Hardware: short}, 2); err == nil {
		t.Error("a response of the wrong length was accepted")
	}
	boom := func([]byte) ([]byte, error) { return nil, errors.New("key unplugged") }
	if _, err := m.NewHardwareKey(m.Unlock{Hardware: boom}, 2); err == nil ||
		!strings.Contains(err.Error(), "key unplugged") {
		t.Errorf("a token failure gave %v; it should say what went wrong", err)
	}
}

// VaultHardware is consulted before anything is prompted for, so it must be
// quiet and correct about files that are not sealed vaults at all.
func TestVaultHardwareOnEverythingElse(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "plain.json")
	if err := (&m.Store{Accounts: []m.Account{acc("a")}}).Save(plain); err != nil {
		t.Fatal(err)
	}
	encrypted := filepath.Join(dir, "encrypted.json")
	if err := (&m.Store{Accounts: []m.Account{acc("a")}}).SaveWithPass(encrypted, "hunter2"); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.json")
	if err := os.WriteFile(junk, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, path string }{
		{"a missing file", filepath.Join(dir, "nope.json")},
		{"a plaintext vault", plain},
		{"a passphrase-only vault", encrypted},
		{"junk", junk},
		{"an empty file", empty},
		{"a directory", dir},
	} {
		if hw := m.VaultHardware(tc.path); hw.Needed {
			t.Errorf("%s reported %+v", tc.name, hw)
		}
	}
}

// A backup is sealed with its own passphrase and never with the key, so that
// losing the key does not take the backup with it.
func TestEncryptedBackupIsNotSealedToHardware(t *testing.T) {
	data, err := m.Encrypt([]byte("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"), "backup-pass")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "backup")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if hw := m.VaultHardware(path); hw.Needed {
		t.Errorf("an encrypted backup reported %+v; it must open with its passphrase alone", hw)
	}
	if _, err := m.Decrypt(data, "backup-pass"); err != nil {
		t.Errorf("the backup does not open with its passphrase: %v", err)
	}
}

// A hostile vault must not be able to ask for a challenge-response that makes
// no sense, and the error has to say which part is wrong.
func TestHardwareHeaderIsRangeChecked(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"no challenge", func(e map[string]any) { delete(e, "hw_challenge") }, "challenge"},
		{"empty challenge", func(e map[string]any) { e["hw_challenge"] = "" }, "challenge"},
		{"oversized challenge", func(e map[string]any) {
			e["hw_challenge"] = strings.Repeat("QUJD", 40) // 120 bytes once decoded
		}, "challenge"},
		{"no slot", func(e map[string]any) { delete(e, "hw_slot") }, "slot"},
		{"slot 7", func(e map[string]any) { e["hw_slot"] = 7 }, "slot"},
	} {
		edited := map[string]any{}
		for k, v := range env {
			edited[k] = v
		}
		tc.edit(edited)
		body, err := json.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		bad := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(bad, body, 0o600); err != nil {
			t.Fatal(err)
		}
		asked := false
		watching := func(c []byte) ([]byte, error) {
			asked = true
			return token("the-token")(c)
		}
		_, _, err = m.OpenVaultFileUnlocked(bad, m.Unlock{Passphrase: "hunter2", Hardware: watching})
		if err == nil {
			t.Errorf("%s: the vault opened", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.want)
		}
		if asked {
			t.Errorf("%s: the key was bothered before the header was checked", tc.name)
		}
	}
}

// An agent could hand back a key blob claiming a hardware binding it cannot
// substantiate; it must be refused rather than used.
func TestImportKeyRejectsAMalformedHardwareBinding(t *testing.T) {
	path := sealedVault(t, "hunter2", "the-token", 2)
	_, key, err := m.OpenVaultFileUnlocked(path,
		m.Unlock{Passphrase: "hunter2", Hardware: token("the-token")})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := key.Export()
	if err != nil {
		t.Fatal(err)
	}
	key.Zero()
	if _, err := m.ImportKey(blob); err != nil {
		t.Fatalf("a sound key blob was refused: %v", err)
	}

	var portable map[string]any
	if err := json.Unmarshal(blob, &portable); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"no challenge", func(p map[string]any) { delete(p, "hw_challenge") }},
		{"no slot", func(p map[string]any) { delete(p, "hw_slot") }},
		{"slot 9", func(p map[string]any) { p["hw_slot"] = 9 }},
	} {
		edited := map[string]any{}
		for k, v := range portable {
			edited[k] = v
		}
		tc.edit(edited)
		body, err := json.Marshal(edited)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.ImportKey(body); err == nil {
			t.Errorf("%s: a malformed hardware key blob was accepted", tc.name)
		}
	}
}

// Sealing twice gives a different challenge and salt each time, so two vaults
// sealed to the same key share no key material.
func TestEachSealGetsItsOwnChallenge(t *testing.T) {
	first := sealedVault(t, "hunter2", "the-token", 2)
	second := sealedVault(t, "hunter2", "the-token", 2)
	readChallenge := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var env struct {
			Challenge string `json:"hw_challenge"`
			Salt      string `json:"salt"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatal(err)
		}
		if env.Challenge == "" || env.Salt == "" {
			t.Fatalf("%s has no challenge or salt", path)
		}
		return env.Challenge + "/" + env.Salt
	}
	if readChallenge(first) == readChallenge(second) {
		t.Error("two seals reused the same challenge and salt")
	}
}
