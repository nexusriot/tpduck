package test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

func vaultAccounts() []m.Account {
	return []m.Account{{
		ID: "acme:alice", Issuer: "Acme", Name: "alice",
		Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1,
	}}
}

func TestEncryptRoundTrip(t *testing.T) {
	plain := []byte(`{"accounts":[{"secret":"JBSWY3DPEHPK3PXP"}]}`)
	sealed, err := m.Encrypt(plain, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("secret appears in the ciphertext")
	}
	if !m.IsEncrypted(sealed) {
		t.Fatal("IsEncrypted said no to an envelope")
	}
	if m.IsEncrypted(plain) {
		t.Fatal("IsEncrypted said yes to a plaintext store")
	}
	got, err := m.Decrypt(sealed, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip changed the data: %s", got)
	}
}

func TestWrongPassphraseRejected(t *testing.T) {
	sealed, err := m.Encrypt([]byte(`{"accounts":[]}`), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Decrypt(sealed, "wrong"); err == nil {
		t.Fatal("a wrong passphrase decrypted the vault")
	}
}

// The KDF parameters are authenticated, so an attacker cannot lower the cost
// and still have the vault open.
func TestKDFDowngradeRejected(t *testing.T) {
	sealed, err := m.Encrypt([]byte(`{"accounts":[]}`), "pass")
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(sealed, &env); err != nil {
		t.Fatal(err)
	}
	env["n"] = 1024 // cheapest value the reader still accepts
	tampered, _ := json.Marshal(env)
	if _, err := m.Decrypt(tampered, "pass"); err == nil {
		t.Fatal("a downgraded KDF cost still authenticated")
	}
}

func TestAbsurdKDFParamsRefused(t *testing.T) {
	sealed, _ := m.Encrypt([]byte(`{"accounts":[]}`), "pass")
	var env map[string]any
	_ = json.Unmarshal(sealed, &env)
	env["n"] = 1 << 30 // would try to allocate an absurd amount of memory
	tampered, _ := json.Marshal(env)
	_, err := m.Decrypt(tampered, "pass")
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("hostile scrypt cost was not refused up front: %v", err)
	}
}

func TestEncryptedVaultSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := &m.Store{Accounts: vaultAccounts()}
	if err := s.SaveWithPass(path, "hunter2"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("JBSWY3DPEHPK3PXP")) || bytes.Contains(raw, []byte("alice")) {
		t.Fatal("vault file leaks plaintext")
	}
	if enc, err := m.IsVaultEncrypted(path); err != nil || !enc {
		t.Fatalf("IsVaultEncrypted = %v, %v", enc, err)
	}
	// Reading without the passphrase must refuse, not return an empty vault.
	if _, err := m.LoadStore(path); err != m.ErrEncrypted {
		t.Fatalf("LoadStore on an encrypted vault = %v, want ErrEncrypted", err)
	}
	got, err := m.LoadStoreWithPass(path, "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Accounts) != 1 || got.Accounts[0].Secret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("round trip lost data: %+v", got.Accounts)
	}
}

// A derived key is reused across saves so the TUI does not pay the KDF cost on
// every keystroke-triggered write.
func TestKeyReuseAcrossSaves(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	k, err := m.NewKey("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	s := &m.Store{Accounts: vaultAccounts()}
	if err := s.SaveWithKey(path, k); err != nil {
		t.Fatal(err)
	}
	s.Accounts[0].Notes = "changed"
	if err := s.SaveWithKey(path, k); err != nil {
		t.Fatal(err)
	}
	got, err := m.LoadStoreWithKey(path, k)
	if err != nil {
		t.Fatal(err)
	}
	if got.Accounts[0].Notes != "changed" {
		t.Fatalf("second save did not take: %+v", got.Accounts[0])
	}
	k.Zero()
	if err := s.SaveWithKey(path, k); err == nil {
		t.Fatal("a zeroed key still sealed data")
	}
}

func TestPlaintextVaultStillLoads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.json")
	s := &m.Store{Accounts: vaultAccounts()}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if enc, _ := m.IsVaultEncrypted(path); enc {
		t.Fatal("plaintext vault reported as encrypted")
	}
	// A passphrase supplied for a plaintext vault is ignored, not an error.
	if got, err := m.LoadStoreWithPass(path, "ignored"); err != nil || len(got.Accounts) != 1 {
		t.Fatalf("got %v, %v", got, err)
	}
}
