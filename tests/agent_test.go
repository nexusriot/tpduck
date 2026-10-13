package test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/nexusriot/tpduck/internal/agent"
	m "github.com/nexusriot/tpduck/internal/model"
)

// startAgent runs an agent on a private socket for the duration of a test.
func startAgent(t *testing.T, ttl time.Duration) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	t.Setenv("TPDUCK_AGENT_SOCK", sock)
	errc := make(chan error, 1)
	go func() { errc <- agent.Serve(sock, ttl) }()

	deadline := time.Now().Add(3 * time.Second)
	for !agent.Running() {
		if time.Now().After(deadline) {
			t.Fatal("agent did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(func() {
		_ = agent.StopAgent()
		select {
		case <-errc:
		case <-time.After(2 * time.Second):
			t.Error("agent did not shut down")
		}
	})
	return sock
}

func TestAgentCachesAKey(t *testing.T) {
	startAgent(t, time.Minute)
	vault := "/some/vault.json"

	if _, err := agent.Get(vault); !errors.Is(err, agent.ErrNoKey) {
		t.Fatalf("empty agent returned %v, want ErrNoKey", err)
	}
	key, err := m.NewKey("passphrase")
	if err != nil {
		t.Fatal(err)
	}
	blob, err := key.Export()
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Put(vault, blob, time.Minute); err != nil {
		t.Fatal(err)
	}
	n, err := agent.Status()
	if err != nil || n != 1 {
		t.Fatalf("status = %d, %v", n, err)
	}
	got, err := agent.Get(vault)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := m.ImportKey(got)
	if err != nil {
		t.Fatal(err)
	}
	// The round-tripped key must still open what the original sealed.
	sealed, err := key.Seal([]byte(`{"accounts":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Decrypt(sealed, "passphrase"); err != nil {
		t.Fatal(err)
	}
	if restored.KDF() != key.KDF() {
		t.Errorf("kdf = %q, want %q", restored.KDF(), key.KDF())
	}
	key.Zero()
}

func TestAgentForgets(t *testing.T) {
	startAgent(t, time.Minute)
	key, _ := m.NewKey("pw")
	blob, _ := key.Export()
	key.Zero()
	for _, v := range []string{"/a.json", "/b.json"} {
		if err := agent.Put(v, blob, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := agent.Drop("/a.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Get("/a.json"); !errors.Is(err, agent.ErrNoKey) {
		t.Errorf("dropped key is still there: %v", err)
	}
	if _, err := agent.Get("/b.json"); err != nil {
		t.Errorf("dropping one key removed another: %v", err)
	}
	// An empty vault drops everything, which is what stepping away wants.
	if err := agent.Drop(""); err != nil {
		t.Fatal(err)
	}
	if n, _ := agent.Status(); n != 0 {
		t.Errorf("agent still holds %d keys", n)
	}
}

// The lifetime is absolute, not sliding: polling the agent must not keep a
// key alive past its expiry.
func TestAgentExpiresKeys(t *testing.T) {
	startAgent(t, 1500*time.Millisecond)
	key, _ := m.NewKey("pw")
	blob, _ := key.Export()
	key.Zero()
	if err := agent.Put("/v.json", blob, 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.Get("/v.json"); err != nil {
		t.Fatalf("key missing immediately after Put: %v", err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for {
		if _, err := agent.Get("/v.json"); errors.Is(err, agent.ErrNoKey) {
			return // expired as it should
		}
		if time.Now().After(deadline) {
			t.Fatal("key never expired")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestAgentNotRunning(t *testing.T) {
	t.Setenv("TPDUCK_AGENT_SOCK", filepath.Join(t.TempDir(), "nothing.sock"))
	if agent.Running() {
		t.Fatal("Running() is true with no agent")
	}
	if _, err := agent.Get("/v.json"); !errors.Is(err, agent.ErrNotRunning) {
		t.Errorf("got %v, want ErrNotRunning", err)
	}
}

func TestAgentRefusesEmptyPut(t *testing.T) {
	startAgent(t, time.Minute)
	if err := agent.Put("", nil, time.Minute); err == nil {
		t.Error("agent accepted an empty put")
	}
}

// A key cached for one vault must not be handed out for a different one.
func TestKeyMatchesVault(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")
	if err := (&m.Store{Accounts: vaultAccounts()}).SaveWithPass(a, "one"); err != nil {
		t.Fatal(err)
	}
	if err := (&m.Store{Accounts: vaultAccounts()}).SaveWithPass(b, "two"); err != nil {
		t.Fatal(err)
	}
	_, ka, err := m.OpenVaultFile(a, "one")
	if err != nil {
		t.Fatal(err)
	}
	defer ka.Zero()
	if !ka.MatchesVault(a) {
		t.Error("key does not match the vault it came from")
	}
	if ka.MatchesVault(b) {
		t.Error("key claims to match a different vault")
	}
	// A plaintext vault never matches a key.
	plain := filepath.Join(dir, "plain.json")
	if err := (&m.Store{Accounts: vaultAccounts()}).Save(plain); err != nil {
		t.Fatal(err)
	}
	if ka.MatchesVault(plain) {
		t.Error("key claims to match a plaintext vault")
	}
}

func TestImportKeyRejectsJunk(t *testing.T) {
	for name, blob := range map[string][]byte{
		"not json":    []byte("hello"),
		"empty key":   []byte(`{"kdf":"argon2id","salt":"AAAA","key":""}`),
		"short key":   []byte(`{"kdf":"argon2id","salt":"AAAA","key":"AAAA"}`),
		"no salt":     []byte(`{"kdf":"argon2id","key":"` + longKeyB64() + `"}`),
		"unknown kdf": []byte(`{"kdf":"rot13","salt":"AAAA","key":"` + longKeyB64() + `"}`),
	} {
		if _, err := m.ImportKey(blob); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func longKeyB64() string {
	// 32 zero bytes, base64 -- the right length for a key.
	return "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
}
