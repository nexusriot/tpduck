// Package keyring stores a vault passphrase in the operating system's own
// secret store, so an encrypted vault does not have to be unlocked by hand
// every single time.
//
// This is a convenience, and it is a real trade-off: anything that can talk to
// your session's secret service as you can read the passphrase back. It is off
// unless the user turns it on, and it is strictly better than the alternative
// people actually choose, which is leaving the vault unencrypted.
package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	kr "github.com/zalando/go-keyring"
)

// Service is the name tpduck registers under in the OS keyring.
const Service = "tpduck"

// ErrNotFound means no passphrase is stored for that vault.
var ErrNotFound = errors.New("no passphrase in the keyring for this vault")

// account derives the keyring entry name from the vault path, so several
// vaults can be remembered independently without putting a filesystem path
// into the keyring UI.
func account(vaultPath string) string {
	sum := sha256.Sum256([]byte(vaultPath))
	return "vault-" + hex.EncodeToString(sum[:8])
}

// Get returns the stored passphrase for a vault.
func Get(vaultPath string) (string, error) {
	s, err := kr.Get(Service, account(vaultPath))
	if err != nil {
		if errors.Is(err, kr.ErrNotFound) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("read keyring: %w", err)
	}
	return s, nil
}

// Set stores the passphrase for a vault.
func Set(vaultPath, passphrase string) error {
	if passphrase == "" {
		return errors.New("refusing to store an empty passphrase")
	}
	if err := kr.Set(Service, account(vaultPath), passphrase); err != nil {
		return fmt.Errorf("write keyring: %w", err)
	}
	return nil
}

// Delete forgets the passphrase for a vault. Deleting something that is not
// there is not an error.
func Delete(vaultPath string) error {
	err := kr.Delete(Service, account(vaultPath))
	if err == nil || errors.Is(err, kr.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("delete from keyring: %w", err)
}

// Available reports whether a usable secret store is present. On a headless
// box there is usually no D-Bus secret service, and callers must fall back to
// prompting rather than failing.
func Available() bool {
	const probe = "availability-probe"
	if err := kr.Set(Service, probe, "x"); err != nil {
		return false
	}
	_ = kr.Delete(Service, probe)
	return true
}
