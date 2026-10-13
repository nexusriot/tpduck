package model

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Profiles keep separate vaults side by side -- work and personal, say --
// without juggling -config paths. The default profile is the plain vault, so
// an existing install is already "the default profile".
const profilesDir = "profiles"

// ProfilePath returns the vault path for a named profile. An empty name means
// the default vault.
func ProfilePath(name string) (string, error) {
	if name == "" {
		return DefaultConfigPath()
	}
	if err := validProfileName(name); err != nil {
		return "", err
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfgDir, appDir, profilesDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

// validProfileName keeps a profile name from escaping its directory or
// colliding with the rotated-version suffixes.
func validProfileName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("profile name is empty")
	}
	if name != filepath.Base(name) || strings.ContainsAny(name, `/\`) || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid profile name %q", name)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("profile names may use letters, digits, - and _ only (%q)", name)
		}
	}
	return nil
}

// Profile describes one named vault.
type Profile struct {
	Name      string
	Path      string
	Accounts  int
	Encrypted bool
}

// ListProfiles returns the named profiles, plus the default vault first.
func ListProfiles() ([]Profile, error) {
	var out []Profile
	if def, err := DefaultConfigPath(); err == nil {
		out = append(out, describeProfile("(default)", def))
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return out, nil
	}
	entries, err := os.ReadDir(filepath.Join(cfgDir, appDir, profilesDir))
	if err != nil {
		return out, nil // no profiles yet is not an error
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		names = append(names, strings.TrimSuffix(e.Name(), ".json"))
	}
	sort.Strings(names)
	for _, n := range names {
		p, err := ProfilePath(n)
		if err != nil {
			continue
		}
		out = append(out, describeProfile(n, p))
	}
	return out, nil
}

func describeProfile(name, path string) Profile {
	p := Profile{Name: name, Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	p.Encrypted = IsEncrypted(data)
	if p.Encrypted {
		return p // counting would need the passphrase
	}
	if s, err := decodeStore(data, vaultOrigin{path: path}); err == nil {
		p.Accounts = len(s.Accounts)
	}
	return p
}
