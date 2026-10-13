package model

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// KeptVersions is how many previous copies of the vault are retained. Deleting
// an account, a bad import or a mistaken edit is otherwise unrecoverable: the
// secret is simply gone, and unlike a password it cannot be reset by asking.
const KeptVersions = 5

// versionSuffix names a rotated copy: accounts.json.1 is the most recent.
func versionPath(vault string, n int) string {
	return fmt.Sprintf("%s.%d", vault, n)
}

// rotateVersions shifts accounts.json.N -> accounts.json.N+1 and copies the
// current vault to accounts.json.1. It runs before a write, while the file
// still holds the previous state.
//
// Failures here are not fatal to the write: losing a backup copy is better
// than refusing to save.
func rotateVersions(vault string) error {
	cur, err := os.ReadFile(vault)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // nothing to keep yet
		}
		return err
	}
	// Drop the oldest, then shift each one down.
	_ = os.Remove(versionPath(vault, KeptVersions))
	for n := KeptVersions - 1; n >= 1; n-- {
		from, to := versionPath(vault, n), versionPath(vault, n+1)
		if _, err := os.Stat(from); err == nil {
			_ = os.Rename(from, to)
		}
	}
	return writeFileAtomic(versionPath(vault, 1), cur)
}

// Version describes one retained copy of the vault.
type Version struct {
	N         int
	Path      string
	Size      int64
	Modified  time.Time
	Encrypted bool
}

// Versions lists the retained copies, most recent first.
func Versions(vault string) ([]Version, error) {
	var out []Version
	for n := 1; n <= KeptVersions; n++ {
		p := versionPath(vault, n)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		enc := false
		if data, err := os.ReadFile(p); err == nil {
			enc = IsEncrypted(data)
		}
		out = append(out, Version{N: n, Path: p, Size: fi.Size(), Modified: fi.ModTime(), Encrypted: enc})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out, nil
}

// RestoreVersion puts a retained copy back as the live vault, rotating the
// current one first so the restore itself is undoable.
func RestoreVersion(vault string, n int) error {
	if n < 1 || n > KeptVersions {
		return fmt.Errorf("version must be between 1 and %d", KeptVersions)
	}
	src := versionPath(vault, n)
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("no retained version %d: %w", n, err)
	}
	unlock, err := lockVault(vault)
	if err != nil {
		return err
	}
	defer unlock()
	if err := rotateVersions(vault); err != nil {
		return err
	}
	return writeFileAtomic(vault, data)
}

// PruneVersions removes every retained copy.
func PruneVersions(vault string) error {
	var firstErr error
	for n := 1; n <= KeptVersions; n++ {
		if err := os.Remove(versionPath(vault, n)); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// IsVersionFile reports whether a path is one of the rotated copies of vault.
func IsVersionFile(vault, path string) bool {
	base := filepath.Base(vault)
	name := filepath.Base(path)
	rest, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return false
	}
	n, err := strconv.Atoi(rest)
	return err == nil && n >= 1 && n <= KeptVersions
}
