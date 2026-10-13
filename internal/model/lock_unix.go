//go:build unix

package model

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockVault takes an exclusive advisory lock covering the read-check-write of
// a vault, so two tpduck processes racing each other cannot interleave between
// the staleness check and the rename that commits it.
//
// The lock lives in a sidecar file rather than the vault itself: the vault is
// replaced by rename on every write, and a lock held on the old inode would
// not be seen by the next writer.
func lockVault(path string) (func(), error) {
	lockPath := path + ".lock"
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open vault lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock vault: %w", err)
	}
	return func() {
		// Closing the descriptor releases the flock; the file is deliberately
		// left behind, because unlinking it would let a waiter lock an inode
		// nobody else can see.
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}
