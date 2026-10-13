//go:build !unix

package model

// lockVault is a no-op where flock is unavailable. The staleness check in
// Store.save still detects a concurrent write and refuses it; without the lock
// there is a narrow window in which two writers could both pass the check, so
// the guarantee there is "usually detected" rather than "always".
func lockVault(path string) (func(), error) { return func() {}, nil }
