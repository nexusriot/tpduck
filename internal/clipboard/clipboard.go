// Package clipboard copies short-lived secrets to the system clipboard.
package clipboard

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DefaultClearAfter is how long a copied code is left on the clipboard. A TOTP
// code is only valid for one period anyway, and leaving it there means the next
// paste in any application hands out a credential.
const DefaultClearAfter = 15 * time.Second

// helper is one clipboard backend: how to write, read and clear it.
type helper struct {
	name  string
	write []string
	read  []string
	clear []string // nil means "write an empty string"
}

// helpers is set per platform; see clipboard_unix.go and clipboard_windows.go.
var helpers = platformHelpers()

// ErrNoHelper is returned when no clipboard tool is available.
var ErrNoHelper = fmt.Errorf("no clipboard helper found (%s)", strings.Join(helperNames(), "/"))

func helperNames() []string {
	names := make([]string, 0, len(helpers))
	for _, h := range helpers {
		names = append(names, h.name)
	}
	return names
}

func find() (helper, error) {
	for _, h := range helpers {
		if _, err := exec.LookPath(h.write[0]); err == nil {
			return h, nil
		}
	}
	return helper{}, ErrNoHelper
}

func run(argv []string, stdin string) error {
	if len(argv) == 0 {
		return ErrNoHelper
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.Run()
}

// The three operations are indirected through variables so tests can supply a
// fake clipboard; there is no real one on a headless machine.
var (
	writeFn = execWrite
	readFn  = execRead
	clearFn = execClear
)

// Copy puts s on the clipboard.
func Copy(s string) error { return writeFn(s) }

func execWrite(s string) error {
	h, err := find()
	if err != nil {
		return err
	}
	return run(h.write, s)
}

// Read returns the clipboard contents. It is used to avoid clearing a clipboard
// that someone has since overwritten with something of their own.
func Read() (string, error) { return readFn() }

func execRead() (string, error) {
	h, err := find()
	if err != nil {
		return "", err
	}
	if len(h.read) == 0 {
		return "", fmt.Errorf("%s cannot read the clipboard", h.name)
	}
	out, err := exec.Command(h.read[0], h.read[1:]...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(out), "\r\n"), nil
}

// Clear empties the clipboard.
func Clear() error { return clearFn() }

func execClear() error {
	h, err := find()
	if err != nil {
		return err
	}
	if len(h.clear) > 0 {
		return run(h.clear, "")
	}
	return run(h.write, "")
}

// Transient copies a secret and schedules it to be wiped.
type Transient struct {
	mu      sync.Mutex
	timer   *time.Timer
	pending string
}

// Copy puts code on the clipboard and clears it after `after`, unless the
// clipboard has been changed by then -- overwriting someone else's copy would
// be worse than leaving ours. Calling Copy again cancels the previous timer.
//
// onClear, if non-nil, is called from the timer goroutine once the clipboard
// has been dealt with, so a UI can say so.
func (t *Transient) Copy(code string, after time.Duration, onClear func()) error {
	if err := Copy(code); err != nil {
		return err
	}
	if after <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timer != nil {
		t.timer.Stop()
	}
	t.pending = code
	t.timer = time.AfterFunc(after, func() {
		t.mu.Lock()
		expected := t.pending
		t.pending = ""
		t.mu.Unlock()
		if expected == "" {
			return
		}
		// If reading the clipboard is not possible, clear it anyway: leaving a
		// live credential behind is the worse failure.
		if cur, err := Read(); err == nil && cur != expected {
			return
		}
		_ = Clear()
		if onClear != nil {
			onClear()
		}
	})
	return nil
}

// Cancel stops a pending clear without touching the clipboard. Use it when the
// clipboard content is no longer ours to manage; to quit, use Flush.
func (t *Transient) Cancel() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopLocked()
}

func (t *Transient) stopLocked() string {
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
	pending := t.pending
	t.pending = ""
	return pending
}

// Flush performs a pending clear immediately instead of waiting for the timer.
//
// This is what quitting must do. Cancelling on exit would leave a live code on
// the clipboard forever, which is exactly the common case: copy a code, paste
// it, quit -- all well inside the clear window.
func (t *Transient) Flush() error {
	t.mu.Lock()
	expected := t.stopLocked()
	t.mu.Unlock()
	if expected == "" {
		return nil
	}
	if cur, err := Read(); err == nil && cur != expected {
		return nil // someone else owns the clipboard now
	}
	return Clear()
}
