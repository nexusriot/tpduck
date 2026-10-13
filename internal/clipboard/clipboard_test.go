package clipboard

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fake replaces the system clipboard for the duration of a test.
type fake struct {
	mu      sync.Mutex
	content string
	readErr error
	writes  int
	clears  int
}

func (f *fake) install(t *testing.T) {
	t.Helper()
	ow, or, oc := writeFn, readFn, clearFn
	writeFn = func(s string) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.content, f.writes = s, f.writes+1
		return nil
	}
	readFn = func() (string, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.content, f.readErr
	}
	clearFn = func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.content, f.clears = "", f.clears+1
		return nil
	}
	t.Cleanup(func() { writeFn, readFn, clearFn = ow, or, oc })
}

func (f *fake) get() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.content, f.clears
}

func (f *fake) set(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.content = s
}

// waitFor polls until cond holds or the deadline passes.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTransientClearsCode(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.get(); got != "123456" {
		t.Fatalf("clipboard = %q, want the code", got)
	}
	waitFor(t, "the clipboard to be cleared", func() bool {
		got, clears := f.get()
		return got == "" && clears == 1
	})
}

// Clearing must not destroy something the user copied in the meantime.
func TestTransientLeavesForeignContentAlone(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	f.set("a shopping list")
	time.Sleep(120 * time.Millisecond)
	got, clears := f.get()
	if got != "a shopping list" {
		t.Errorf("clipboard = %q, want the user's own content", got)
	}
	if clears != 0 {
		t.Errorf("cleared someone else's clipboard %d time(s)", clears)
	}
}

// If the clipboard cannot be read, clearing is the safer failure.
func TestTransientClearsWhenReadFails(t *testing.T) {
	f := &fake{readErr: errors.New("no paste helper")}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", 20*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "an unreadable clipboard to be cleared", func() bool {
		_, clears := f.get()
		return clears == 1
	})
}

func TestTransientCancelAndSupersede(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("111111", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	tr.Cancel()
	time.Sleep(80 * time.Millisecond)
	if got, clears := f.get(); got != "111111" || clears != 0 {
		t.Errorf("Cancel did not stop the clear: content=%q clears=%d", got, clears)
	}

	// A second copy supersedes the first timer rather than stacking with it.
	if err := tr.Copy("222222", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	if err := tr.Copy("333333", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the latest code to be cleared", func() bool {
		got, _ := f.get()
		return got == ""
	})
	if _, clears := f.get(); clears != 1 {
		t.Errorf("clipboard cleared %d times, want 1", clears)
	}
}

func TestTransientZeroDurationKeepsCode(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", 0, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got, clears := f.get(); got != "123456" || clears != 0 {
		t.Errorf("a zero duration still cleared: content=%q clears=%d", got, clears)
	}
}

func TestOnClearCallbackFires(t *testing.T) {
	f := &fake{}
	f.install(t)
	done := make(chan struct{})
	var once sync.Once
	var tr Transient
	if err := tr.Copy("123456", 20*time.Millisecond, func() { once.Do(func() { close(done) }) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("onClear was never called")
	}
}

// Quitting must clear a pending code rather than abandoning it on the
// clipboard, which is what Cancel would do.
func TestFlushClearsImmediately(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, clears := f.get(); got != "" || clears != 1 {
		t.Fatalf("Flush did not clear: content=%q clears=%d", got, clears)
	}
	// A second Flush is a no-op, not another clear.
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, clears := f.get(); clears != 1 {
		t.Errorf("second Flush cleared again (%d)", clears)
	}
}

func TestFlushLeavesForeignContent(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Copy("123456", time.Hour, nil); err != nil {
		t.Fatal(err)
	}
	f.set("something the user copied")
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, clears := f.get(); got != "something the user copied" || clears != 0 {
		t.Errorf("Flush clobbered foreign content: %q clears=%d", got, clears)
	}
}

func TestFlushWithNothingPending(t *testing.T) {
	f := &fake{}
	f.install(t)
	var tr Transient
	if err := tr.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, clears := f.get(); clears != 0 {
		t.Errorf("Flush cleared with nothing pending (%d)", clears)
	}
}
