package clipboard

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// fake replaces the system clipboard for the duration of a test.
type fake struct {
	mu        sync.Mutex
	content   string
	readErr   error
	writes    int
	clears    int
	sensitive bool // what the last write asked for
	// markable makes the fake backend accept the sensitive marking.
	markable bool
}

func (f *fake) install(t *testing.T) {
	t.Helper()
	ow, or, oc := writeFn, readFn, clearFn
	writeFn = func(s string, sensitive bool) (Result, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.content, f.writes, f.sensitive = s, f.writes+1, sensitive
		return Result{Helper: "fake", Sensitive: sensitive && f.markable}, nil
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

func (f *fake) askedSensitive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sensitive
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
	if _, err := tr.Copy("123456", 30*time.Millisecond, nil); err != nil {
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
	if _, err := tr.Copy("123456", 30*time.Millisecond, nil); err != nil {
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
	if _, err := tr.Copy("123456", 20*time.Millisecond, nil); err != nil {
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
	if _, err := tr.Copy("111111", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	tr.Cancel()
	time.Sleep(80 * time.Millisecond)
	if got, clears := f.get(); got != "111111" || clears != 0 {
		t.Errorf("Cancel did not stop the clear: content=%q clears=%d", got, clears)
	}

	// A second copy supersedes the first timer rather than stacking with it.
	if _, err := tr.Copy("222222", 30*time.Millisecond, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Copy("333333", 30*time.Millisecond, nil); err != nil {
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
	if _, err := tr.Copy("123456", 0, nil); err != nil {
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
	if _, err := tr.Copy("123456", 20*time.Millisecond, func() { once.Do(func() { close(done) }) }); err != nil {
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
	if _, err := tr.Copy("123456", time.Hour, nil); err != nil {
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
	if _, err := tr.Copy("123456", time.Hour, nil); err != nil {
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

// A copied code that a clipboard manager records is still a leaked credential
// fifteen seconds later, so the backend is asked to mark it and the caller is
// told whether that worked.
func TestSecretCopyIsMarkedWhenTheBackendCanDoIt(t *testing.T) {
	f := &fake{markable: true}
	f.install(t)
	res, err := CopySecret("123456")
	if err != nil {
		t.Fatal(err)
	}
	if !f.askedSensitive() {
		t.Error("the backend was not asked to mark the copy")
	}
	if !res.Sensitive {
		t.Error("the result does not report the marking")
	}
}

// Where it cannot, the copy still happens -- a code on the clipboard is the
// point -- and the result says it went unmarked.
func TestSecretCopyFallsBackWhenItCannot(t *testing.T) {
	f := &fake{markable: false}
	f.install(t)
	res, err := CopySecret("123456")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := f.get(); got != "123456" {
		t.Errorf("clipboard holds %q, want the code", got)
	}
	if res.Sensitive {
		t.Error("the result claims a marking the backend did not accept")
	}
}

// The plain Copy path must not claim to mark anything.
func TestPlainCopyDoesNotAskForMarking(t *testing.T) {
	f := &fake{markable: true}
	f.install(t)
	if err := Copy("123456"); err != nil {
		t.Fatal(err)
	}
	if f.askedSensitive() {
		t.Error("a plain copy asked for the sensitive marking")
	}
}

// Transient copies are the ones that carry codes, so they go through the
// marked path and report what happened.
func TestTransientCopyIsMarked(t *testing.T) {
	f := &fake{markable: true}
	f.install(t)
	var tr Transient
	res, err := tr.Copy("123456", time.Hour, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.Cancel()
	if !res.Sensitive {
		t.Error("a transient copy was not marked")
	}
}

// Every backend either marks a copy or says why it cannot; a silent "no" would
// leave the user believing in protection that is not there.
func TestEveryHelperSaysWhereItStands(t *testing.T) {
	for _, h := range helpers {
		if len(h.sensitive) == 0 && h.sensitiveNote == "" {
			t.Errorf("%s neither marks copies nor explains why not", h.name)
		}
		if len(h.sensitive) > 0 && h.sensitiveNote != "" {
			t.Errorf("%s both marks copies and explains why it cannot", h.name)
		}
	}
}

// A backend too old for the flag must be noticed once, not probed on every
// copy: the fallback costs a process launch.
func TestUnsupportedMarkingIsRememberedOnce(t *testing.T) {
	sensitiveMu.Lock()
	saved := sensitiveUnsupported
	sensitiveUnsupported = map[string]bool{}
	sensitiveMu.Unlock()
	t.Cleanup(func() {
		sensitiveMu.Lock()
		sensitiveUnsupported = saved
		sensitiveMu.Unlock()
	})

	if !markingWorks("probe") {
		t.Fatal("a backend starts out assumed to work")
	}
	markingFailed("probe")
	if markingWorks("probe") {
		t.Error("the failure was not remembered")
	}
	if !markingWorks("another") {
		t.Error("one backend's failure was taken for another's")
	}
}
