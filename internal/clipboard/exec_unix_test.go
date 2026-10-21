//go:build !windows

package clipboard

import (
	"os"
	"path/filepath"
	"testing"
)

// These exercise execWrite itself -- the probe-and-fall-back logic that the
// fake-clipboard tests bypass by replacing writeFn wholesale. The "tools" are
// shell scripts that record what they were given, so the real exec path,
// including stdin, is what runs.

func stubTool(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// useHelpers swaps the backend list and the PATH the tools are found on.
func useHelpers(t *testing.T, dir string, hs []helper) {
	t.Helper()
	oldHelpers, oldPath := helpers, os.Getenv("PATH")
	helpers = hs
	// Prepended, not replaced: the stub tools are shell scripts and still need
	// to find cat and friends.
	t.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath)
	sensitiveMu.Lock()
	oldUnsupported := sensitiveUnsupported
	sensitiveUnsupported = map[string]bool{}
	sensitiveMu.Unlock()
	t.Cleanup(func() {
		helpers = oldHelpers
		os.Setenv("PATH", oldPath)
		sensitiveMu.Lock()
		sensitiveUnsupported = oldUnsupported
		sensitiveMu.Unlock()
	})
}

func TestExecWriteUsesTheSensitiveCommandWhenItWorks(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	stubTool(t, dir, "marker", `printf 'sensitive:' > `+out+`; cat >> `+out)
	useHelpers(t, dir, []helper{{
		name: "marker", write: []string{"marker"}, sensitive: []string{"marker", "--sensitive"},
	}})

	res, err := execWrite("123456", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Sensitive {
		t.Error("the marking was not reported")
	}
	if res.Note != "" {
		t.Errorf("a successful marking still carried a note: %q", res.Note)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "sensitive:123456" {
		t.Errorf("the tool received %q", got)
	}
}

// The important path: an installed tool too old for the flag. The copy must
// still happen, because a code the user cannot paste is worse than one a
// clipboard manager might record.
func TestExecWriteFallsBackWhenTheFlagIsRejected(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	stubTool(t, dir, "oldtool", `
if [ "$1" = "--sensitive" ]; then
  echo "unknown option" >&2
  exit 2
fi
cat > `+out)
	useHelpers(t, dir, []helper{{
		name: "oldtool", write: []string{"oldtool"}, sensitive: []string{"oldtool", "--sensitive"},
	}})

	res, err := execWrite("123456", true)
	if err != nil {
		t.Fatalf("the copy failed instead of falling back: %v", err)
	}
	if res.Sensitive {
		t.Error("the result claims a marking the tool rejected")
	}
	if res.Note == "" {
		t.Error("the fallback is silent; it should say the tool is too old")
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the code never reached the clipboard: %v", err)
	}
	if string(got) != "123456" {
		t.Errorf("the tool received %q, want the code", got)
	}
}

// Once a tool has rejected the flag, it must not be probed again: the probe
// costs a process launch on every single copy.
func TestExecWriteProbesTheFlagOnlyOnce(t *testing.T) {
	dir := t.TempDir()
	tries := filepath.Join(dir, "tries")
	stubTool(t, dir, "oldtool", `
if [ "$1" = "--sensitive" ]; then
  echo x >> `+tries+`
  exit 2
fi
cat > /dev/null`)
	useHelpers(t, dir, []helper{{
		name: "oldtool", write: []string{"oldtool"}, sensitive: []string{"oldtool", "--sensitive"},
	}})

	for i := 0; i < 3; i++ {
		if _, err := execWrite("123456", true); err != nil {
			t.Fatalf("copy %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(tries)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(got); n != 2 { // "x\n"
		t.Errorf("the flag was probed %d times, want 1", n/2)
	}
}

// A backend with no sensitive command at all must not be probed, and must pass
// its explanation back to the caller.
func TestExecWriteReportsABackendThatCannotMark(t *testing.T) {
	dir := t.TempDir()
	stubTool(t, dir, "plain", "cat > /dev/null")
	useHelpers(t, dir, []helper{{
		name: "plain", write: []string{"plain"},
		sensitiveNote: "plain cannot mark a copy as sensitive",
	}})

	res, err := execWrite("123456", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Sensitive {
		t.Error("a backend with no sensitive command reported one")
	}
	if res.Note != "plain cannot mark a copy as sensitive" {
		t.Errorf("note = %q", res.Note)
	}
}

// A genuine write failure is still a failure: falling back must not swallow it.
func TestExecWriteReportsARealFailure(t *testing.T) {
	dir := t.TempDir()
	stubTool(t, dir, "broken", "exit 1")
	useHelpers(t, dir, []helper{{name: "broken", write: []string{"broken"}}})

	if _, err := execWrite("123456", true); err == nil {
		t.Error("a failing clipboard tool was reported as success")
	}
}

// With no tool on PATH at all, the caller is told so rather than believing the
// code was copied.
func TestExecWriteWithNoHelperInstalled(t *testing.T) {
	useHelpers(t, t.TempDir(), []helper{{name: "absent", write: []string{"definitely-not-installed"}}})
	if _, err := execWrite("123456", true); err == nil {
		t.Error("copying with no clipboard tool reported success")
	}
}
