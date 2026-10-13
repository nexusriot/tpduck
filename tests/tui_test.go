package test

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/nexusriot/tpduck/internal/controller"
	m "github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/view"
)

// harness runs the real TUI against a simulation screen.
type harness struct {
	t      *testing.T
	screen tcell.SimulationScreen
	v      *view.View
	done   chan struct{}
	path   string
}

func newHarness(t *testing.T, accounts []m.Account) *harness {
	t.Helper()
	return newHarnessOpts(t, accounts, controller.Options{})
}

// newHarnessOpts seeds a vault on disk and drives the real TUI against a
// simulation screen.
func newHarnessOpts(t *testing.T, accounts []m.Account, opts controller.Options) *harness {
	t.Helper()
	sc := tcell.NewSimulationScreen("UTF-8")
	if err := sc.Init(); err != nil {
		t.Fatal(err)
	}
	sc.SetSize(120, 40)

	if opts.Path == "" {
		opts.Path = filepath.Join(t.TempDir(), "accounts.json")
		if accounts != nil {
			if err := (&m.Store{Accounts: accounts}).Save(opts.Path); err != nil {
				t.Fatal(err)
			}
		}
	}
	v := view.New()
	v.App.SetScreen(sc)
	c, err := controller.New(v, opts)
	if err != nil {
		t.Fatal(err)
	}

	h := &harness{t: t, screen: sc, v: v, done: make(chan struct{}), path: opts.Path}
	go func() {
		defer close(h.done)
		c.Start(10 * time.Millisecond)
	}()
	h.settle()
	t.Cleanup(func() {
		v.App.QueueUpdate(func() { v.App.Stop() })
		select {
		case <-h.done:
		case <-time.After(2 * time.Second):
			t.Error("app did not shut down")
		}
	})
	return h
}

// settle pumps the event loop once so queued work is drawn. Injected keys and
// queued updates travel on separate channels, so this is a nudge, not a
// barrier -- assertions use waitFor/waitGone rather than relying on it.
func (h *harness) settle() {
	h.t.Helper()
	done := make(chan struct{})
	h.v.App.QueueUpdateDraw(func() { close(done) })
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		h.t.Fatal("event loop stalled")
	}
}

// waitFor polls the screen until it contains want, and returns the screen.
func (h *harness) waitFor(what, want string) string {
	h.t.Helper()
	return h.poll(what, want, true)
}

// waitGone polls the screen until want has disappeared from it.
func (h *harness) waitGone(what, want string) string {
	h.t.Helper()
	return h.poll(what, want, false)
}

func (h *harness) poll(what, want string, present bool) string {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var screen string
	for {
		screen = h.text()
		if strings.Contains(screen, want) == present {
			return screen
		}
		if time.Now().After(deadline) {
			verb := "never appeared"
			if !present {
				verb = "never disappeared"
			}
			h.t.Fatalf("%s: %q %s on screen:\n%s", what, want, verb, screen)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (h *harness) typeStr(s string) {
	h.t.Helper()
	h.screen.InjectKey(tcell.KeyRune, rune(s[0]), tcell.ModNone)
	for _, r := range s[1:] {
		h.screen.InjectKey(tcell.KeyRune, r, tcell.ModNone)
	}
	h.settle()
}

func (h *harness) key(k tcell.Key) {
	h.t.Helper()
	h.screen.InjectKey(k, 0, tcell.ModNone)
	h.settle()
}

// text returns everything currently drawn, one line per screen row. The scrape
// runs on the event-loop goroutine: tcell's GetContents hands back the live
// cell buffer, so reading it from the test goroutine would race with a redraw.
func (h *harness) text() string {
	h.t.Helper()
	var out string
	done := make(chan struct{})
	h.v.App.QueueUpdate(func() {
		defer close(done)
		cells, w, hgt := h.screen.GetContents()
		var b strings.Builder
		for y := 0; y < hgt; y++ {
			for x := 0; x < w; x++ {
				r := cells[y*w+x].Runes
				if len(r) > 0 && r[0] != 0 {
					b.WriteRune(r[0])
				} else {
					b.WriteByte(' ')
				}
			}
			b.WriteByte('\n')
		}
		out = b.String()
	})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.t.Fatal("event loop stalled while reading the screen")
	}
	return out
}

func sample() []m.Account {
	return []m.Account{
		{ID: "acme:alice", Issuer: "Acme", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{ID: "beta:bob", Issuer: "Beta", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Period: 60, Algo: m.AlgoSHA256},
	}
}

// Regression: the application-level input capture runs before the focused
// primitive, so unguarded single-letter shortcuts ate every A/C/D/E/I/Q/R typed
// into a form -- which is most of the Base32 alphabet. The Add form was
// unusable.
func TestFormAcceptsShortcutLetters(t *testing.T) {
	h := newHarness(t, sample())
	h.typeStr("a") // open Add
	h.waitFor("opening the Add form", "Add Account")
	h.typeStr("Discord")
	h.waitFor("typing the issuer", "Discord")
	h.key(tcell.KeyTab)
	h.typeStr("carol@example.com")
	h.waitFor("typing the name", "carol@example.com")
	// 'q' must not quit while a form is up.
	h.typeStr("q")
	h.settle()
	select {
	case <-h.done:
		t.Fatal("pressing q inside a form quit the application")
	default:
	}
}

// Regression: ESC in the import dialog did nothing, trapping the user.
func TestImportFormEscapes(t *testing.T) {
	h := newHarness(t, sample())
	h.typeStr("i")
	h.waitFor("opening the import form", "Import")
	h.typeStr("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")
	h.waitFor("typing the URI", "otpauth://totp/x")
	h.key(tcell.KeyEscape)
	h.waitGone("pressing ESC", "otpauth://")
	// Shortcuts must work again after the dialog closes.
	h.typeStr("a")
	h.waitFor("re-opening Add after a dialog", "Add Account")
}

// Regression: only Enter updated the detail panel, so arrow keys moved the
// highlight while the code and details kept showing the previous account.
func TestArrowKeysFollowSelection(t *testing.T) {
	h := newHarness(t, sample())
	h.waitFor("initial render", "Algo:    SHA1")
	h.key(tcell.KeyDown)
	h.waitFor("cursor down", "Algo:    SHA256")
	h.key(tcell.KeyUp)
	h.waitFor("cursor up", "Algo:    SHA1")
}

func TestRevealTogglesSecret(t *testing.T) {
	h := newHarness(t, sample())
	if strings.Contains(h.text(), "JBSWY3DPEHPK3PXP") {
		t.Fatal("secret shown before reveal")
	}
	h.typeStr("r")
	h.waitFor("pressing R", "JBSWY3DPEHPK3PXP")
	h.typeStr("r")
	h.waitGone("pressing R again", "JBSWY3DPEHPK3PXP")
}

// Validation errors are reported on the footer, which a full-screen form hides.
// Without a status line inside the form, a rejected action looks like a dead
// key. The import form is used here because its layout is stable: one field,
// then the buttons.
func TestFormShowsValidationError(t *testing.T) {
	h := newHarness(t, sample())
	h.typeStr("i")
	h.waitFor("opening the import form", "Import")
	h.typeStr("otpauth://totp/x?secret=1111")
	h.key(tcell.KeyTab) // move to the Import button
	h.key(tcell.KeyEnter)
	h.waitFor("importing an invalid secret", "invalid secret")
	// The form must still be up, not silently dismissed.
	if !strings.Contains(h.text(), "otpauth://totp/x") {
		t.Errorf("form closed despite a validation failure:\n%s", h.text())
	}
}
