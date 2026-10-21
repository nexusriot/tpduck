package controller

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/clipboard"
	"github.com/nexusriot/tpduck/internal/keyring"
	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/view"
)

// nextCodeThreshold is how few seconds must remain before the following code
// is previewed alongside the current one.
const nextCodeThreshold = 5

// Options configures the interactive session.
type Options struct {
	Path      string
	IdleLock  time.Duration // 0 disables auto-locking
	ClipClear time.Duration // 0 leaves copied codes on the clipboard
	NTPServer string
	// UseKeyring allows reading the passphrase from the OS secret store at
	// startup. Writing to it is always an explicit choice by the user.
	UseKeyring bool
	// Hardware builds a responder for a vault sealed to a hardware token. It
	// is nil in builds and tests with no smart-card support, which simply
	// means such a vault cannot be opened here.
	Hardware func(slot int) model.HardwareResponder
}

type Controller struct {
	store     *model.Store
	storePath string
	v         *view.View
	opts      Options

	selected      string
	reveal        bool
	filter        string
	lastErr       string // de-duplicates the per-tick error flash
	failedUnlocks int

	key    *model.Key // nil when the vault is plaintext
	locked bool

	clip         clipboard.Transient
	lastActivity time.Time
	done         chan struct{}
}

// New prepares a session for the vault at opts.Path. An encrypted vault starts
// locked: nothing is read from disk until the passphrase arrives.
func New(v *view.View, opts Options) (*Controller, error) {
	if opts.Path == "" {
		p, err := model.DefaultConfigPath()
		if err != nil {
			return nil, err
		}
		opts.Path = p
	}
	c := &Controller{
		v:            v,
		opts:         opts,
		storePath:    opts.Path,
		store:        &model.Store{},
		done:         make(chan struct{}),
		lastActivity: time.Now(),
	}
	encrypted, err := model.IsVaultEncrypted(opts.Path)
	if err != nil {
		return nil, err
	}
	if encrypted {
		c.locked = true
	} else {
		s, err := model.LoadStore(opts.Path)
		if err != nil {
			return nil, err
		}
		c.store = s
	}

	v.SetHandlers(view.Handlers{
		OnAdd:        c.onAdd,
		OnEdit:       c.onEdit,
		OnDelete:     c.onDelete,
		OnImport:     c.onImport,
		OnExport:     c.onExport,
		OnReveal:     c.onReveal,
		OnCopy:       c.onCopy,
		OnQuit:       c.onQuit,
		OnSelect:     c.onSelect,
		OnSearch:     c.onSearch,
		OnAdvance:    c.onAdvance,
		OnPassphrase: c.onPassphrase,
		OnLock:       c.onLock,
		OnSkew:       c.onSkew,
		OnHelp:       c.onHelp,
		OnPin:        c.onPin,
		OnOrder:      c.onOrder,
		OnResync:     c.onResync,
		OnVerify:     c.onVerify,
		OnMigrate:    c.onMigrate,
		OnActivity:   c.onActivity,
		OnStart:      c.onStart,
	})
	c.refreshList()
	return c, nil
}

func (c *Controller) Start(refreshPeriod time.Duration) {
	if refreshPeriod <= 0 {
		refreshPeriod = 250 * time.Millisecond
	}
	ticker := time.NewTicker(refreshPeriod)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-c.done:
				return
			case <-ticker.C:
				c.v.App.QueueUpdateDraw(func() {
					c.checkIdle()
					c.renderCodeOnly()
				})
			}
		}
	}()
	err := c.v.Run()
	// Stop the refresh goroutine before the event loop is gone: QueueUpdateDraw
	// on a stopped application blocks forever once its buffer fills.
	close(c.done)
	// Clear, not cancel: quitting right after copying must not leave the code
	// on the clipboard.
	_ = c.clip.Flush()
	if err != nil {
		fmt.Fprintln(os.Stderr, "run:", err)
	}
	if c.key != nil {
		c.key.Zero()
	}
}

// onStart runs once the event loop owns the screen.
func (c *Controller) onStart() {
	if c.locked {
		if c.tryKeyringUnlock() {
			return
		}
		c.promptUnlock("Vault is locked")
		return
	}
	c.v.SetVaultStatus(false)
	if len(c.store.Accounts) > 0 {
		c.v.Flash("[yellow]vault is NOT encrypted -- press P to set a passphrase")
	}
}

// --- vault state ------------------------------------------------------------

// tryKeyringUnlock opens the vault with a passphrase the user chose to store
// in the OS keyring. A failure here is never fatal: it falls back to asking.
func (c *Controller) tryKeyringUnlock() bool {
	if !c.opts.UseKeyring {
		return false
	}
	pass, err := keyring.Get(c.storePath)
	if err != nil || pass == "" {
		return false
	}
	store, key, err := model.OpenVaultFileUnlocked(c.storePath,
		model.Unlock{Passphrase: pass, Hardware: c.hardware()})
	if err != nil {
		// A stale entry (the passphrase was changed elsewhere) must not loop.
		c.v.Flash("[yellow]keyring passphrase no longer opens this vault")
		return false
	}
	c.adoptStore(store, key)
	c.v.Flash("[green]unlocked from keyring")
	return true
}

// adoptStore installs a freshly opened vault.
func (c *Controller) adoptStore(store *model.Store, key *model.Key) {
	c.store, c.key, c.locked = store, key, false
	c.failedUnlocks = 0
	c.selected = ""
	c.store.Sort()
	if len(c.store.Accounts) > 0 {
		c.selected = c.store.Accounts[0].ID
	}
	c.v.SetVaultStatus(c.key != nil)
	c.refreshList()
	c.v.RestoreRoot()
	c.touch()
}

// hardware returns the responder for this vault, or nil when it does not need
// one (or this build cannot reach a key).
func (c *Controller) hardware() model.HardwareResponder {
	hw := model.VaultHardware(c.storePath)
	if !hw.Needed || c.opts.Hardware == nil {
		return nil
	}
	return c.opts.Hardware(hw.Slot)
}

func (c *Controller) promptUnlock(title string) {
	// A vault whose only factor is the token has nothing to ask for: go
	// straight to the key.
	if hw := model.VaultHardware(c.storePath); hw.Needed && hw.NoPassphrase {
		c.unlockWith(title, model.Unlock{Hardware: c.hardware()})
		return
	}
	c.promptUnlockHint(title, "passphrase for "+c.storePath)
}

func (c *Controller) promptUnlockHint(title, hint string) {
	if hw := model.VaultHardware(c.storePath); hw.Needed {
		hint += fmt.Sprintf(" (and its YubiKey, slot %d)", hw.Slot)
	}
	c.v.ShowPassphraseForm(title, hint, false, func(pass string) {
		c.unlockWith(title, model.Unlock{Passphrase: pass, Hardware: c.hardware()})
	}, nil) // no cancel: a locked vault has nothing to show
}

// unlockWith opens the vault off the event-loop goroutine. The key derivation
// already costs ~100ms, and a touch-protected YubiKey can take seconds, so
// doing it inline would freeze the screen with nothing on it explaining why.
func (c *Controller) unlockWith(title string, u model.Unlock) {
	needsKey := u.Hardware != nil
	// The waiting dialog goes up for every unlock, not only the slow ones: it
	// also takes the passphrase form off the screen, so the OK button cannot
	// be pressed a second time while the first attempt is still running.
	waiting := "deriving the key..."
	if needsKey {
		waiting = "asking the YubiKey -- touch it if it starts blinking"
	}
	c.v.ShowWaiting("Unlocking", waiting)
	// Rate-limit guessing. The KDF already costs ~0.1s per attempt; this makes
	// a sustained attempt against an unattended terminal pointless.
	delay := c.unlockDelay()
	path := c.storePath
	go func() {
		if delay > 0 {
			time.Sleep(delay)
		}
		s, key, err := model.OpenVaultFileUnlocked(path, u)
		// A touch can take seconds, and the user may have quit in the
		// meantime. Queueing an update on a stopped application blocks this
		// goroutine for good once the queue fills.
		select {
		case <-c.done:
			if key != nil {
				key.Zero()
			}
			return
		default:
		}
		c.v.App.QueueUpdateDraw(func() {
			if err != nil {
				c.failedUnlocks++
				// Rebuild the prompt rather than flashing in place: otherwise
				// the rejected passphrase stays in the field and focus stays
				// on the button, so the user has to clear it by hand before
				// retrying.
				again := fmt.Sprintf("[red]%v[-] -- try again", err)
				if d := c.unlockDelay(); d > 0 {
					again += fmt.Sprintf(" (waiting %s between attempts)", d)
				}
				if needsKey && u.Passphrase == "" {
					// Nothing was typed, so there is no form to put back up;
					// offer a retry the user can trigger.
					c.v.ConfirmOne("Unlock failed", again, "Try again", func() {
						c.promptUnlock(title)
					})
					return
				}
				c.promptUnlockHint(title, again)
				return
			}
			c.adoptStore(s, key)
			c.v.Flash("[green]unlocked")
		})
	}()
}

// lock discards the decrypted accounts and the key. Everything is saved on
// every mutation, so there is nothing to flush first.
func (c *Controller) lock(reason string) {
	if c.key == nil || c.locked {
		return
	}
	c.store.Wipe()
	c.store = &model.Store{}
	c.key.Zero()
	c.key = nil
	c.locked = true
	c.selected = ""
	c.reveal = false
	c.refreshList()
	c.v.RenderNoSelection()
	c.promptUnlock(reason)
}

func (c *Controller) onLock() {
	if c.key == nil {
		c.v.Flash("[yellow]vault is not encrypted -- press P to set a passphrase first")
		return
	}
	c.lock("Locked")
}

// unlockDelay backs off after repeated failures, capped so a genuine typo does
// not lock the owner out for minutes.
func (c *Controller) unlockDelay() time.Duration {
	if c.failedUnlocks < 3 {
		return 0
	}
	d := time.Duration(c.failedUnlocks-2) * time.Second
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

func (c *Controller) onActivity() { c.touch() }
func (c *Controller) touch()      { c.lastActivity = time.Now() }

// checkIdle runs on the event-loop goroutine via the refresh tick.
func (c *Controller) checkIdle() {
	if c.opts.IdleLock <= 0 || c.key == nil || c.locked {
		return
	}
	if time.Since(c.lastActivity) >= c.opts.IdleLock {
		c.lock("Locked after inactivity")
	}
}

// newKeyFor derives a key for a new passphrase, keeping whatever hardware
// binding the vault already has. Deriving a plain key here would quietly throw
// the YubiKey factor away the next time somebody changed their passphrase.
func (c *Controller) newKeyFor(pass string) (*model.Key, error) {
	if hw := model.VaultHardware(c.storePath); hw.Needed {
		r := c.hardware()
		if r == nil {
			return nil, fmt.Errorf("this vault is sealed to a YubiKey, which this build cannot reach")
		}
		return model.NewHardwareKey(model.Unlock{Passphrase: pass, Hardware: r}, hw.Slot)
	}
	return model.NewKey(pass)
}

func (c *Controller) onPassphrase() {
	if c.key == nil {
		c.v.ShowPassphraseForm("Encrypt vault", "choose a passphrase -- there is no recovery if you forget it", true,
			func(pass string) {
				if pass == "" {
					c.v.Flash("[red]passphrase is empty")
					return
				}
				key, err := c.newKeyFor(pass)
				if err != nil {
					c.v.Flash(fmt.Sprintf("[red]%v", err))
					return
				}
				if err := c.store.SaveWithKey(c.storePath, key); err != nil {
					key.Zero()
					c.v.Flash(fmt.Sprintf("[red]SAVE FAILED: %v", err))
					return
				}
				c.key = key
				c.v.SetVaultStatus(true)
				c.v.RestoreRoot()
				c.v.Flash("[green]vault encrypted")
				c.offerKeyring(pass)
			}, func() { c.v.RestoreRoot() })
		return
	}
	c.v.ShowPassphraseForm("Change passphrase", "leave both fields empty to remove encryption", true,
		func(pass string) {
			if pass == "" {
				c.v.RestoreRoot()
				c.confirmDecrypt()
				return
			}
			key, err := c.newKeyFor(pass)
			if err != nil {
				c.v.Flash(fmt.Sprintf("[red]%v", err))
				return
			}
			if err := c.store.SaveWithKey(c.storePath, key); err != nil {
				key.Zero()
				c.v.Flash(fmt.Sprintf("[red]SAVE FAILED: %v", err))
				return
			}
			c.key.Zero()
			c.key = key
			c.v.RestoreRoot()
			c.v.Flash("[green]passphrase changed")
			// A stored passphrase is now stale either way.
			_ = keyring.Delete(c.storePath)
			c.offerKeyring(pass)
		}, func() { c.v.RestoreRoot() })
}

// offerKeyring asks once whether to remember the passphrase in the OS secret
// store. It is never assumed: storing it means anything that can talk to your
// session's secret service can read it back.
func (c *Controller) offerKeyring(pass string) {
	if !c.opts.UseKeyring || !keyring.Available() {
		return
	}
	c.v.Confirm(
		"Remember this passphrase in the OS keyring?\n\n"+
			"tpduck will then unlock without asking.\nAnything that can read your keyring can read it too.",
		"Remember",
		func() {
			if err := keyring.Set(c.storePath, pass); err != nil {
				c.v.Flash(fmt.Sprintf("[red]keyring: %v", err))
			} else {
				c.v.Flash("[green]passphrase stored in the OS keyring")
			}
			c.v.RestoreRoot()
		},
		func() { c.v.RestoreRoot() })
}

func (c *Controller) confirmDecrypt() {
	c.v.Confirm("Remove encryption?\n\nSecrets will be written to disk in plaintext.", "Remove", func() {
		if err := c.store.SaveWithKey(c.storePath, nil); err != nil {
			c.v.Flash(fmt.Sprintf("[red]SAVE FAILED: %v", err))
			c.v.RestoreRoot()
			return
		}
		c.key.Zero()
		c.key = nil
		_ = keyring.Delete(c.storePath)
		c.v.SetVaultStatus(false)
		c.v.RestoreRoot()
		c.v.Flash("[yellow]vault is now stored in plaintext")
	}, func() { c.v.RestoreRoot() })
}

// save persists the store and surfaces failures instead of dropping them: a
// silent save error means the user walks away believing a secret was stored.
func (c *Controller) save() bool {
	err := c.store.SaveWithKey(c.storePath, c.key)
	if err == nil {
		return true
	}
	if errors.Is(err, model.ErrVaultChanged) {
		c.resolveConflict()
		return false
	}
	c.v.Flash(fmt.Sprintf("[red]SAVE FAILED: %v", err))
	return false
}

// resolveConflict asks what to do when the vault was modified underneath us --
// another tpduck, or a sync tool. Both answers are lossy in one direction, so
// the choice belongs to the user rather than to whichever writer ran last.
func (c *Controller) resolveConflict() {
	c.v.Confirm(
		"The vault changed on disk.\n\nAnother tpduck or a sync tool wrote to it.\n"+
			"Keep what is on screen, or discard it and reload?",
		"Overwrite",
		func() {
			if err := c.store.ForceSaveWithKey(c.storePath, c.key); err != nil {
				c.v.Flash(fmt.Sprintf("[red]SAVE FAILED: %v", err))
			} else {
				c.v.Flash("[yellow]overwrote the other version")
			}
			c.v.RestoreRoot()
		},
		func() {
			c.v.RestoreRoot()
			c.reloadFromDisk()
		})
}

// reloadFromDisk takes the on-disk version, discarding unsaved changes.
func (c *Controller) reloadFromDisk() {
	store, err := model.LoadStoreWithKey(c.storePath, c.key)
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]reload failed: %v", err))
		return
	}
	c.store = store
	c.store.Sort()
	if c.store.FindIndexByID(c.selected) < 0 {
		c.selected = ""
		if len(c.store.Accounts) > 0 {
			c.selected = c.store.Accounts[0].ID
		}
	}
	c.refreshList()
	c.v.Flash("[yellow]reloaded from disk; your unsaved change was discarded")
}

// --- list and selection -----------------------------------------------------

// visible returns the accounts matching the active search filter.
func (c *Controller) visible() []model.Account {
	if c.filter == "" {
		return c.store.Accounts
	}
	out := make([]model.Account, 0, len(c.store.Accounts))
	for _, a := range c.store.Accounts {
		if a.Matches(c.filter) {
			out = append(out, a)
		}
	}
	return out
}

// refreshList redraws the table and keeps the selection on something visible.
func (c *Controller) refreshList() {
	vis := c.visible()
	found := false
	for _, a := range vis {
		if a.ID == c.selected {
			found = true
			break
		}
	}
	if !found {
		c.selected = ""
		if len(vis) > 0 {
			c.selected = vis[0].ID
		}
	}
	c.v.PopulateTable(vis, c.selected)
	c.renderDetailAndCode()
}

func (c *Controller) onSearch(q string) {
	c.filter = q
	c.refreshList()
}

func (c *Controller) onSelect(id string) { c.selected = id; c.renderDetailAndCode() }

func (c *Controller) current() *model.Account {
	if c.selected == "" {
		return nil
	}
	i := c.store.FindIndexByID(c.selected)
	if i < 0 {
		return nil
	}
	return &c.store.Accounts[i]
}

// --- account actions --------------------------------------------------------

func (c *Controller) onAdd() {
	initial := model.Account{Digits: model.DefaultDigits, Period: model.DefaultPeriod, Algo: model.AlgoSHA1, Type: model.TypeTOTP}
	c.v.ShowAccountForm("Add Account", initial, func(acc model.Account) {
		if !c.normalizeAndValidate(&acc) {
			return
		}
		// Without this, two accounts can share an ID and every lookup
		// (select, edit, delete) silently resolves to the first of them.
		acc.ID = c.store.UniqueID(model.MakeID(acc), -1)
		acc.AddedAt = time.Now().Unix()
		c.store.Accounts = append(c.store.Accounts, acc)
		c.selected = acc.ID
		// Close the form before saving, never after: a save that finds the
		// vault changed underneath us puts its own dialog up, and restoring
		// the root afterwards would take that dialog away before it could be
		// read, losing both the choice and the write.
		c.v.RestoreRoot()
		c.save()
		c.refreshList()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onEdit() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	origID := acc.ID
	c.v.ShowAccountForm("Edit Account", *acc, func(updated model.Account) {
		if !c.normalizeAndValidate(&updated) {
			return
		}
		i := c.store.FindIndexByID(origID)
		if i < 0 {
			c.v.Flash("[red]account vanished; not saved")
			return
		}
		updated.ID = c.store.UniqueID(model.MakeID(updated), i)
		c.store.Accounts[i] = updated
		c.selected = updated.ID
		c.v.RestoreRoot() // before the save; see onAdd
		c.save()
		c.refreshList()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) normalizeAndValidate(a *model.Account) bool {
	a.Secret = model.NormalizeSecret(a.Secret)
	a.Issuer = strings.TrimSpace(a.Issuer)
	a.Name = strings.TrimSpace(a.Name)
	if err := a.Validate(); err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return false
	}
	return true
}

func (c *Controller) onDelete() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	c.v.ConfirmDelete(*acc, func() {
		i := c.store.FindIndexByID(acc.ID)
		removed := i >= 0
		if removed {
			c.store.Accounts = append(c.store.Accounts[:i], c.store.Accounts[i+1:]...)
		}
		c.selected = ""
		if n := len(c.store.Accounts); n > 0 {
			if i < 0 || i >= n {
				i = n - 1
			}
			c.selected = c.store.Accounts[i].ID
		}
		c.v.RestoreRoot() // before the save; see onAdd
		if removed {
			c.save()
		}
		c.refreshList()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onImport() {
	c.v.ShowImportURIForm(func(uri string) {
		added, err := ImportURI(c.store, uri)
		if err != nil {
			c.v.Flash(fmt.Sprintf("[red]%v", err))
			return
		}
		if len(added) > 0 {
			c.selected = added[len(added)-1]
		}
		c.v.RestoreRoot() // before the save; see onAdd
		saved := c.save()
		c.refreshList()
		if saved {
			c.v.Flash(fmt.Sprintf("[green]imported %d account(s)", len(added)))
		}
	}, func() { c.v.RestoreRoot() })
}

// ImportURI adds every account described by an otpauth:// or
// otpauth-migration:// URI, returning the IDs it created.
func ImportURI(store *model.Store, uri string) ([]string, error) {
	accounts, err := ResolveImport(uri)
	if err != nil {
		return nil, err
	}
	return addAll(store, accounts), nil
}

// ResolveImport turns whatever the user supplied -- an otpauth:// URI, a
// migration URI, a path to another authenticator's backup, or a path to a
// screenshot containing a QR code -- into accounts.
func ResolveImport(input string) ([]model.Account, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, fmt.Errorf("nothing to import")
	}
	if strings.HasPrefix(strings.ToLower(input), "otpauth") {
		if model.IsMigrationURI(input) {
			return model.ParseMigrationURI(input)
		}
		acc, err := model.ParseOtpauthURI(input)
		if err != nil {
			return nil, err
		}
		return []model.Account{*acc}, nil
	}
	// Not a URI, so it must be a file.
	info, err := os.Stat(expandHome(input))
	if err != nil {
		return nil, fmt.Errorf("not a URI, and not a readable file: %s", input)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", input)
	}
	path := expandHome(input)
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif":
		text, err := model.DecodeQRImage(path)
		if err != nil {
			return nil, err
		}
		return ResolveImport(text)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	accounts, _, err := model.ParseBackup(data)
	return accounts, err
}

// expandHome resolves a leading ~ so typed paths behave as in a shell.
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func addAll(store *model.Store, accounts []model.Account) []string {
	ids := make([]string, 0, len(accounts))
	for _, acc := range accounts {
		acc.ID = store.UniqueID(model.MakeID(acc), -1)
		store.Accounts = append(store.Accounts, acc)
		ids = append(ids, acc.ID)
	}
	return ids
}

func (c *Controller) onExport() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	uri := acc.URI()
	qr, err := model.QRBlocks(uri)
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	// URI first: the QR is taller than most terminals, and scrolling to find
	// out what you are about to hand over is the wrong way round. The text view
	// cannot soft-wrap (that would mangle the QR), so the URI is wrapped here.
	body := wrapAt(uri, 74) + "\n\n" + qr
	c.v.ShowTextModal(fmt.Sprintf("Export %s (scan or copy -- this is the secret)", acc.Label()), body,
		func() { c.v.RestoreRoot() })
}

// wrapAt hard-wraps s into lines of at most n characters.
func wrapAt(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n])
		b.WriteByte('\n')
		s = s[n:]
	}
	b.WriteString(s)
	return b.String()
}

func (c *Controller) onAdvance() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	if acc.Kind() != model.TypeHOTP {
		c.v.Flash("[yellow]only counter-based (HOTP) accounts have a counter")
		return
	}
	if err := c.store.AdvanceHOTP(acc.ID); err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	saved := c.save()
	c.refreshList()
	if saved {
		c.v.Flash(fmt.Sprintf("[green]counter advanced to %d", c.current().Counter))
	}
}

func (c *Controller) onPin() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	pinned, err := c.store.TogglePinned(acc.ID)
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	saved := c.save()
	c.refreshList()
	if !saved {
		return
	}
	if pinned {
		c.v.Flash("[green]pinned to the top")
	} else {
		c.v.Flash("[gray]unpinned")
	}
}

func (c *Controller) onOrder() {
	if c.store.Order == model.SortByUsed {
		c.store.Order = model.SortByIssuer
	} else {
		c.store.Order = model.SortByUsed
	}
	saved := c.save()
	c.refreshList()
	if saved {
		c.v.Flash(fmt.Sprintf("[green]ordering by %s", c.store.Order))
	}
}

func (c *Controller) onResync() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	if acc.Kind() != model.TypeHOTP {
		c.v.Flash("[yellow]only counter-based (HOTP) accounts can drift out of sync")
		return
	}
	id := acc.ID
	c.v.ShowPrompt("Resync counter", "Code shown by the server",
		fmt.Sprintf("searching up to %d steps from counter %d", model.DefaultResyncLookahead, acc.Counter),
		func(code string) {
			n, err := c.store.ResyncHOTP(id, strings.TrimSpace(code), model.DefaultResyncLookahead)
			if err != nil {
				c.v.Flash(fmt.Sprintf("[red]%v", err))
				return
			}
			c.v.RestoreRoot() // before the save; see onAdd
			saved := c.save()
			c.refreshList()
			if saved {
				c.v.Flash(fmt.Sprintf("[green]counter resynced to %d", n))
			}
		}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onVerify() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	target := *acc
	c.v.ShowPrompt("Verify a code", "Code to check",
		"checks this account against the code a server showed you",
		func(code string) {
			res, err := model.Verify(target, strings.TrimSpace(code), c.store.Now(), model.DefaultVerifyWindow)
			if err != nil {
				c.v.Flash(fmt.Sprintf("[red]%v", err))
				return
			}
			c.v.RestoreRoot()
			switch {
			case res.OK && res.Offset == 0:
				c.v.Flash("[green]matches the current code")
			case res.OK:
				c.v.Flash(fmt.Sprintf("[yellow]matches, but %+d window(s) away -- check your clock (K)", res.Offset))
			default:
				c.v.Flash("[red]no match within the accepted window")
			}
		}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onMigrate() {
	if len(c.store.Accounts) == 0 {
		c.v.Flash("[yellow]nothing to export")
		return
	}
	uris, skipped, err := model.BuildMigrationURIs(c.store.Accounts, model.DefaultMigrationBatch)
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "%d account(s) in %d QR code(s).\n", len(c.store.Accounts)-len(skipped), len(uris))
	fmt.Fprintf(b, "Scan each one with Google Authenticator's \"Import accounts\".\n")
	fmt.Fprintf(b, "Every code below contains secrets.\n")
	if len(skipped) > 0 {
		labels := make([]string, 0, len(skipped))
		for _, a := range skipped {
			labels = append(labels, a.Label())
		}
		fmt.Fprintf(b, "\nLeft out (the migration format has no Steam Guard): %s\n"+
			"Export those with X instead.\n", strings.Join(labels, ", "))
	}
	for i, u := range uris {
		qr, err := model.QRBlocks(u)
		if err != nil {
			c.v.Flash(fmt.Sprintf("[red]%v", err))
			return
		}
		fmt.Fprintf(b, "\n--- batch %d of %d ---\n\n%s", i+1, len(uris), qr)
	}
	c.v.ShowTextModal("Migration export", b.String(), func() { c.v.RestoreRoot() })
}

func (c *Controller) onReveal() { c.reveal = !c.reveal; c.renderDetailOnly() }

func (c *Controller) onCopy() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	code, err := model.Generate(*acc, c.store.Now())
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	c.store.MarkUsed(acc.ID)
	c.save()
	if c.store.Order == model.SortByUsed {
		c.refreshList()
	}
	res, err := c.clip.Copy(code.Value, c.opts.ClipClear, func() {
		c.v.App.QueueUpdateDraw(func() { c.v.Flash("[gray]clipboard cleared") })
	})
	if err != nil {
		c.v.Flash(fmt.Sprintf("[yellow]%s (no clipboard helper: %v)", code.Value, err))
		return
	}
	what := "copied"
	if res.Sensitive {
		// Worth saying: it is the difference between a code a clipboard
		// manager has already recorded and one it was asked to skip.
		what = "copied (marked sensitive)"
	}
	switch {
	case c.opts.ClipClear > 0:
		c.v.Flash(fmt.Sprintf("[green]%s -- clipboard clears in %s", what, c.opts.ClipClear))
	default:
		c.v.Flash("[green]" + what + " to clipboard")
	}
}

func (c *Controller) onSkew() {
	c.v.Flash("[gray]checking clock against " + c.ntpServer() + " ...")
	server := c.ntpServer()
	period := c.shortestPeriod()
	// The network call must not block the event loop.
	go func() {
		skew, err := model.ClockSkew(server, 5*time.Second)
		c.v.App.QueueUpdateDraw(func() {
			if err != nil {
				c.v.Flash(fmt.Sprintf("[red]clock check failed: %v", err))
				return
			}
			text, bad := model.SkewVerdict(skew, period)
			colour := "green"
			if bad {
				colour = "red"
			}
			c.v.Flash(fmt.Sprintf("[%s]%s", colour, text))
		})
	}()
}

func (c *Controller) ntpServer() string {
	if c.opts.NTPServer != "" {
		return c.opts.NTPServer
	}
	return model.DefaultNTPServer
}

func (c *Controller) shortestPeriod() int {
	shortest := model.DefaultPeriod
	for _, a := range c.store.Accounts {
		if a.Kind() != model.TypeHOTP && a.Period > 0 && a.Period < shortest {
			shortest = a.Period
		}
	}
	return shortest
}

func (c *Controller) onHelp() {
	c.v.ShowTextModal("Keys", helpText(c.storePath, c.opts, c.store.TimeOffsetSeconds), func() { c.v.RestoreRoot() })
}

func helpText(path string, o Options, offsetSeconds int64) string {
	idle := "off"
	if o.IdleLock > 0 {
		idle = o.IdleLock.String()
	}
	clip := "never"
	if o.ClipClear > 0 {
		clip = o.ClipClear.String()
	}
	keyringState := "off (-keyring to enable)"
	if o.UseKeyring {
		keyringState = "enabled"
		if !keyring.Available() {
			keyringState = "enabled, but no secret service is reachable"
		}
	}
	offset := "none"
	if offsetSeconds != 0 {
		offset = fmt.Sprintf("%+ds (tpduck offset)", offsetSeconds)
	}
	return strings.Join([]string{
		"  Navigation",
		"    up/down     move between accounts (details follow the cursor)",
		"    Enter       copy the highlighted code",
		"    /           search; \"tag:work\" filters by tag",
		"    F           pin/unpin to the top of the list",
		"    O           switch between alphabetical and most-recently-used",
		"",
		"  Accounts",
		"    A           add            E  edit           D  delete",
		"    I           import        X  export (QR + otpauth URI)",
		"    M           export every account as migration QR codes",
		"    N           advance the counter of an HOTP account",
		"    Y           resync an HOTP counter against a server code",
		"",
		"  Codes",
		"    C           copy the current code to the clipboard",
		"    V           verify a code a server showed you",
		"    R           reveal/hide the stored secret",
		"    K           check the system clock against network time",
		"",
		"  Vault",
		"    P           set, change or remove the passphrase",
		"    L           lock now (encrypted vaults only)",
		"    Q, Ctrl-Q   quit",
		"",
		"  This session",
		"    vault       " + path,
		"    auto-lock   " + idle,
		"    clipboard   cleared after " + clip,
		"    keyring     " + keyringState,
		"    time offset " + offset,
		"",
		"  Types: TOTP, HOTP and Steam Guard.",
		"",
		"  Import accepts otpauth:// URIs, Google Authenticator",
		"  otpauth-migration:// exports, a path to an Aegis / andOTP /",
		"  2FAS / KeePassXC backup, or a path to a PNG screenshot of a",
		"  QR code.",
	}, "\n")
}

// --- rendering --------------------------------------------------------------

func (c *Controller) renderDetailAndCode() { c.renderDetailOnly(); c.renderCodeOnly() }

func (c *Controller) renderDetailOnly() {
	acc := c.current()
	if acc == nil {
		c.v.RenderNoSelection()
		return
	}
	c.v.RenderDetails(acc, c.reveal)
}

func (c *Controller) renderCodeOnly() {
	if c.locked {
		return
	}
	acc := c.current()
	if acc == nil {
		c.v.RenderNoSelection()
		return
	}
	code, err := model.Generate(*acc, c.store.Now())
	if err != nil {
		// This runs on every tick; only flash when the message actually changes.
		if msg := err.Error(); msg != c.lastErr {
			c.lastErr = msg
			c.v.Flash(fmt.Sprintf("[red]error: %v", msg))
		}
		c.v.RenderCodeError()
		return
	}
	c.lastErr = ""
	if code.Static {
		c.v.RenderStaticCode(code.Value, acc.Counter)
		return
	}
	// Once the window is nearly spent, show what comes next so a code is not
	// pasted moments before it expires.
	var next string
	if code.Remain <= nextCodeThreshold {
		period := acc.Period
		if period <= 0 {
			period = model.DefaultPeriod
		}
		if n, err := model.Generate(*acc, c.store.Now().Add(time.Duration(period)*time.Second)); err == nil {
			next = n.Value
		}
	}
	c.v.RenderCode(code.Value, code.Remain, acc.Period, next)
}

func (c *Controller) onQuit() { c.v.Stop() }
