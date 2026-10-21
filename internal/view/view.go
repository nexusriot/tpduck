package view

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/nexusriot/tpduck/internal/model"
)

const keyHints = "[yellow]A add  E edit  D del  I import  X export  M migrate  F pin  O order  N next  Y resync  V verify  / search  R reveal  C copy  P pass  L lock  K clock  ? help  Q quit[-]"

type Handlers struct {
	OnAdd        func()
	OnEdit       func()
	OnDelete     func()
	OnImport     func()
	OnExport     func()
	OnReveal     func()
	OnCopy       func()
	OnQuit       func()
	OnSelect     func(id string)
	OnSearch     func(query string)
	OnAdvance    func()
	OnPassphrase func()
	OnLock       func()
	OnSkew       func()
	OnHelp       func()
	OnPin        func()
	OnOrder      func()
	OnResync     func()
	OnVerify     func()
	OnMigrate    func()
	OnActivity   func()
	// OnStart runs once the event loop owns the screen. Anything that sets a
	// root before Run would be overwritten by Run's own SetRoot.
	OnStart func()
}

type View struct {
	App        *tview.Application
	Table      *tview.Table
	CodeView   *tview.TextView
	DetailView *tview.TextView
	Footer     *tview.TextView
	Search     *tview.InputField

	main       tview.Primitive
	root       *tview.Flex
	searchOpen bool

	// modal is true while a form or dialog owns the screen. The single-letter
	// shortcuts must stay inert then, otherwise typing a Base32 secret (which
	// contains A, C, D, E, I, Q and R) fires Add/Copy/Delete/... instead of
	// reaching the input field.
	modal bool
	// populating suppresses selection callbacks while the table is rebuilt.
	populating bool
	// formStatus receives messages while a form owns the screen; the footer is
	// not visible then, so validation errors would otherwise vanish and the
	// Save button would look dead.
	formStatus *tview.TextView

	h Handlers
}

func New() *View {
	v := &View{App: tview.NewApplication()}

	v.Table = tview.NewTable()
	v.Table.SetSelectable(true, false)
	v.Table.SetBorder(true)
	v.Table.SetTitle(" Accounts ")

	v.CodeView = tview.NewTextView()
	v.CodeView.SetDynamicColors(true)
	v.CodeView.SetBorder(true)
	v.CodeView.SetTitle(" Code ")
	v.CodeView.SetTextAlign(tview.AlignCenter)

	v.DetailView = tview.NewTextView()
	v.DetailView.SetDynamicColors(true)
	v.DetailView.SetBorder(true)
	v.DetailView.SetTitle(" Details ")

	v.Footer = tview.NewTextView()
	v.Footer.SetDynamicColors(true)
	v.Footer.SetText("  " + keyHints)

	v.Search = tview.NewInputField()
	v.Search.SetLabel(" / ")
	v.Search.SetFieldWidth(0)

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(v.CodeView, 7, 0, false).
		AddItem(v.DetailView, 0, 1, false).
		AddItem(v.Footer, 1, 0, false)

	v.main = tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(v.Table, 0, 2, true).
		AddItem(right, 0, 3, false)

	v.root = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(v.main, 0, 1, true)
	return v
}

func (v *View) SetHandlers(h Handlers) { v.h = h }

func (v *View) Run() error {
	// Fire on cursor movement, not only on Enter: the panel must follow the
	// highlighted row.
	v.Table.SetSelectionChangedFunc(v.emitSelection)
	// Enter on a row copies it: that is what you came to the list to do.
	v.Table.SetSelectedFunc(func(row, col int) {
		v.emitSelection(row, col)
		if v.h.OnCopy != nil {
			v.h.OnCopy()
		}
	})
	v.App.EnableMouse(true)
	v.App.SetRoot(v.root, true).SetFocus(v.Table)
	v.App.SetInputCapture(v.handleKey)
	if v.h.OnStart != nil {
		v.h.OnStart()
	}
	return v.App.Run()
}

func (v *View) handleKey(ev *tcell.EventKey) *tcell.EventKey {
	if v.h.OnActivity != nil {
		v.h.OnActivity()
	}
	// Ctrl-Q quits from anywhere, including a form; Ctrl-C is tview's own.
	if ev.Key() == tcell.KeyCtrlQ {
		if v.h.OnQuit != nil {
			v.h.OnQuit()
		}
		return nil
	}
	// While a form, dialog or the search field is up, every key belongs to it.
	if v.modal || v.searchOpen {
		return ev
	}
	if ev.Key() != tcell.KeyRune || ev.Modifiers()&(tcell.ModAlt|tcell.ModCtrl) != 0 {
		return ev
	}
	call := func(f func()) *tcell.EventKey {
		if f != nil {
			f()
		}
		return nil
	}
	switch ev.Rune() {
	case 'q', 'Q':
		return call(v.h.OnQuit)
	case 'a', 'A':
		return call(v.h.OnAdd)
	case 'e', 'E':
		return call(v.h.OnEdit)
	case 'd', 'D':
		return call(v.h.OnDelete)
	case 'i', 'I':
		return call(v.h.OnImport)
	case 'x', 'X':
		return call(v.h.OnExport)
	case 'r', 'R':
		return call(v.h.OnReveal)
	case 'c', 'C':
		return call(v.h.OnCopy)
	case 'n', 'N':
		return call(v.h.OnAdvance)
	case 'p', 'P':
		return call(v.h.OnPassphrase)
	case 'l', 'L':
		return call(v.h.OnLock)
	case 'k', 'K':
		return call(v.h.OnSkew)
	case 'f', 'F':
		return call(v.h.OnPin)
	case 'o', 'O':
		return call(v.h.OnOrder)
	case 'y', 'Y':
		return call(v.h.OnResync)
	case 'v', 'V':
		return call(v.h.OnVerify)
	case 'm', 'M':
		return call(v.h.OnMigrate)
	case '?':
		return call(v.h.OnHelp)
	case '/':
		return call(v.openSearch)
	}
	return ev
}

func (v *View) emitSelection(row, _ int) {
	if v.populating || row <= 0 || v.h.OnSelect == nil {
		return
	}
	cell := v.Table.GetCell(row, 0)
	if cell == nil {
		return
	}
	if id, ok := cell.GetReference().(string); ok {
		v.h.OnSelect(id)
	}
}

func (v *View) Stop() { v.App.Stop() }

// --- search -----------------------------------------------------------------

func (v *View) openSearch() {
	if v.searchOpen {
		return
	}
	v.searchOpen = true
	v.Search.SetText("")
	v.Search.SetChangedFunc(func(q string) {
		if v.h.OnSearch != nil {
			v.h.OnSearch(q)
		}
	})
	v.Search.SetDoneFunc(func(key tcell.Key) {
		switch key {
		case tcell.KeyEscape:
			v.closeSearch(true)
		case tcell.KeyEnter, tcell.KeyTab:
			v.closeSearch(false) // keep the filter, move back to the list
		}
	})
	v.root.Clear()
	v.root.AddItem(v.Search, 1, 0, true).AddItem(v.main, 0, 1, false)
	v.App.SetFocus(v.Search)
}

// closeSearch leaves the search field. Clearing also drops the filter.
func (v *View) closeSearch(clear bool) {
	if !v.searchOpen {
		return
	}
	v.searchOpen = false
	if clear {
		v.Search.SetText("")
		if v.h.OnSearch != nil {
			v.h.OnSearch("")
		}
	}
	v.root.Clear()
	v.root.AddItem(v.main, 0, 1, true)
	v.App.SetFocus(v.Table)
}

// SearchQuery returns the active filter, or "" when searching is off.
func (v *View) SearchQuery() string {
	if v.Search == nil {
		return ""
	}
	return v.Search.GetText()
}

// --- table and panels -------------------------------------------------------

func (v *View) PopulateTable(accts []model.Account, selectedID string) {
	v.populating = true
	defer func() { v.populating = false }()
	v.Table.Clear()
	// Three columns, not seven: the list shares the screen with the code and
	// detail panels, so on an 80-column terminal it only has about thirty
	// columns to work with. The ID is omitted because it is just the issuer and
	// name lower-cased; the full parameters are in the Details panel.
	for i, h := range []string{"Issuer", "Name", "Opts"} {
		v.Table.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false).SetAttributes(tcell.AttrBold))
	}
	for r, acc := range accts {
		row := r + 1
		issuer := acc.Issuer
		if issuer == "" {
			issuer = "[gray]-[-]"
		}
		if acc.Pinned {
			issuer = "*" + issuer
		}
		v.Table.SetCell(row, 0, tview.NewTableCell(issuer).SetReference(acc.ID).SetMaxWidth(14))
		v.Table.SetCell(row, 1, tview.NewTableCell(acc.Name).SetMaxWidth(18))
		v.Table.SetCell(row, 2, tview.NewTableCell(params(acc)))
		if acc.ID == selectedID {
			v.Table.Select(row, 0)
		}
	}
	if selectedID == "" && len(accts) > 0 {
		v.Table.Select(1, 0)
	}
	title := fmt.Sprintf(" Accounts (%d) ", len(accts))
	if q := v.SearchQuery(); q != "" {
		title = fmt.Sprintf(" Accounts (%d matching %q) ", len(accts), q)
	}
	v.Table.SetTitle(title)
}

// RenderCode shows a time-based code with its countdown bar. `next` is the
// code for the following window, shown once the current one is nearly spent so
// you do not paste a code that expires while the form is submitting.
func (v *View) RenderCode(code string, remain, period int, next string) {
	barW := 24
	if period <= 0 {
		period = model.DefaultPeriod
	}
	fill := int(float64(period-remain) / float64(period) * float64(barW))
	if fill < 0 {
		fill = 0
	}
	if fill > barW {
		fill = barW
	}
	colour := "white"
	if remain <= 5 {
		colour = "red"
	}
	bar := "[" + strings.Repeat("█", fill) + strings.Repeat("░", barW-fill) + "]"
	body := fmt.Sprintf("\n  [%s::b]%s[-:-:-]\n\n  %s  [gray]%ds left[-]\n", colour, group(code), bar, remain)
	if next != "" {
		body += fmt.Sprintf("  [gray]next: %s[-]\n", group(next))
	}
	v.CodeView.SetText(body)
}

// RenderStaticCode shows a counter-based code, which has no countdown.
func (v *View) RenderStaticCode(code string, counter uint64) {
	v.CodeView.SetText(fmt.Sprintf("\n  [white::b]%s[-:-:-]\n\n  [gray]counter %d -- press N after use[-]\n", group(code), counter))
}

func (v *View) RenderNoSelection() {
	v.CodeView.SetText("[gray]No account selected[-]")
	v.DetailView.SetText("—")
}

// RenderCodeError blanks the code panel when the selected account cannot
// produce one, rather than leaving a stale code on screen.
func (v *View) RenderCodeError() {
	v.CodeView.SetText("\n  [red]------[-]\n\n  [gray]cannot generate code[-]\n")
}

func (v *View) RenderDetails(acc *model.Account, reveal bool) {
	if acc == nil {
		v.DetailView.SetText("—")
		return
	}
	secret := "[hidden]"
	if reveal {
		secret = acc.Secret
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "Issuer:  [white]%s[-]\n", acc.Issuer)
	fmt.Fprintf(b, "Name:    [white]%s[-]\n", acc.Name)
	fmt.Fprintf(b, "Type:    [white]%s[-]\n", strings.ToUpper(string(acc.Kind())))
	fmt.Fprintf(b, "Digits:  [white]%d[-]\n", acc.Digits)
	if acc.Kind() == model.TypeHOTP {
		fmt.Fprintf(b, "Counter: [white]%d[-]\n", acc.Counter)
	} else {
		fmt.Fprintf(b, "Period:  [white]%d s[-]\n", acc.Period)
	}
	fmt.Fprintf(b, "Algo:    [white]%s[-]\n", acc.Algo)
	fmt.Fprintf(b, "Secret:  [white]%s[-]\n", secret)
	if len(acc.Tags) > 0 {
		fmt.Fprintf(b, "Tags:    [white]%s[-]\n", strings.Join(acc.Tags, ", "))
	}
	if acc.Notes != "" {
		fmt.Fprintf(b, "Notes:   [white]%s[-]\n", acc.Notes)
	}
	v.DetailView.SetText(b.String())
}

// SetVaultStatus shows the encryption state permanently in the title bar, so an
// unencrypted vault is never a silent condition.
func (v *View) SetVaultStatus(encrypted bool) {
	// Keep these short: a narrow terminal truncates a border title from the
	// left, which makes a long one look like a rendering fault.
	if encrypted {
		v.DetailView.SetTitle(" Details [green]*[-] ")
		return
	}
	v.DetailView.SetTitle(" Details [red]!plaintext[-] ")
}

func (v *View) Flash(msg string) {
	if v.modal && v.formStatus != nil {
		v.formStatus.SetText("  " + msg)
		return
	}
	v.Footer.SetText("  " + msg + "  |  " + keyHints)
}

// newFormStatus creates the one-line message strip shown under a form.
func (v *View) newFormStatus(hint string) *tview.TextView {
	t := tview.NewTextView()
	t.SetDynamicColors(true)
	t.SetWrap(true)
	t.SetWordWrap(true)
	t.SetText("  [gray]" + hint + "[-]")
	v.formStatus = t
	return t
}

// --- dialogs ----------------------------------------------------------------

func (v *View) ShowAccountForm(title string, initial model.Account, onSave func(model.Account), onCancel func()) {
	acc := initial

	algos := []string{string(model.AlgoSHA1), string(model.AlgoSHA256), string(model.AlgoSHA512)}
	algoIdx := 0
	for i, s := range algos {
		if s == string(acc.Algo) {
			algoIdx = i
			break
		}
	}
	digitIdx := 0
	if acc.Digits == 8 {
		digitIdx = 1
	}
	types := []string{string(model.TypeTOTP), string(model.TypeHOTP), string(model.TypeSteam)}
	typeIdx := 0
	switch acc.Kind() {
	case model.TypeHOTP:
		typeIdx = 1
	case model.TypeSteam:
		typeIdx = 2
	}

	form := tview.NewForm().
		AddInputField("Issuer", acc.Issuer, 40, nil, func(s string) { acc.Issuer = s }).
		AddInputField("Name", acc.Name, 40, nil, func(s string) { acc.Name = s }).
		AddInputField("Secret (Base32)", acc.Secret, 52, nil, func(s string) { acc.Secret = s }).
		AddDropDown("Type", types, typeIdx, func(opt string, _ int) { acc.Type = model.OTPType(opt) }).
		AddDropDown("Algo", algos, algoIdx, func(opt string, _ int) { acc.Algo = model.Algo(opt) }).
		AddDropDown("Digits", []string{"6", "8"}, digitIdx, func(opt string, _ int) {
			if v, _ := strconv.Atoi(opt); v != 0 {
				acc.Digits = v
			}
		}).
		AddInputField("Period (sec)", fmt.Sprintf("%d", acc.Period), 5,
			func(s string, _ rune) bool {
				if s == "" {
					return true
				}
				n, err := strconv.Atoi(s)
				return err == nil && n >= 0 && n <= model.MaxPeriod
			},
			func(s string) {
				if n, err := strconv.Atoi(s); err == nil {
					acc.Period = n
				} else if s == "" {
					acc.Period = 0
				}
			}).
		AddInputField("Counter (HOTP)", fmt.Sprintf("%d", acc.Counter), 12,
			func(s string, _ rune) bool {
				if s == "" {
					return true
				}
				_, err := strconv.ParseUint(s, 10, 64)
				return err == nil
			},
			func(s string) {
				if n, err := strconv.ParseUint(s, 10, 64); err == nil {
					acc.Counter = n
				} else if s == "" {
					acc.Counter = 0
				}
			}).
		AddInputField("Tags (comma-separated)", strings.Join(acc.Tags, ", "), 0, nil, func(s string) {
			acc.Tags = nil
			for _, t := range strings.Split(s, ",") {
				if t = strings.TrimSpace(t); t != "" {
					acc.Tags = append(acc.Tags, t)
				}
			}
		}).
		AddInputField("Notes", acc.Notes, 0, nil, func(s string) { acc.Notes = s })

	form.AddButton("Save", func() { onSave(acc) })
	form.AddButton("Cancel", func() { onCancel() })
	form.SetCancelFunc(onCancel) // ESC to cancel

	form.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)

	// Full-screen so nothing gets cut off on short terminals.
	full := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(v.newFormStatus("Tab/Shift-Tab to move, Enter on Save, ESC to cancel"), 2, 0, false)

	v.modal = true
	v.App.SetRoot(full, true)
	v.App.SetFocus(form)
}

func (v *View) ShowImportURIForm(onImport func(uri string), onCancel func()) {
	var uri string
	// Width 0 lets the field use whatever the dialog has; a fixed width wider
	// than the terminal pushes the label off the left edge.
	form := tview.NewForm().AddInputField("URI", "", 0, nil, func(s string) { uri = s })
	form.AddButton("Import", func() { onImport(uri) }).AddButton("Cancel", func() { onCancel() })
	form.SetCancelFunc(onCancel) // ESC to cancel
	form.SetBorder(true).SetTitle(" Import ")
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(v.newFormStatus("paste an otpauth:// or otpauth-migration:// URI, ESC to cancel"), 2, 0, false)
	v.modal = true
	v.App.SetRoot(center(dialogWidth, 11, wrap), true)
	v.App.SetFocus(form)
}

// ShowPassphraseForm asks for a passphrase, optionally twice for confirmation.
func (v *View) ShowPassphraseForm(title, hint string, confirm bool, onOK func(string), onCancel func()) {
	var pass, again string
	form := tview.NewForm()
	form.AddPasswordField("Passphrase", "", 0, '*', func(s string) { pass = s })
	if confirm {
		form.AddPasswordField("Confirm", "", 0, '*', func(s string) { again = s })
	}
	form.AddButton("OK", func() {
		if confirm && !model.ConstantTimeEqualString(pass, again) {
			v.Flash("[red]passphrases do not match")
			return
		}
		onOK(pass)
	})
	if onCancel != nil {
		form.AddButton("Cancel", func() { onCancel() })
		form.SetCancelFunc(onCancel)
	}
	form.SetBorder(true).SetTitle(" " + title + " ")
	h := 10
	if confirm {
		h = 12
	}
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(v.newFormStatus(hint), 2, 0, false)
	v.modal = true
	v.App.SetRoot(center(dialogWidth, h, wrap), true)
	v.App.SetFocus(form)
}

// ShowPrompt asks for a single line of text.
func (v *View) ShowPrompt(title, label, hint string, onOK func(string), onCancel func()) {
	var value string
	form := tview.NewForm().AddInputField(label, "", 0, nil, func(s string) { value = s })
	form.AddButton("OK", func() { onOK(value) }).AddButton("Cancel", func() { onCancel() })
	form.SetCancelFunc(onCancel)
	form.SetBorder(true).SetTitle(" " + title + " ")
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true).
		AddItem(v.newFormStatus(hint), 2, 0, false)
	v.modal = true
	v.App.SetRoot(center(dialogWidth, 10, wrap), true)
	v.App.SetFocus(form)
}

// ShowTextModal displays scrollable read-only text, used for exports, QR codes
// and help.
func (v *View) ShowTextModal(title, body string, onClose func()) {
	tv := tview.NewTextView()
	tv.SetDynamicColors(false)
	tv.SetWrap(false)
	tv.SetScrollable(true)
	tv.SetText(body)
	tv.SetBorder(true).SetTitle(" " + title + " ")
	tv.SetDoneFunc(func(tcell.Key) { onClose() })
	// A QR must be rendered dark-on-light to stay scannable.
	if strings.ContainsAny(body, "█▀▄") {
		tv.SetBackgroundColor(tcell.ColorWhite)
		tv.SetTextColor(tcell.ColorBlack)
	}
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(tv, 0, 1, true).
		AddItem(v.newFormStatus("ESC or Enter to close, arrows to scroll"), 2, 0, false)
	v.modal = true
	v.App.SetRoot(wrap, true)
	v.App.SetFocus(tv)
}

func (v *View) ConfirmDelete(acc model.Account, onDelete func(), onCancel func()) {
	modal := tview.NewModal().
		SetText(fmt.Sprintf("Delete %s / %s ?", acc.Issuer, acc.Name)).
		AddButtons([]string{"Delete", "Cancel"}).
		SetDoneFunc(func(ix int, label string) {
			if label == "Delete" {
				onDelete()
			} else {
				onCancel()
			}
		})
	v.modal = true
	v.App.SetRoot(center(50, 8, modal), true)
	v.App.SetFocus(modal)
}

// ShowWaiting puts up a message with no buttons, for something that will take
// long enough that a frozen screen would look like a crash.
func (v *View) ShowWaiting(title, text string) {
	tv := tview.NewTextView()
	tv.SetDynamicColors(true)
	tv.SetTextAlign(tview.AlignCenter)
	tv.SetText("\n" + text)
	tv.SetBorder(true).SetTitle(" " + title + " ")
	v.modal = true
	v.formStatus = nil
	v.App.SetRoot(center(60, 7, tv), true)
}

// ConfirmOne states something and offers a single way onward.
func (v *View) ConfirmOne(title, text, okLabel string, onOK func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{okLabel}).
		SetDoneFunc(func(int, string) { onOK() })
	v.modal = true
	v.App.SetRoot(center(60, 10, modal), true)
	v.App.SetFocus(modal)
}

// Confirm asks a yes/no question.
func (v *View) Confirm(text, okLabel string, onOK func(), onCancel func()) {
	modal := tview.NewModal().
		SetText(text).
		AddButtons([]string{okLabel, "Cancel"}).
		SetDoneFunc(func(_ int, label string) {
			if label == okLabel {
				onOK()
			} else {
				onCancel()
			}
		})
	v.modal = true
	v.App.SetRoot(center(60, 10, modal), true)
	v.App.SetFocus(modal)
}

func (v *View) RestoreRoot() {
	v.modal = false
	v.formStatus = nil
	v.App.SetRoot(v.root, true)
	if v.searchOpen {
		v.App.SetFocus(v.Search)
	} else {
		v.App.SetFocus(v.Table)
	}
}

// dialogWidth keeps dialogs inside an 80-column terminal, the narrowest still
// in common use. center() shrinks further on anything narrower.
const dialogWidth = 72

// center sizes p to at most w x h and places it in the middle of the screen,
// shrinking to fit when the terminal is smaller. A plain Flex cannot do this:
// its fixed sizes are chosen before the screen size is known, so a dialog wider
// than the terminal would be drawn off the edge.
type centered struct {
	*tview.Box
	inner tview.Primitive
	w, h  int
}

func center(w, h int, p tview.Primitive) tview.Primitive {
	return &centered{Box: tview.NewBox(), inner: p, w: w, h: h}
}

func (c *centered) Draw(screen tcell.Screen) {
	sw, sh := screen.Size()
	w, h := c.w, c.h
	if w > sw {
		w = sw
	}
	if h > sh {
		h = sh
	}
	c.inner.SetRect((sw-w)/2, (sh-h)/2, w, h)
	c.inner.Draw(screen)
}

func (c *centered) Focus(delegate func(p tview.Primitive)) { delegate(c.inner) }

func (c *centered) HasFocus() bool { return c.inner.HasFocus() }

func (c *centered) InputHandler() func(*tcell.EventKey, func(tview.Primitive)) {
	return c.inner.InputHandler()
}

func (c *centered) MouseHandler() func(tview.MouseAction, *tcell.EventMouse, func(tview.Primitive)) (bool, tview.Primitive) {
	return c.inner.MouseHandler()
}

// params renders an account's settings compactly for the list, e.g. "6/30s" or
// "8/c42" for a counter-based account.
func params(a model.Account) string {
	if a.Kind() == model.TypeHOTP {
		return fmt.Sprintf("%d/c%d", a.Digits, a.Counter)
	}
	return fmt.Sprintf("%d/%ds", a.Digits, a.Period)
}

// group splits a code in the middle, the way authenticator apps show it.
func group(code string) string {
	// Steam codes are five characters and are shown whole.
	if len(code) < 6 {
		return code
	}
	h := len(code) / 2
	return code[:h] + " " + code[h:]
}
