package view

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/nexusriot/tpduck/internal/model"
)

type Handlers struct {
	OnAdd    func()
	OnEdit   func()
	OnDelete func()
	OnImport func()
	OnReveal func()
	OnCopy   func()
	OnQuit   func()
	OnSelect func(id string)
}

type View struct {
	App        *tview.Application
	Table      *tview.Table
	CodeView   *tview.TextView
	DetailView *tview.TextView
	Footer     *tview.TextView
	root       tview.Primitive

	h Handlers
}

func New() *View {
	v := &View{App: tview.NewApplication()}

	// Table
	v.Table = tview.NewTable()
	v.Table.SetSelectable(true, false)
	v.Table.SetBorder(true)
	v.Table.SetTitle(" Accounts (↑↓/Enter, A=Add, E=Edit, D=Del, I=Import) ")

	// Code view
	v.CodeView = tview.NewTextView()
	v.CodeView.SetDynamicColors(true)
	v.CodeView.SetBorder(true)
	v.CodeView.SetTitle(" Code ")
	v.CodeView.SetTextAlign(tview.AlignCenter)

	// Detail view
	v.DetailView = tview.NewTextView()
	v.DetailView.SetDynamicColors(true)
	v.DetailView.SetBorder(true)
	v.DetailView.SetTitle(" Details (R=Reveal/C=Copy) ")

	// Footer
	v.Footer = tview.NewTextView()
	v.Footer.SetDynamicColors(true)
	v.Footer.SetText("  [yellow]A add  E edit  D delete  I import  R reveal  C copy  Q quit[-]")

	right := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(v.CodeView, 7, 0, false).
		AddItem(v.DetailView, 0, 1, false).
		AddItem(v.Footer, 1, 0, false)

	v.root = tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(v.Table, 0, 2, true).
		AddItem(right, 0, 5, false)
	return v
}

func (v *View) SetHandlers(h Handlers) { v.h = h }

func (v *View) Run() error {
	v.Table.SetSelectedFunc(func(row, _ int) {
		if row <= 0 {
			return
		}
		if ref := v.Table.GetCell(row, 0).GetReference(); ref != nil {
			if id, ok := ref.(string); ok && v.h.OnSelect != nil {
				v.h.OnSelect(id)
			}
		}
	})
	v.App.SetRoot(v.root, true).SetFocus(v.Table)
	v.App.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case 'q', 'Q':
			if v.h.OnQuit != nil {
				v.h.OnQuit()
			}
			return nil
		case 'a', 'A':
			if v.h.OnAdd != nil {
				v.h.OnAdd()
			}
			return nil
		case 'e', 'E':
			if v.h.OnEdit != nil {
				v.h.OnEdit()
			}
			return nil
		case 'd', 'D':
			if v.h.OnDelete != nil {
				v.h.OnDelete()
			}
			return nil
		case 'i', 'I':
			if v.h.OnImport != nil {
				v.h.OnImport()
			}
			return nil
		case 'r', 'R':
			if v.h.OnReveal != nil {
				v.h.OnReveal()
			}
			return nil
		case 'c', 'C':
			if v.h.OnCopy != nil {
				v.h.OnCopy()
			}
			return nil
		}
		return ev
	})
	return v.App.Run()
}

func (v *View) Stop() { v.App.Stop() }

func (v *View) PopulateTable(accts []model.Account, selectedID string) {
	v.Table.Clear()
	v.Table.SetCell(0, 0, tview.NewTableCell("ID").SetSelectable(false).SetAttributes(tcell.AttrBold))
	v.Table.SetCell(0, 1, tview.NewTableCell("Issuer").SetSelectable(false).SetAttributes(tcell.AttrBold))
	v.Table.SetCell(0, 2, tview.NewTableCell("Name").SetSelectable(false).SetAttributes(tcell.AttrBold))
	v.Table.SetCell(0, 3, tview.NewTableCell("Algo").SetSelectable(false).SetAttributes(tcell.AttrBold))
	v.Table.SetCell(0, 4, tview.NewTableCell("Digits").SetSelectable(false).SetAttributes(tcell.AttrBold))
	v.Table.SetCell(0, 5, tview.NewTableCell("Period").SetSelectable(false).SetAttributes(tcell.AttrBold))
	for r, acc := range accts {
		row := r + 1
		idCell := tview.NewTableCell(shorten(acc.ID, 24)).SetReference(acc.ID)
		v.Table.SetCell(row, 0, idCell)
		v.Table.SetCell(row, 1, tview.NewTableCell(acc.Issuer))
		v.Table.SetCell(row, 2, tview.NewTableCell(acc.Name))
		v.Table.SetCell(row, 3, tview.NewTableCell(string(acc.Algo)))
		v.Table.SetCell(row, 4, tview.NewTableCell(fmt.Sprintf("%d", acc.Digits)))
		v.Table.SetCell(row, 5, tview.NewTableCell(fmt.Sprintf("%ds", acc.Period)))
		if acc.ID == selectedID {
			v.Table.Select(row, 0)
		}
	}
	if selectedID == "" && len(accts) > 0 {
		v.Table.Select(1, 0)
	}
}

func (v *View) RenderCode(code string, remain, period int) {
	barW := 24
	fill := int(float64(period-remain) / float64(period) * float64(barW))
	if fill < 0 {
		fill = 0
	}
	if fill > barW {
		fill = barW
	}
	bar := "[" + strings.Repeat("█", fill) + strings.Repeat("░", barW-fill) + "]"
	v.CodeView.SetText(fmt.Sprintf("\n  [white::b]%s[-:-:-]\n\n  %s  [gray]%ds left[-]\n", code, bar, remain))
}

func (v *View) RenderNoSelection() {
	v.CodeView.SetText("[gray]No account selected[-]")
	v.DetailView.SetText("—")
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
	fmt.Fprintf(b, "Digits:  [white]%d[-]\n", acc.Digits)
	fmt.Fprintf(b, "Period:  [white]%d s[-]\n", acc.Period)
	fmt.Fprintf(b, "Algo:    [white]%s[-]\n", acc.Algo)
	fmt.Fprintf(b, "Secret:  [white]%s[-]\n", secret)
	if acc.Notes != "" {
		fmt.Fprintf(b, "Notes:   [white]%s[-]\n", acc.Notes)
	}
	v.DetailView.SetText(b.String())
}

func (v *View) Flash(msg string) {
	v.Footer.SetText("  " + msg + "  |  [yellow]A add  E edit  D delete  I import  R reveal  C copy  Q quit[-]")
}

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

	form := tview.NewForm().
		AddInputField("Issuer", acc.Issuer, 40, nil, func(s string) { acc.Issuer = s }).
		AddInputField("Name", acc.Name, 40, nil, func(s string) { acc.Name = s }).
		AddInputField("Secret (Base32)", acc.Secret, 52, nil, func(s string) { acc.Secret = s }).
		AddDropDown("Algo", algos, algoIdx, func(opt string, _ int) { acc.Algo = model.Algo(opt) }).
		AddDropDown("Digits", []string{"6", "8"}, digitIdx, func(opt string, _ int) {
			if v, _ := strconv.Atoi(opt); v != 0 {
				acc.Digits = v
			}
		}).
		AddInputField("Period (sec)", fmt.Sprintf("%d", acc.Period), 5,
			func(s string, _ rune) bool { _, e := strconv.Atoi(s); return e == nil || s == "" },
			func(s string) {
				if n, err := strconv.Atoi(s); err == nil {
					acc.Period = n
				}
			}).
		AddInputField("Notes", acc.Notes, 80, nil, func(s string) { acc.Notes = s })

	form.AddButton("Save", func() { onSave(acc) })
	form.AddButton("Cancel", func() { onCancel() })
	form.SetCancelFunc(onCancel) // ESC to cancel

	form.SetBorder(true).SetTitle(" " + title + " ").SetTitleAlign(tview.AlignLeft)

	// Full-screen so nothing gets cut off on short terminals.
	full := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(form, 0, 1, true)

	v.App.SetRoot(full, true)
	v.App.SetFocus(form)
}

func (v *View) ShowImportURIForm(onImport func(uri string), onCancel func()) {
	var uri string
	form := tview.NewForm().AddInputField("otpauth:// URI", "", 120, nil, func(s string) { uri = s })
	form.AddButton("Import", func() { onImport(uri) }).AddButton("Cancel", func() { onCancel() })
	form.SetBorder(true).SetTitle(" Import from otpauth:// ")
	v.App.SetRoot(center(100, 10, form), true)
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
	v.App.SetRoot(center(50, 8, modal), true)
}

func (v *View) RestoreRoot() { v.App.SetRoot(v.root, true) }

func center(w, h int, p tview.Primitive) tview.Primitive {
	f := tview.NewFlex().SetDirection(tview.FlexRow)
	f.AddItem(nil, 0, 1, false)
	row := tview.NewFlex().SetDirection(tview.FlexColumn)
	row.AddItem(nil, 0, 1, false)
	row.AddItem(p, w, 0, true)
	row.AddItem(nil, 0, 1, false)
	f.AddItem(row, h, 0, true)
	f.AddItem(nil, 0, 1, false)
	return f
}

func shorten(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
