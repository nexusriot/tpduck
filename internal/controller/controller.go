package controller

import (
	"fmt"
	"time"

	"github.com/nexusriot/tpduck/internal/clipboard"
	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/view"
)

type Controller struct {
	store     *model.Store
	storePath string
	v         *view.View
	selected  string
	reveal    bool
}

func New(s *model.Store, path string, v *view.View) *Controller {
	c := &Controller{store: s, storePath: path, v: v}
	v.SetHandlers(view.Handlers{
		OnAdd:    c.onAdd,
		OnEdit:   c.onEdit,
		OnDelete: c.onDelete,
		OnImport: c.onImport,
		OnReveal: c.onReveal,
		OnCopy:   c.onCopy,
		OnQuit:   c.onQuit,
		OnSelect: c.onSelect,
	})
	v.PopulateTable(s.Accounts, "")
	if len(s.Accounts) > 0 {
		c.selected = s.Accounts[0].ID
	}
	c.renderDetailAndCode()
	return c
}

func (c *Controller) Start(refreshPeriod time.Duration) {
	if refreshPeriod <= 0 {
		refreshPeriod = 250 * time.Millisecond
	}
	ticker := time.NewTicker(refreshPeriod)
	defer ticker.Stop()
	go func() {
		for range ticker.C {
			c.v.App.QueueUpdateDraw(func() { c.renderCodeOnly() })
		}
	}()
	if err := c.v.Run(); err != nil {
		fmt.Println("run:", err)
	}
	_ = c.store.Save(c.storePath)
}

func (c *Controller) onSelect(id string) { c.selected = id; c.renderDetailAndCode() }

func (c *Controller) onAdd() {
	initial := model.Account{Digits: 6, Period: 30, Algo: model.AlgoSHA1}
	c.v.ShowAccountForm("Add Account", initial, func(acc model.Account) {
		acc.Secret = model.NormalizeSecret(acc.Secret)
		if acc.Name == "" || acc.Secret == "" {
			c.v.Flash("[red]name and secret are required")
			return
		}
		if err := model.ValidateSecret(acc.Secret); err != nil {
			c.v.Flash(fmt.Sprintf("[red]invalid secret: %v", err))
			return
		}
		acc.ID = model.MakeID(acc)
		acc.AddedAt = time.Now().Unix()
		c.store.Accounts = append(c.store.Accounts, acc)
		_ = c.store.Save(c.storePath)
		c.selected = acc.ID
		c.v.PopulateTable(c.store.Accounts, c.selected)
		c.renderDetailAndCode()
		c.v.RestoreRoot()
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
		updated.Secret = model.NormalizeSecret(updated.Secret)
		if err := model.ValidateSecret(updated.Secret); err != nil {
			c.v.Flash(fmt.Sprintf("[red]invalid secret: %v", err))
			return
		}
		updated.ID = model.MakeID(updated)
		i := c.store.FindIndexByID(origID)
		if i >= 0 {
			c.store.Accounts[i] = updated
		}
		_ = c.store.Save(c.storePath)
		c.selected = updated.ID
		c.v.PopulateTable(c.store.Accounts, c.selected)
		c.renderDetailAndCode()
		c.v.RestoreRoot()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onDelete() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	c.v.ConfirmDelete(*acc, func() {
		i := c.store.FindIndexByID(acc.ID)
		if i >= 0 {
			c.store.Accounts = append(c.store.Accounts[:i], c.store.Accounts[i+1:]...)
			_ = c.store.Save(c.storePath)
		}
		c.selected = ""
		if len(c.store.Accounts) > 0 {
			c.selected = c.store.Accounts[0].ID
		}
		c.v.PopulateTable(c.store.Accounts, c.selected)
		c.renderDetailAndCode()
		c.v.RestoreRoot()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onImport() {
	c.v.ShowImportURIForm(func(uri string) {
		acc, err := model.ParseOtpauthURI(uri)
		if err != nil {
			c.v.Flash(fmt.Sprintf("[red]parse: %v", err))
			return
		}
		if c.store.FindIndexByID(acc.ID) >= 0 {
			acc.ID = fmt.Sprintf("%s#%d", acc.ID, time.Now().Unix())
		}
		c.store.Accounts = append(c.store.Accounts, *acc)
		_ = c.store.Save(c.storePath)
		c.selected = acc.ID
		c.v.PopulateTable(c.store.Accounts, c.selected)
		c.renderDetailAndCode()
		c.v.RestoreRoot()
	}, func() { c.v.RestoreRoot() })
}

func (c *Controller) onReveal() { c.reveal = !c.reveal; c.renderDetailOnly() }

func (c *Controller) onCopy() {
	acc := c.current()
	if acc == nil {
		c.v.Flash("[yellow]no selection")
		return
	}
	code, _, err := model.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, time.Now())
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]%v", err))
		return
	}
	if err := clipboard.Copy(code); err != nil {
		c.v.Flash(fmt.Sprintf("[yellow]copied: %s (no helper)", code))
	} else {
		c.v.Flash("[green]copied to clipboard")
	}
}

func (c *Controller) onQuit() { c.v.Stop() }

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
	acc := c.current()
	if acc == nil {
		c.v.RenderNoSelection()
		return
	}
	code, remain, err := model.Totp(acc.Secret, acc.Algo, acc.Period, acc.Digits, time.Now())
	if err != nil {
		c.v.Flash(fmt.Sprintf("[red]error: %v", err))
		return
	}
	c.v.RenderCode(code, remain, acc.Period)
}
