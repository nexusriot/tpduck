package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/yubikey"
)

func cmdYubikey(f *flags, path string, args []string) error {
	action := "list"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "list":
		return yubikeyList(f)
	case "code":
		if len(args) != 2 {
			return errors.New("usage: tpduck yubikey code <credential>")
		}
		return yubikeyCode(f, args[1])
	case "put", "add":
		return yubikeyPut(f, path, args[1:])
	case "delete", "rm":
		if len(args) != 2 {
			return errors.New("usage: tpduck yubikey delete <credential>")
		}
		return yubikeyDelete(f, args[1])
	case "rename":
		if len(args) != 3 {
			return errors.New("usage: tpduck yubikey rename <old> <new>")
		}
		return yubikeyRename(f, args[1], args[2])
	case "password", "passwd":
		return yubikeyPassword(f, args[1:])
	case "reset":
		return yubikeyReset(f)
	default:
		return fmt.Errorf("usage: tpduck yubikey <list|code|put|delete|rename|password|reset>")
	}
}

// annotateTouch fills in which credentials need a physical touch.
//
// The applet's LIST response has no touch bit, so without this the column
// could never be set. CALCULATE ALL does report it, and for a touch-protected
// credential it answers with the touch tag rather than computing anything, so
// asking costs nothing and prompts for nothing.
func annotateTouch(s *yubikey.Session, creds []yubikey.Credential) {
	_, all, err := s.CalculateAll(time.Now())
	if err != nil {
		return // not worth failing a listing over
	}
	needsTouch := make(map[string]bool, len(all))
	for _, c := range all {
		needsTouch[c.Name] = c.Touch
	}
	for i := range creds {
		if needsTouch[creds[i].Name] {
			creds[i].Touch = true
		}
	}
}

// unlockIfNeeded authenticates against a password-protected applet.
func unlockIfNeeded(s *yubikey.Session) error {
	if !s.NeedsPassword() {
		return nil
	}
	pass, err := readKeyPassword("YubiKey OATH password: ")
	if err != nil {
		return err
	}
	return s.Unlock(pass)
}

func yubikeyPut(f *flags, path string, args []string) error {
	// With a query, the secret comes from the vault -- there is no reason to
	// retype something tpduck already holds. Without one, it comes from the
	// flags, which is how a brand-new secret gets onto the key without ever
	// touching the disk.
	if len(args) == 1 {
		return yubikeyPutFromVault(f, path, args[0])
	}
	if len(args) > 1 {
		return errors.New("usage: tpduck yubikey put <query>   or   tpduck yubikey put -secret S -name N ...")
	}
	if f.secret == "" || f.name == "" {
		return errors.New("usage: tpduck yubikey put <query>   or   tpduck yubikey put -secret S -name N [-issuer I] [-type hotp] [-touch]")
	}
	typ := yubikey.TypeTOTP
	if strings.EqualFold(f.otpType, "hotp") {
		typ = yubikey.TypeHOTP
	}
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	name := yubikey.CredentialName(f.issuer, f.name, f.period, typ)
	if err := s.Put(yubikey.PutOptions{
		Name: name, Secret: f.secret, Type: typ, Algo: f.algo,
		Digits: f.digits, Counter: f.counter, Touch: f.touch,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stored %s on the key; the secret is not written to disk\n", name)
	return nil
}

// yubikeyPutFromVault copies one of the vault's accounts onto the key, and
// with -move removes the vault's copy once the key has demonstrably got it.
//
// There is no way back: a credential on the key answers challenges but never
// gives its secret up, which is the point of putting it there. -move is
// therefore gated on the key reproducing a code tpduck computed itself.
func yubikeyPutFromVault(f *flags, path, query string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(query)
	if err != nil {
		return err
	}
	typ := yubikey.TypeTOTP
	switch acc.Kind() {
	case model.TypeHOTP:
		typ = yubikey.TypeHOTP
	case model.TypeSteam:
		return fmt.Errorf("%s is a Steam Guard account, and the OATH applet has no Steam Guard; it can only live in the vault", acc.Label())
	}
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}

	name := yubikey.CredentialName(acc.Issuer, acc.Name, acc.Period, typ)
	if err := s.Put(yubikey.PutOptions{
		Name: name, Secret: acc.Secret, Type: typ, Algo: string(acc.Algo),
		Digits: acc.Digits, Counter: acc.Counter, Touch: f.touch,
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "stored %s on the key\n", name)

	verified, why := verifyOnKey(s, *acc, name)
	if verified {
		fmt.Fprintln(os.Stderr, "verified: the key produces the same code tpduck does")
	} else {
		fmt.Fprintf(os.Stderr, "not verified: %s\n", why)
	}
	if !f.move {
		fmt.Fprintln(os.Stderr, "the vault still has its own copy; add -move to remove it")
		return nil
	}
	if !verified && !f.force {
		return fmt.Errorf("refusing -move without verification (%s); re-run with -force to delete anyway", why)
	}
	ok, err := confirm(f.force, fmt.Sprintf(
		"Delete %s from the vault? The key will hold the only copy.", acc.Label()))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "kept in the vault")
		return nil
	}
	i := store.FindIndexByID(acc.ID)
	store.Accounts = append(store.Accounts[:i], store.Accounts[i+1:]...)
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "moved: %s now lives only on the key\n", acc.Label())
	return nil
}

// verifyOnKey checks that the credential the key now holds really is the one
// the vault had, by comparing codes for the same moment.
//
// HOTP is not checked: asking a counter-based credential for a code makes the
// key advance its counter, so a verification would leave the two out of step.
func verifyOnKey(s *yubikey.Session, acc model.Account, name string) (bool, string) {
	if acc.Kind() == model.TypeHOTP {
		return false, "counter-based credentials cannot be checked without consuming a counter step"
	}
	at := time.Now()
	want, err := model.Generate(acc, at)
	if err != nil {
		return false, err.Error()
	}
	got, err := s.Calculate(name, acc.Digits, at, acc.Period)
	if err != nil {
		return false, err.Error()
	}
	if got != want.Value {
		return false, "the key produced a different code"
	}
	return true, ""
}

// --- the applet's own password ---

func yubikeyPassword(f *flags, args []string) error {
	action := ""
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "set", "remove":
	default:
		return errors.New("usage: tpduck yubikey password <set|remove>")
	}
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	if action == "remove" {
		if err := s.RemovePassword(); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "the key's OATH credentials are no longer password-protected")
		return nil
	}
	pass, err := readKeyPassword("New YubiKey OATH password: ")
	if err != nil {
		return err
	}
	if pass == "" {
		return errors.New("password is empty (use `tpduck yubikey password remove` to take it off)")
	}
	if _, isEnv := os.LookupEnv(envKeyPassword); !isEnv {
		again, err := readKeyPassword("Confirm: ")
		if err != nil {
			return err
		}
		if !model.ConstantTimeEqualString(pass, again) {
			return errors.New("passwords do not match")
		}
	}
	if err := s.SetPassword(pass); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "the key's OATH credentials now need this password")
	fmt.Fprintln(os.Stderr, "note: this protects the credentials on the key, not the tpduck vault")
	return nil
}

func yubikeyReset(f *flags) error {
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	creds, listErr := s.List()
	n := len(creds)
	what := fmt.Sprintf("%d credential(s)", n)
	if listErr != nil {
		what = "every credential"
	}
	ok, err := confirm(f.force, fmt.Sprintf(
		"Wipe the YubiKey's OATH applet? This deletes %s and its password. "+
			"The key holds the only copy of each secret and there is no undo.", what))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "not reset")
		return nil
	}
	if err := s.Reset(); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "the key's OATH applet is now empty")
	return nil
}

func yubikeyDelete(f *flags, name string) error {
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	ok, err := confirm(f.force, fmt.Sprintf("Delete %s from the key? The key holds the only copy.", name))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "not deleted")
		return nil
	}
	if err := s.Delete(name); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "deleted")
	return nil
}

func yubikeyRename(f *flags, from, to string) error {
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	if err := s.Rename(from, to); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "renamed to %s\n", to)
	return nil
}

func openKey(f *flags) (*yubikey.Session, error) {
	s, err := yubikey.Connect(f.reader)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func yubikeyList(f *flags) error {
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	creds, err := s.List()
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		fmt.Fprintln(os.Stderr, "no OATH credentials on the key")
		return nil
	}
	annotateTouch(s, creds)
	fmt.Fprintf(os.Stderr, "YubiKey OATH %s\n", s.Version)
	for _, c := range creds {
		extra := fmt.Sprintf("%ds", c.Period)
		if c.Type == yubikey.TypeHOTP {
			extra = "counter"
		}
		touch := ""
		if c.Touch {
			touch = "  (touch)"
		}
		fmt.Printf("%-40s  %-4s  %-6s  %s%s\n",
			c.Name, strings.ToUpper(string(c.Type)), c.Algo, extra, touch)
	}
	return nil
}

// findCredential resolves a query the way the vault does: an exact name or
// label first, then a unique substring. Without the exact-match pass, asking
// for "GitHub" on a key that also holds "GitHub-work" is ambiguous rather than
// an obvious hit.
func findCredential(creds []yubikey.Credential, query string) (*yubikey.Credential, error) {
	for i := range creds {
		if creds[i].Name == query || strings.EqualFold(creds[i].Label(), query) {
			return &creds[i], nil
		}
	}
	var match *yubikey.Credential
	q := strings.ToLower(query)
	for i := range creds {
		if strings.Contains(strings.ToLower(creds[i].Name), q) {
			if match != nil {
				return nil, fmt.Errorf("%q matches more than one credential on the key", query)
			}
			match = &creds[i]
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no credential on the key matches %q", query)
	}
	return match, nil
}

func yubikeyCode(f *flags, query string) error {
	s, err := openKey(f)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := unlockIfNeeded(s); err != nil {
		return err
	}
	creds, err := s.List()
	if err != nil {
		return err
	}
	// List says nothing about which credentials need a touch, so ask before
	// choosing -- otherwise the key sits there waiting with nothing on screen
	// to say why.
	annotateTouch(s, creds)
	match, err := findCredential(creds, query)
	if err != nil {
		return err
	}
	if match.Touch {
		fmt.Fprintln(os.Stderr, "touch the key now...")
	}
	code, err := s.Calculate(match.Name, 0, time.Now(), match.Period)
	if err != nil {
		return err
	}
	fmt.Println(code)
	return nil
}
