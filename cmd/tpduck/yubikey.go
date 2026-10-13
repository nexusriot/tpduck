package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/yubikey"
)

func cmdYubikey(f *flags, args []string) error {
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
		return yubikeyPut(f)
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
	default:
		return fmt.Errorf("usage: tpduck yubikey <list|code|put|delete|rename>")
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
	pass, err := readPassphrase("YubiKey OATH password: ")
	if err != nil {
		return err
	}
	return s.Unlock(pass)
}

func yubikeyPut(f *flags) error {
	if f.secret == "" || f.name == "" {
		return errors.New("usage: tpduck yubikey put -secret S -name N [-issuer I] [-type hotp] [-touch]")
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
	var match *yubikey.Credential
	for i := range creds {
		if creds[i].Name == query || strings.EqualFold(creds[i].Label(), query) ||
			strings.Contains(strings.ToLower(creds[i].Name), strings.ToLower(query)) {
			if match != nil {
				return fmt.Errorf("%q matches more than one credential on the key", query)
			}
			match = &creds[i]
		}
	}
	if match == nil {
		return fmt.Errorf("no credential on the key matches %q", query)
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
