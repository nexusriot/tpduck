package main

import (
	"strings"
	"testing"
	"time"

	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/yubikey"
)

func creds(names ...string) []yubikey.Credential {
	out := make([]yubikey.Credential, 0, len(names))
	for _, n := range names {
		c := yubikey.Credential{Name: n, Account: n, Period: 30, Type: yubikey.TypeTOTP}
		if issuer, account, ok := strings.Cut(n, ":"); ok {
			c.Issuer, c.Account = issuer, account
		}
		out = append(out, c)
	}
	return out
}

// An exact name or label wins outright. Without that pass, asking for
// "GitHub" on a key that also holds "GitHub-work" is ambiguous rather than the
// obvious hit it looks like.
func TestFindCredentialPrefersAnExactMatch(t *testing.T) {
	cs := creds("GitHub:alice", "GitHub-work:alice", "Bank:bob")
	for _, query := range []string{"GitHub:alice", "github:alice", "GITHUB:ALICE"} {
		got, err := findCredential(cs, query)
		if err != nil {
			t.Fatalf("%q: %v", query, err)
		}
		if got.Name != "GitHub:alice" {
			t.Errorf("%q resolved to %q", query, got.Name)
		}
	}
}

func TestFindCredentialUniqueSubstring(t *testing.T) {
	cs := creds("GitHub:alice", "Bank:bob")
	got, err := findCredential(cs, "bank")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Bank:bob" {
		t.Errorf("resolved to %q", got.Name)
	}
}

// An ambiguous query is refused rather than guessed, as it is for the vault.
func TestFindCredentialRefusesAmbiguity(t *testing.T) {
	cs := creds("GitHub:alice", "GitHub:bob")
	_, err := findCredential(cs, "github")
	if err == nil {
		t.Fatal("an ambiguous query was resolved")
	}
	if !strings.Contains(err.Error(), "more than one") {
		t.Errorf("error %q does not say why", err)
	}
}

func TestFindCredentialNoMatch(t *testing.T) {
	if _, err := findCredential(creds("GitHub:alice"), "nope"); err == nil {
		t.Error("a query matching nothing was resolved")
	}
}

// A period-prefixed name is how the applet stores a non-default period, and
// the label hides that prefix, so both spellings must resolve.
func TestFindCredentialWithAPeriodPrefix(t *testing.T) {
	cs := []yubikey.Credential{{
		Name: "60/Acme:carol", Issuer: "Acme", Account: "carol", Period: 60, Type: yubikey.TypeTOTP,
	}}
	for _, query := range []string{"60/Acme:carol", "Acme:carol", "carol"} {
		if _, err := findCredential(cs, query); err != nil {
			t.Errorf("%q: %v", query, err)
		}
	}
}

// --- verifyOnKey ---

func totpAccount() model.Account {
	return model.Account{
		ID: "acme:alice", Issuer: "Acme", Name: "alice",
		Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: model.AlgoSHA1,
	}
}

// -move deletes the vault's only other copy, so it is gated on the key
// reproducing a code tpduck computed itself.
func TestVerifyOnKeyAcceptsAMatchingCredential(t *testing.T) {
	acc := totpAccount()
	name := yubikey.CredentialName(acc.Issuer, acc.Name, acc.Period, yubikey.TypeTOTP)
	card := yubikey.NewSimCard(yubikey.SimCredential{
		Name: name, Secret: acc.Secret, Digits: byte(acc.Digits),
		Type: yubikey.TypeTOTP, Algo: string(acc.Algo),
	})
	s, err := yubikey.Open(card)
	if err != nil {
		t.Fatal(err)
	}
	ok, why := verifyOnKey(s, acc, name)
	if !ok {
		t.Errorf("a correctly stored credential did not verify: %s", why)
	}
}

// The case that matters: the key holds something else under that name, and
// -move would otherwise delete the real secret.
func TestVerifyOnKeyRejectsADifferentSecret(t *testing.T) {
	acc := totpAccount()
	name := yubikey.CredentialName(acc.Issuer, acc.Name, acc.Period, yubikey.TypeTOTP)
	card := yubikey.NewSimCard(yubikey.SimCredential{
		Name: name, Secret: "KRSXG5CTMVRXEZLUMUQHO2LROVZQ", Digits: byte(acc.Digits),
		Type: yubikey.TypeTOTP, Algo: string(acc.Algo),
	})
	s, _ := yubikey.Open(card)
	ok, why := verifyOnKey(s, acc, name)
	if ok {
		t.Fatal("a credential holding a different secret verified")
	}
	if !strings.Contains(why, "different code") {
		t.Errorf("reason %q does not say what went wrong", why)
	}
}

// Counter-based credentials are deliberately not verified: asking one for a
// code advances the key's counter, which would leave the two out of step.
func TestVerifyOnKeySkipsHOTP(t *testing.T) {
	acc := totpAccount()
	acc.Type = model.TypeHOTP
	acc.Counter = 3
	card := yubikey.NewSimCard()
	s, _ := yubikey.Open(card)
	ok, why := verifyOnKey(s, acc, "Acme:alice")
	if ok {
		t.Fatal("an HOTP credential was reported as verified")
	}
	if !strings.Contains(why, "counter") {
		t.Errorf("reason %q does not explain the exemption", why)
	}
}

// A credential that is simply not there must be reported, not treated as a
// match.
func TestVerifyOnKeyMissingCredential(t *testing.T) {
	acc := totpAccount()
	s, _ := yubikey.Open(yubikey.NewSimCard())
	if ok, why := verifyOnKey(s, acc, "Acme:alice"); ok {
		t.Error("a missing credential verified")
	} else if why == "" {
		t.Error("no reason was given")
	}
}

// A touch-protected credential cannot answer unattended; that is a failure to
// verify, not a mismatch, and -move must not proceed on it silently.
func TestVerifyOnKeyTouchCredential(t *testing.T) {
	acc := totpAccount()
	name := yubikey.CredentialName(acc.Issuer, acc.Name, acc.Period, yubikey.TypeTOTP)
	card := yubikey.NewSimCard(yubikey.SimCredential{
		Name: name, Secret: acc.Secret, Digits: byte(acc.Digits),
		Type: yubikey.TypeTOTP, Algo: string(acc.Algo), Touch: true,
	})
	s, _ := yubikey.Open(card)
	if ok, why := verifyOnKey(s, acc, name); ok {
		t.Error("a touch-protected credential verified without a touch")
	} else if why == "" {
		t.Error("no reason was given")
	}
}

// The simulator computes codes the same way the model does, which is what
// makes the verification above meaningful rather than circular.
func TestSimulatorAgreesWithTheModel(t *testing.T) {
	acc := totpAccount()
	at := time.Unix(1234567890, 0)
	want, err := model.Generate(acc, at)
	if err != nil {
		t.Fatal(err)
	}
	got, err := yubikey.SimCode(acc.Secret, string(acc.Algo), at.Unix(), acc.Period, acc.Digits)
	if err != nil {
		t.Fatal(err)
	}
	if got != want.Value {
		t.Errorf("simulator says %s, model says %s", got, want.Value)
	}
}
