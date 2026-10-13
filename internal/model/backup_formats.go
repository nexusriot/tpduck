package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// BackupFormat is one of the shapes tpduck can write a whole vault as.
type BackupFormat string

const (
	// FormatURI is a newline-separated list of otpauth:// URIs. Every
	// authenticator understands it, and ParseBackup reads it back.
	FormatURI BackupFormat = "uri"
	// FormatAegis is Aegis's plain (unencrypted) JSON export.
	FormatAegis BackupFormat = "aegis"
	// FormatAndOTP is andOTP's plain JSON export.
	FormatAndOTP BackupFormat = "andotp"
)

// BackupFormats lists what -format accepts.
func BackupFormats() []string {
	return []string{string(FormatURI), string(FormatAegis), string(FormatAndOTP)}
}

// RenderBackup serialises accounts in the requested interchange format. Every
// one of these contains secrets in the clear.
func RenderBackup(accounts []Account, format BackupFormat) ([]byte, error) {
	switch format {
	case "", FormatURI:
		return []byte(ExportBackup(accounts)), nil
	case FormatAegis:
		return renderAegis(accounts)
	case FormatAndOTP:
		return renderAndOTP(accounts)
	default:
		return nil, fmt.Errorf("unknown backup format %q (want %s)", format, strings.Join(BackupFormats(), ", "))
	}
}

type aegisInfo struct {
	Secret  string `json:"secret"`
	Algo    string `json:"algo"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period,omitempty"`
	Counter uint64 `json:"counter,omitempty"`
}

type aegisEntry struct {
	Type   string    `json:"type"`
	UUID   string    `json:"uuid"`
	Name   string    `json:"name"`
	Issuer string    `json:"issuer"`
	Note   string    `json:"note,omitempty"`
	Info   aegisInfo `json:"info"`
}

func renderAegis(accounts []Account) ([]byte, error) {
	entries := make([]aegisEntry, 0, len(accounts))
	for _, a := range accounts {
		e := aegisEntry{
			Type: string(a.Kind()), UUID: a.ID, Name: a.Name, Issuer: a.Issuer, Note: a.Notes,
			Info: aegisInfo{Secret: NormalizeSecret(a.Secret), Algo: string(a.Algo), Digits: a.Digits},
		}
		if a.Kind() == TypeHOTP {
			e.Info.Counter = a.Counter
		} else {
			e.Info.Period = a.Period
		}
		entries = append(entries, e)
	}
	doc := map[string]any{
		"version": 1,
		"header":  map[string]any{"slots": nil, "params": nil},
		"db":      map[string]any{"version": 2, "entries": entries},
	}
	return json.MarshalIndent(doc, "", "  ")
}

type andOTPEntry struct {
	Secret    string   `json:"secret"`
	Label     string   `json:"label"`
	Issuer    string   `json:"issuer"`
	Digits    int      `json:"digits"`
	Type      string   `json:"type"`
	Algorithm string   `json:"algorithm"`
	Period    int      `json:"period,omitempty"`
	Counter   uint64   `json:"counter,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	LastUsed  int64    `json:"last_used,omitempty"`
}

func renderAndOTP(accounts []Account) ([]byte, error) {
	entries := make([]andOTPEntry, 0, len(accounts))
	for _, a := range accounts {
		e := andOTPEntry{
			Secret: NormalizeSecret(a.Secret), Label: a.Name, Issuer: a.Issuer,
			Digits: a.Digits, Type: strings.ToUpper(string(a.Kind())),
			Algorithm: string(a.Algo), Tags: a.Tags, LastUsed: a.LastUsedAt * 1000,
		}
		if a.Kind() == TypeHOTP {
			e.Counter = a.Counter
		} else {
			e.Period = a.Period
		}
		entries = append(entries, e)
	}
	return json.MarshalIndent(entries, "", "  ")
}

// --- generic URI scavenger -------------------------------------------------

// parseJSONScavenge walks any JSON document and collects otpauth:// URIs and
// bare secrets sitting in a "totp" field. Password managers each have their own
// schema but all of them store the credential in one of those two shapes, so
// this one reader covers Bitwarden, 1Password and the rest without needing a
// parser per product.
func parseJSONScavenge(data []byte) ([]Account, error) {
	var doc any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []Account
	var walk func(node any, nameHint string)
	walk = func(node any, nameHint string) {
		switch v := node.(type) {
		case map[string]any:
			// Remember a human name from this object for any bare secret in it.
			hint := nameHint
			for _, key := range []string{"name", "title", "username", "login_uri"} {
				if s, ok := v[key].(string); ok && strings.TrimSpace(s) != "" {
					hint = s
					break
				}
			}
			for key, child := range v {
				if s, ok := child.(string); ok {
					if acc := accountFromScavenged(key, s, hint); acc != nil {
						out = append(out, *acc)
						continue
					}
				}
				walk(child, hint)
			}
		case []any:
			for _, child := range v {
				walk(child, nameHint)
			}
		}
	}
	walk(doc, "")
	if len(out) == 0 {
		return nil, fmt.Errorf("no otpauth URIs or totp secrets found")
	}
	return out, nil
}

// accountFromScavenged turns one string field into an account when it looks
// like a credential.
func accountFromScavenged(key, value, nameHint string) *Account {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(value), "otpauth://") {
		if acc, err := ParseOtpauthURI(value); err == nil {
			return acc
		}
		return nil
	}
	// A bare Base32 secret is only meaningful in a field that says so.
	if !strings.EqualFold(key, "totp") && !strings.EqualFold(key, "otp") &&
		!strings.EqualFold(key, "totpSecret") {
		return nil
	}
	if ValidateSecret(value) != nil {
		return nil
	}
	name := strings.TrimSpace(nameHint)
	if name == "" {
		name = "imported"
	}
	acc := Account{
		Name: name, Secret: NormalizeSecret(value),
		Digits: DefaultDigits, Period: DefaultPeriod, Algo: AlgoSHA1,
		Type: TypeTOTP, AddedAt: time.Now().Unix(),
	}
	if parts := strings.SplitN(name, ":", 2); len(parts) == 2 {
		acc.Issuer, acc.Name = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	if acc.Validate() != nil {
		return nil
	}
	acc.ID = MakeID(acc)
	return &acc
}
