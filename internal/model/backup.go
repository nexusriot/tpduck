package model

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParseBackup imports accounts from another authenticator's export, sniffing
// the format. It returns the accounts and the name of the format recognised.
//
// Supported: Aegis (plain JSON export), andOTP (plain JSON), 2FAS (JSON),
// KeePassXC CSV, and a plain list of otpauth:// URIs (one per line), which is
// also what `tpduck export` writes.
func ParseBackup(data []byte) ([]Account, string, error) {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, "", errors.New("file is empty")
	}
	switch trimmed[0] {
	case '{':
		// Checked first: an encrypted Aegis export has a string "db", so every
		// parser below fails on it and the user would get a generic message
		// instead of being told what to do about it.
		if isEncryptedAegis([]byte(trimmed)) {
			return nil, "", errors.New("this Aegis export is encrypted; re-export it with encryption turned off")
		}
		if accs, err := parseAegis([]byte(trimmed)); err == nil {
			return accs, "Aegis", nil
		}
		if accs, err := parse2FAS([]byte(trimmed)); err == nil {
			return accs, "2FAS", nil
		}
		// Password managers each have their own schema; scavenging for the
		// credential shapes covers Bitwarden, 1Password and friends at once.
		if accs, err := parseJSONScavenge([]byte(trimmed)); err == nil {
			return accs, "JSON export (otpauth fields)", nil
		}
		return nil, "", errors.New("unrecognised JSON backup (tried Aegis, 2FAS, and a scan for otpauth fields)")
	case '[':
		if accs, err := parseAndOTP([]byte(trimmed)); err == nil {
			return accs, "andOTP", nil
		}
		if accs, err := parseJSONScavenge([]byte(trimmed)); err == nil {
			return accs, "JSON export (otpauth fields)", nil
		}
		return nil, "", errors.New("unrecognised JSON array backup (tried andOTP and a scan for otpauth fields)")
	}
	// Non-JSON: either a URI list or a CSV with a TOTP column.
	if accs, err := parseURIList(trimmed); err == nil {
		return accs, "otpauth URI list", nil
	}
	if accs, err := parseKeePassCSV(trimmed); err == nil {
		return accs, "KeePassXC CSV", nil
	}
	return nil, "", errors.New("unrecognised backup format")
}

// finish applies the shared tail of every importer: defaults, validation and ID.
func finish(a Account) (Account, error) {
	if a.Digits == 0 {
		a.Digits = DefaultDigits
	}
	// Steam Guard is time-based too, so it needs a period just as much as
	// TOTP does; only counter-based codes have no use for one. Leaving it at
	// zero made Validate reject every Steam entry whose export omitted it.
	if a.Period == 0 && a.Kind() != TypeHOTP {
		a.Period = DefaultPeriod
	}
	if a.Algo == "" {
		a.Algo = AlgoSHA1
	}
	a.Secret = NormalizeSecret(a.Secret)
	a.Issuer = strings.TrimSpace(a.Issuer)
	a.Name = strings.TrimSpace(a.Name)
	// Some exports put "Issuer:name" in the name and leave issuer empty.
	if a.Issuer == "" {
		if parts := strings.SplitN(a.Name, ":", 2); len(parts) == 2 {
			a.Issuer, a.Name = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	if a.AddedAt == 0 {
		a.AddedAt = time.Now().Unix()
	}
	if err := a.Validate(); err != nil {
		return a, fmt.Errorf("%s: %w", a.Label(), err)
	}
	a.ID = MakeID(a)
	return a, nil
}

func algoFrom(s string) (Algo, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "SHA1":
		return AlgoSHA1, nil
	case "SHA256":
		return AlgoSHA256, nil
	case "SHA512":
		return AlgoSHA512, nil
	default:
		return "", fmt.Errorf("unsupported algorithm %q", s)
	}
}

func typeFrom(s string) (OTPType, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "totp":
		return TypeTOTP, nil
	case "hotp":
		return TypeHOTP, nil
	case "steam":
		return TypeSteam, nil
	default:
		return "", fmt.Errorf("unsupported entry type %q", s)
	}
}

// --- Aegis ---

func parseAegis(data []byte) ([]Account, error) {
	var f struct {
		DB struct {
			Entries []struct {
				Type   string `json:"type"`
				Name   string `json:"name"`
				Issuer string `json:"issuer"`
				Note   string `json:"note"`
				Info   struct {
					Secret  string `json:"secret"`
					Algo    string `json:"algo"`
					Digits  int    `json:"digits"`
					Period  int    `json:"period"`
					Counter uint64 `json:"counter"`
				} `json:"info"`
			} `json:"entries"`
		} `json:"db"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if len(f.DB.Entries) == 0 {
		return nil, errors.New("no Aegis entries")
	}
	out := make([]Account, 0, len(f.DB.Entries))
	for _, e := range f.DB.Entries {
		kind, err := typeFrom(e.Type)
		if err != nil {
			return nil, err
		}
		algo, err := algoFrom(e.Info.Algo)
		if err != nil {
			return nil, err
		}
		acc, err := finish(Account{
			Issuer: e.Issuer, Name: e.Name, Secret: e.Info.Secret,
			Digits: e.Info.Digits, Period: e.Info.Period, Algo: algo,
			Type: kind, Counter: e.Info.Counter, Notes: e.Note,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

// isEncryptedAegis reports whether data is an Aegis export whose database is
// still ciphertext (a JSON string rather than an object).
func isEncryptedAegis(data []byte) bool {
	var probe struct {
		DB json.RawMessage `json:"db"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	trimmed := strings.TrimSpace(string(probe.DB))
	return len(trimmed) > 0 && trimmed[0] == '"'
}

// --- andOTP ---

func parseAndOTP(data []byte) ([]Account, error) {
	var entries []struct {
		Secret    string   `json:"secret"`
		Label     string   `json:"label"`
		Issuer    string   `json:"issuer"`
		Digits    int      `json:"digits"`
		Type      string   `json:"type"`
		Algorithm string   `json:"algorithm"`
		Period    int      `json:"period"`
		Counter   uint64   `json:"counter"`
		Tags      []string `json:"tags"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("no andOTP entries")
	}
	out := make([]Account, 0, len(entries))
	for _, e := range entries {
		if e.Secret == "" {
			return nil, errors.New("andOTP entry has no secret")
		}
		kind, err := typeFrom(e.Type)
		if err != nil {
			return nil, err
		}
		algo, err := algoFrom(e.Algorithm)
		if err != nil {
			return nil, err
		}
		acc, err := finish(Account{
			Issuer: e.Issuer, Name: e.Label, Secret: e.Secret,
			Digits: e.Digits, Period: e.Period, Algo: algo,
			Type: kind, Counter: e.Counter, Tags: e.Tags,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

// --- 2FAS ---

func parse2FAS(data []byte) ([]Account, error) {
	var f struct {
		Services []struct {
			Secret string `json:"secret"`
			Name   string `json:"name"`
			OTP    struct {
				Account   string `json:"account"`
				Issuer    string `json:"issuer"`
				Digits    int    `json:"digits"`
				Period    int    `json:"period"`
				Algorithm string `json:"algorithm"`
				TokenType string `json:"tokenType"`
				Counter   uint64 `json:"counter"`
			} `json:"otp"`
		} `json:"services"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if len(f.Services) == 0 {
		return nil, errors.New("no 2FAS services")
	}
	out := make([]Account, 0, len(f.Services))
	for _, e := range f.Services {
		kind, err := typeFrom(e.OTP.TokenType)
		if err != nil {
			return nil, err
		}
		algo, err := algoFrom(e.OTP.Algorithm)
		if err != nil {
			return nil, err
		}
		issuer := e.OTP.Issuer
		if issuer == "" {
			issuer = e.Name
		}
		name := e.OTP.Account
		if name == "" {
			name = e.Name
		}
		acc, err := finish(Account{
			Issuer: issuer, Name: name, Secret: e.Secret,
			Digits: e.OTP.Digits, Period: e.OTP.Period, Algo: algo,
			Type: kind, Counter: e.OTP.Counter,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, acc)
	}
	return out, nil
}

// --- otpauth URI list ---

func parseURIList(text string) ([]Account, error) {
	var out []Account
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if IsMigrationURI(line) {
			accs, err := ParseMigrationURI(line)
			if err != nil {
				return nil, err
			}
			out = append(out, accs...)
			continue
		}
		if !strings.HasPrefix(strings.ToLower(line), "otpauth://") {
			return nil, fmt.Errorf("not a URI list (line %q)", truncate(line, 40))
		}
		acc, err := ParseOtpauthURI(line)
		if err != nil {
			return nil, err
		}
		out = append(out, *acc)
	}
	if len(out) == 0 {
		return nil, errors.New("no URIs found")
	}
	return out, nil
}

// --- KeePassXC CSV ---

// parseKeePassCSV reads a KeePassXC CSV export, taking accounts from whichever
// column holds an otpauth:// URI. KeePassXC stores TOTP as such a URI, so this
// works regardless of which optional columns the export included.
func parseKeePassCSV(text string) ([]Account, error) {
	r := csv.NewReader(strings.NewReader(text))
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, errors.New("csv has no data rows")
	}
	var out []Account
	for _, row := range rows[1:] { // skip the header
		for _, cell := range row {
			cell = strings.TrimSpace(cell)
			if !strings.HasPrefix(strings.ToLower(cell), "otpauth://") {
				continue
			}
			acc, err := ParseOtpauthURI(cell)
			if err != nil {
				return nil, err
			}
			out = append(out, *acc)
			break
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no otpauth:// URIs in the csv")
	}
	return out, nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

// ExportBackup renders accounts as a newline-separated otpauth:// URI list,
// the format ParseBackup reads back.
func ExportBackup(accounts []Account) string {
	var b strings.Builder
	for _, a := range accounts {
		b.WriteString(a.URI())
		b.WriteByte('\n')
	}
	return b.String()
}

// ParseCounter is a small helper shared by the CLI flags.
func ParseCounter(s string) (uint64, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	return strconv.ParseUint(strings.TrimSpace(s), 10, 64)
}
