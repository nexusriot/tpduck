package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Algo string

const (
	AlgoSHA1   Algo = "SHA1"
	AlgoSHA256 Algo = "SHA256"
	AlgoSHA512 Algo = "SHA512"
)

type Account struct {
	ID      string `json:"id"`
	Issuer  string `json:"issuer"`
	Name    string `json:"name"`
	Secret  string `json:"secret"`
	Digits  int    `json:"digits"`
	Period  int    `json:"period"`
	Algo    Algo   `json:"algo"`
	Notes   string `json:"notes,omitempty"`
	AddedAt int64  `json:"added_at_unix,omitempty"`
}

type Store struct {
	Accounts []Account `json:"accounts"`
}

func (s *Store) FindIndexByID(id string) int {
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			return i
		}
	}
	return -1
}

func DefaultConfigPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfgDir, "totp-tui")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "accounts.json"), nil
}

func LoadStore() (*Store, string, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Store{Accounts: []Account{}}, path, nil
		}
		return nil, "", err
	}
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, "", err
	}
	return &s, path, nil
}

func (s *Store) Save(path string) error {
	sort.Slice(s.Accounts, func(i, j int) bool {
		ai, aj := s.Accounts[i], s.Accounts[j]
		if ai.Issuer != aj.Issuer {
			return ai.Issuer < aj.Issuer
		}
		if ai.Name != aj.Name {
			return ai.Name < aj.Name
		}
		return ai.ID < aj.ID
	})
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o600)
}

func MakeID(a Account) string {
	i := strings.ToLower(strings.TrimSpace(a.Issuer))
	n := strings.ToLower(strings.TrimSpace(a.Name))
	if i == "" && n == "" {
		return fmt.Sprintf("acc-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%s:%s", i, n)
}
