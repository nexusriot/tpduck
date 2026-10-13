package model

import (
	"bytes"
	"crypto/sha256"
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

// OTPType distinguishes time-based from counter-based codes.
type OTPType string

const (
	TypeTOTP OTPType = "totp"
	TypeHOTP OTPType = "hotp"
	// TypeSteam is Steam Guard: TOTP underneath, but truncated into five
	// characters of Steam's own alphabet instead of decimal digits.
	TypeSteam OTPType = "steam"
)

// Parameter bounds shared by the otpauth parser, the CLI and the account form.
const (
	DefaultDigits = 6
	DefaultPeriod = 30
	MinPeriod     = 1
	MaxPeriod     = 3600
)

type Account struct {
	ID      string   `json:"id"`
	Issuer  string   `json:"issuer"`
	Name    string   `json:"name"`
	Secret  string   `json:"secret"`
	Digits  int      `json:"digits"`
	Period  int      `json:"period"`
	Algo    Algo     `json:"algo"`
	Type    OTPType  `json:"type,omitempty"`    // empty means totp (vaults written before HOTP support)
	Counter uint64   `json:"counter,omitempty"` // HOTP only
	Notes   string   `json:"notes,omitempty"`
	Tags    []string `json:"tags,omitempty"`
	AddedAt int64    `json:"added_at_unix,omitempty"`

	// Pinned floats an account to the top of the list; LastUsedAt records when
	// a code was last taken, so the list can be ordered by what you actually
	// reach for rather than alphabetically.
	Pinned     bool  `json:"pinned,omitempty"`
	LastUsedAt int64 `json:"last_used_at_unix,omitempty"`
}

// Kind returns the account's OTP type, defaulting to TOTP so vaults written
// before HOTP support keep working.
func (a Account) Kind() OTPType {
	switch a.Type {
	case TypeHOTP, TypeSteam:
		return a.Type
	default:
		return TypeTOTP
	}
}

// HasTag reports whether the account carries a tag, ignoring case.
func (a Account) HasTag(tag string) bool {
	for _, t := range a.Tags {
		if strings.EqualFold(t, tag) {
			return true
		}
	}
	return false
}

// Label renders the account the way a human refers to it.
func (a Account) Label() string {
	if a.Issuer == "" {
		return a.Name
	}
	return a.Issuer + ":" + a.Name
}

// Matches reports whether the account matches a case-insensitive substring
// query against its issuer, name, ID and notes.
func (a Account) Matches(query string) bool {
	if query == "" {
		return true
	}
	q := strings.ToLower(query)
	// "tag:work" filters by tag rather than searching the text fields.
	if rest, ok := strings.CutPrefix(q, "tag:"); ok {
		return a.HasTag(strings.TrimSpace(rest))
	}
	for _, f := range []string{a.Issuer, a.Name, a.ID, a.Notes} {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	for _, t := range a.Tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

// Validate checks an account's parameters before it enters the store.
func (a *Account) Validate() error {
	if strings.TrimSpace(a.Name) == "" {
		return errors.New("name is required")
	}
	if err := ValidateSecret(a.Secret); err != nil {
		return fmt.Errorf("invalid secret: %w", err)
	}
	if a.Kind() == TypeSteam {
		// Steam's alphabet is fixed at five characters; any stored digit count
		// is ignored, so normalise rather than rejecting an import.
		a.Digits = SteamDigits
	} else if a.Digits != 6 && a.Digits != 8 {
		return fmt.Errorf("digits must be 6 or 8, got %d", a.Digits)
	}
	switch a.Kind() {
	case TypeTOTP, TypeSteam:
		if a.Period < MinPeriod || a.Period > MaxPeriod {
			return fmt.Errorf("period must be between %d and %d seconds, got %d", MinPeriod, MaxPeriod, a.Period)
		}
	case TypeHOTP:
		// Counter-based codes have no period; any stored value is ignored.
	default:
		return fmt.Errorf("unsupported type: %s", a.Type)
	}
	switch a.Algo {
	case AlgoSHA1, AlgoSHA256, AlgoSHA512:
	default:
		return fmt.Errorf("unsupported algorithm: %s", a.Algo)
	}
	return nil
}

// SortOrder controls how the account list is ordered.
type SortOrder string

const (
	SortByIssuer SortOrder = "issuer" // alphabetical
	SortByUsed   SortOrder = "used"   // most recently used first
)

type Store struct {
	Accounts []Account `json:"accounts"`

	// TimeOffsetSeconds is added to the system clock when generating codes, for
	// a device whose clock cannot be synchronised. It is a workaround, not a
	// fix: `tpduck skew` reports the real drift either way.
	TimeOffsetSeconds int64 `json:"time_offset_seconds,omitempty"`

	// Order is how the UI lists accounts. Empty means SortByIssuer.
	Order SortOrder `json:"order,omitempty"`

	// origin records the file this store was read from and what it contained
	// at the time, so a save can refuse to overwrite somebody else's changes.
	// It is unexported, so encoding/json neither writes nor reads it.
	origin vaultOrigin
}

// vaultOrigin fingerprints the vault file a store was loaded from.
type vaultOrigin struct {
	// known is false for a store built in memory rather than read from disk.
	// Writing such a store is a deliberate "create or replace", so it is not
	// subject to the staleness check.
	known  bool
	path   string
	exists bool
	size   int64
	sum    [sha256.Size]byte
}

// ErrVaultChanged is returned when the vault on disk no longer matches what
// this store was read from, so writing would discard somebody else's work.
var ErrVaultChanged = errors.New("vault changed on disk since it was read")

// stampFile fingerprints the current contents of a vault file. A missing file
// is a valid fingerprint: "there was nothing here".
func stampFile(path string) (vaultOrigin, error) {
	o := vaultOrigin{known: true, path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return o, nil
		}
		return o, err
	}
	o.exists = true
	o.size = int64(len(data))
	o.sum = sha256.Sum256(data)
	return o, nil
}

// stampBytes fingerprints content we are about to write, so the store knows
// what the file holds without reading it back.
func stampBytes(path string, data []byte) vaultOrigin {
	return vaultOrigin{
		known: true, path: path, exists: true,
		size: int64(len(data)), sum: sha256.Sum256(data),
	}
}

func (o vaultOrigin) matches(other vaultOrigin) bool {
	return o.exists == other.exists && o.size == other.size && o.sum == other.sum
}

// checkUnchanged reports whether path still holds what this store was read
// from. It is skipped for stores that were never loaded, and for saves to a
// different path, which are copies rather than updates.
func (s *Store) checkUnchanged(path string) error {
	if !s.origin.known || s.origin.path != path {
		return nil
	}
	now, err := stampFile(path)
	if err != nil {
		return err
	}
	if s.origin.matches(now) {
		return nil
	}
	switch {
	case s.origin.exists && !now.exists:
		return fmt.Errorf("%w: %s was deleted", ErrVaultChanged, path)
	case !s.origin.exists && now.exists:
		return fmt.Errorf("%w: %s was created by something else", ErrVaultChanged, path)
	default:
		return fmt.Errorf("%w: %s was modified by something else", ErrVaultChanged, path)
	}
}

// Now returns the time codes should be generated for, applying any configured
// offset.
func (s *Store) Now() time.Time {
	return time.Now().Add(time.Duration(s.TimeOffsetSeconds) * time.Second)
}

// MarkUsed records that a code was taken for this account.
func (s *Store) MarkUsed(id string) {
	if i := s.FindIndexByID(id); i >= 0 {
		s.Accounts[i].LastUsedAt = time.Now().Unix()
	}
}

// Tags returns every tag in use, sorted and de-duplicated.
func (s *Store) Tags() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range s.Accounts {
		for _, t := range a.Tags {
			k := strings.ToLower(t)
			if !seen[k] {
				seen[k] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out
}

// SetTags replaces an account's tags, trimming and de-duplicating them.
func (s *Store) SetTags(id string, tags []string) error {
	i := s.FindIndexByID(id)
	if i < 0 {
		return fmt.Errorf("no account with id %q", id)
	}
	seen := map[string]bool{}
	var clean []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		clean = append(clean, t)
	}
	sort.Strings(clean)
	s.Accounts[i].Tags = clean
	return nil
}

// TogglePinned flips an account's pinned flag and reports the new value.
func (s *Store) TogglePinned(id string) (bool, error) {
	i := s.FindIndexByID(id)
	if i < 0 {
		return false, fmt.Errorf("no account with id %q", id)
	}
	s.Accounts[i].Pinned = !s.Accounts[i].Pinned
	return s.Accounts[i].Pinned, nil
}

func (s *Store) FindIndexByID(id string) int {
	for i := range s.Accounts {
		if s.Accounts[i].ID == id {
			return i
		}
	}
	return -1
}

// Find resolves a query to exactly one account. It accepts an exact ID, then an
// exact "issuer:name" label, then a unique case-insensitive substring match.
func (s *Store) Find(query string) (*Account, error) {
	if i := s.FindIndexByID(query); i >= 0 {
		return &s.Accounts[i], nil
	}
	for i := range s.Accounts {
		if strings.EqualFold(s.Accounts[i].Label(), query) {
			return &s.Accounts[i], nil
		}
	}
	var hits []int
	for i := range s.Accounts {
		if s.Accounts[i].Matches(query) {
			hits = append(hits, i)
		}
	}
	switch len(hits) {
	case 0:
		return nil, fmt.Errorf("no account matches %q", query)
	case 1:
		return &s.Accounts[hits[0]], nil
	default:
		labels := make([]string, 0, len(hits))
		for _, i := range hits {
			labels = append(labels, s.Accounts[i].Label())
		}
		return nil, fmt.Errorf("%q matches %d accounts: %s", query, len(hits), strings.Join(labels, ", "))
	}
}

// HasID reports whether any account other than the one at index `except`
// (pass -1 for none) already uses id.
func (s *Store) HasID(id string, except int) bool {
	for i := range s.Accounts {
		if i != except && s.Accounts[i].ID == id {
			return true
		}
	}
	return false
}

// UniqueID returns id, or id with a numeric suffix if it is already taken.
func (s *Store) UniqueID(id string, except int) string {
	if !s.HasID(id, except) {
		return id
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s#%d", id, n)
		if !s.HasID(cand, except) {
			return cand
		}
	}
}

// Sort orders accounts for display: pinned first, then by the configured
// order, with the alphabetical comparison as the final tie-break so the result
// is always deterministic.
func (s *Store) Sort() {
	byName := func(ai, aj Account) bool {
		if ai.Issuer != aj.Issuer {
			return ai.Issuer < aj.Issuer
		}
		if ai.Name != aj.Name {
			return ai.Name < aj.Name
		}
		return ai.ID < aj.ID
	}
	sort.SliceStable(s.Accounts, func(i, j int) bool {
		ai, aj := s.Accounts[i], s.Accounts[j]
		if ai.Pinned != aj.Pinned {
			return ai.Pinned
		}
		if s.Order == SortByUsed && ai.LastUsedAt != aj.LastUsedAt {
			return ai.LastUsedAt > aj.LastUsedAt // most recent first
		}
		return byName(ai, aj)
	})
}

// Wipe overwrites every secret in memory. Go's GC may still have copies, but
// this removes the obvious ones when the vault is locked.
func (s *Store) Wipe() {
	for i := range s.Accounts {
		zeroString(&s.Accounts[i].Secret)
	}
	s.Accounts = nil
}

const (
	appDir    = "tpduck"
	legacyDir = "totp-tui"
	vaultName = "accounts.json"
)

// DefaultConfigPath returns the vault path, creating the directory. A vault
// left behind by the pre-rename config directory is moved across on first use
// so existing installs keep their accounts.
func DefaultConfigPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfgDir, appDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, vaultName)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		legacy := filepath.Join(cfgDir, legacyDir, vaultName)
		if _, err := os.Stat(legacy); err == nil {
			// Copy rather than rename: leaving the old file in place means a
			// failed migration can never lose the only copy of the vault.
			if data, err := os.ReadFile(legacy); err == nil {
				_ = writeFileAtomic(path, data)
			}
		}
	}
	return path, nil
}

// ErrEncrypted is returned by LoadStore when the vault needs a passphrase.
var ErrEncrypted = errors.New("vault is encrypted")

// LoadStore reads a plaintext vault. It returns ErrEncrypted if the file is an
// encrypted envelope, in which case the caller must use LoadStoreWithPass.
func LoadStore(path string) (*Store, error) {
	data, origin, err := readVault(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return emptyStore(origin), nil
	}
	if IsEncrypted(data) {
		return nil, ErrEncrypted
	}
	return decodeStore(data, origin)
}

// readVault reads a vault and fingerprints it. A missing file yields nil data
// and a fingerprint saying so, which is what lets a first save detect that
// something else created the vault in the meantime.
func readVault(path string) ([]byte, vaultOrigin, error) {
	origin := vaultOrigin{known: true, path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, origin, nil
		}
		return nil, origin, err
	}
	origin.exists = true
	origin.size = int64(len(data))
	origin.sum = sha256.Sum256(data)
	return data, origin, nil
}

func emptyStore(origin vaultOrigin) *Store {
	return &Store{Accounts: []Account{}, origin: origin}
}

// LoadStoreWithPass reads a vault, decrypting it if necessary. A passphrase
// supplied for a plaintext vault is ignored.
func LoadStoreWithPass(path, passphrase string) (*Store, error) {
	data, origin, err := readVault(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return emptyStore(origin), nil
	}
	if IsEncrypted(data) {
		plain, err := Decrypt(data, passphrase)
		if err != nil {
			return nil, err
		}
		return decodeStore(plain, origin)
	}
	return decodeStore(data, origin)
}

// decodeStore parses vault contents. `origin` fingerprints the file the bytes
// came from -- for an encrypted vault that is the envelope, not the plaintext,
// since the envelope is what a later read will compare against.
func decodeStore(data []byte, origin vaultOrigin) (*Store, error) {
	var s Store
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", origin.path, err)
	}
	if s.Accounts == nil {
		s.Accounts = []Account{}
	}
	s.origin = origin
	return &s, nil
}

// IsVaultEncrypted reports whether the vault at path needs a passphrase.
func IsVaultEncrypted(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return IsEncrypted(data), nil
}

// LoadStoreWithKey reads a vault using an already-derived key.
func LoadStoreWithKey(path string, k *Key) (*Store, error) {
	data, origin, err := readVault(path)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return emptyStore(origin), nil
	}
	if !IsEncrypted(data) {
		return decodeStore(data, origin)
	}
	if k == nil {
		return nil, ErrEncrypted
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse vault: %w", err)
	}
	plain, err := k.open(&e)
	if err != nil {
		return nil, err
	}
	return decodeStore(plain, origin)
}

// SaveWithKey writes the vault sealed under an already-derived key, or in
// plaintext when k is nil. Deriving a key costs ~100ms, so the TUI derives
// once at unlock and saves through this.
//
// It returns ErrVaultChanged rather than overwriting a vault that something
// else has modified since this store was read. Use ForceSaveWithKey once the
// user has decided what to do about it.
func (s *Store) SaveWithKey(path string, k *Key) error { return s.save(path, k, false) }

// ForceSaveWithKey writes unconditionally, discarding whatever is on disk.
func (s *Store) ForceSaveWithKey(path string, k *Key) error { return s.save(path, k, true) }

func (s *Store) save(path string, k *Key, force bool) error {
	// The lock makes the check and the rename that commits it one step, so two
	// writers cannot both decide the file is unchanged.
	unlock, err := lockVault(path)
	if err != nil {
		return err
	}
	defer unlock()

	if !force {
		if err := s.checkUnchanged(path); err != nil {
			return err
		}
	}
	s.Sort()
	data, err := s.encode()
	if err != nil {
		return err
	}
	if k != nil {
		if data, err = k.Seal(data); err != nil {
			return err
		}
	}
	// Keep the previous state before replacing it. A failure here is not worth
	// refusing the save over -- losing a backup copy beats losing the write.
	_ = rotateVersions(path)
	if err := writeFileAtomic(path, data); err != nil {
		return err
	}
	// This store now describes what is on disk, so the next save compares
	// against what we just wrote.
	s.origin = stampBytes(path, data)
	return nil
}

// Reload re-reads the vault from the file this store came from, discarding
// unsaved changes. It is how a caller recovers from ErrVaultChanged by taking
// the other writer's version.
func (s *Store) Reload(k *Key) (*Store, error) {
	if !s.origin.known {
		return nil, errors.New("this store was not loaded from a file")
	}
	return LoadStoreWithKey(s.origin.path, k)
}

// VaultPath reports the file this store was loaded from, if any.
func (s *Store) VaultPath() string { return s.origin.path }

func (s *Store) encode() ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Save writes the vault in plaintext.
func (s *Store) Save(path string) error { return s.SaveWithPass(path, "") }

// SaveWithPass writes the vault, encrypting it when passphrase is non-empty.
func (s *Store) SaveWithPass(path, passphrase string) error {
	if passphrase == "" {
		return s.save(path, nil, false)
	}
	k, err := NewKey(passphrase)
	if err != nil {
		return err
	}
	defer k.Zero()
	return s.save(path, k, false)
}

// writeFileAtomic writes data to a temp file in the same directory, fsyncs it
// and renames it over path, so an interrupted write can never truncate an
// existing vault.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".accounts-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename succeeded
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func MakeID(a Account) string {
	i := strings.ToLower(strings.TrimSpace(a.Issuer))
	n := strings.ToLower(strings.TrimSpace(a.Name))
	if i == "" && n == "" {
		return fmt.Sprintf("acc-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%s:%s", i, n)
}

// OpenVaultFile reads a vault and returns both the store and the derived key,
// so the caller can save again without paying the KDF cost a second time. The
// key is nil for a plaintext vault.
func OpenVaultFile(path, passphrase string) (*Store, *Key, error) {
	data, origin, err := readVault(path)
	if err != nil {
		return nil, nil, err
	}
	if data == nil {
		return emptyStore(origin), nil, nil
	}
	if !IsEncrypted(data) {
		s, err := decodeStore(data, origin)
		return s, nil, err
	}
	plain, key, err := Open(data, passphrase)
	if err != nil {
		return nil, nil, err
	}
	s, err := decodeStore(plain, origin)
	if err != nil {
		key.Zero()
		return nil, nil, err
	}
	return s, key, nil
}
