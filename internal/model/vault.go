package model

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// KDF names understood by the vault format.
const (
	KDFScrypt   = "scrypt"
	KDFArgon2id = "argon2id"
	// KDFArgon2idHMAC folds a hardware token's HMAC-SHA1 challenge-response
	// into the Argon2id input. The vault then cannot be opened by copying the
	// file: the token's secret never leaves it, so an attacker needs the
	// hardware as well as whatever passphrase is set.
	KDFArgon2idHMAC = "argon2id-hmac"
)

// DefaultKDF is what a new vault is written with. Argon2id is the current
// recommendation for passphrase hashing; scrypt stays readable forever so
// vaults written by older builds keep opening.
const DefaultKDF = KDFArgon2id

// Argon2id cost: 64 MiB, 3 passes, 4 lanes -- the "second recommended" option
// from RFC 9106, sized to match the scrypt defaults below.
const (
	defaultArgonTime    = 3
	defaultArgonMemory  = 64 * 1024 // KiB
	defaultArgonThreads = 4
)

// Vault format: a JSON envelope holding scrypt parameters and an
// XChaCha20-Poly1305 ciphertext. The envelope is distinguishable from a
// plaintext store by its "tpduck" version field, which a plaintext store never
// has, so the reader can tell the two apart without a magic byte prefix.
const vaultVersion = 1

// Default scrypt cost: 64 MiB, roughly 0.1-0.3s on current hardware. The
// parameters are stored per-vault so they can be raised later without
// invalidating existing files.
const (
	defaultScryptN = 1 << 16
	defaultScryptR = 8
	defaultScryptP = 1
	keyLen         = chacha20poly1305.KeySize
	saltLen        = 16
)

// HardwareResponder asks a hardware token for HMAC-SHA1 of a challenge. The
// model never talks to a card itself: the caller supplies this, which keeps
// the vault format testable and keeps smart-card code out of the data layer.
type HardwareResponder func(challenge []byte) ([]byte, error)

// Unlock is everything needed to derive a vault's key: the passphrase, and a
// responder for a vault that also needs a hardware token. A vault that needs
// one and is given none fails with ErrHardwareRequired rather than a
// misleading "wrong passphrase".
type Unlock struct {
	Passphrase string
	Hardware   HardwareResponder
}

// Pass builds an Unlock for an ordinary passphrase-only vault.
func Pass(passphrase string) Unlock { return Unlock{Passphrase: passphrase} }

// ErrHardwareRequired means the vault is sealed to a hardware token and none
// was offered.
var ErrHardwareRequired = errors.New("this vault needs its YubiKey; plug it in (or pass -yubikey)")

// DefaultHardwareSlot is the challenge-response slot tpduck uses unless told
// otherwise. Slot 1 usually still holds the factory Yubico OTP credential, so
// slot 2 is the one people programme for challenge-response.
const DefaultHardwareSlot = 2

// hardwareChallengeLen is how many random bytes the token is asked to sign.
// It is stored in the envelope, so the same challenge is replayed every time
// and the response is stable.
const hardwareChallengeLen = 32

// ErrWrongPassphrase is returned when authentication fails. It deliberately
// does not distinguish a bad passphrase from a corrupted file: the AEAD tag
// covers both and guessing which it was only helps an attacker.
var ErrWrongPassphrase = errors.New("wrong passphrase or corrupted vault")

// envelope is the on-disk vault header. For scrypt, n/r/p are its cost
// parameters; for argon2id they carry memory (KiB), time and threads, which
// keeps one shape for both and means the AAD binding covers either.
type envelope struct {
	Tpduck int    `json:"tpduck"`
	KDF    string `json:"kdf"`
	N      int    `json:"n"`
	R      int    `json:"r"`
	P      int    `json:"p"`
	Salt   []byte `json:"salt"`
	// HWChallenge and HWSlot are set only for KDFArgon2idHMAC: the challenge
	// replayed to the token every unlock, and which of its two slots answers.
	// They are not secret -- the response to them is.
	HWChallenge []byte `json:"hw_challenge,omitempty"`
	HWSlot      int    `json:"hw_slot,omitempty"`
	// HWOnly says the token is the only factor, so there is no passphrase to
	// ask for. It is a prompting hint and nothing more: the key comes out of
	// whatever material the caller supplies either way.
	HWOnly     bool   `json:"hw_only,omitempty"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// aad returns the additional authenticated data binding the ciphertext to the
// KDF parameters, so an attacker cannot strip the cost down to something
// brute-forceable and have the result still authenticate.
func (e *envelope) aad() []byte {
	base := fmt.Sprintf("tpduck/%d|%s|%d|%d|%d", e.Tpduck, e.KDF, e.N, e.R, e.P)
	if e.KDF == KDFArgon2idHMAC {
		// The challenge and slot pick which response goes into the key, so
		// they are part of what the tag must cover. Changing either already
		// derives a different key; binding them as well means a tampered
		// header fails as a forgery rather than as a wrong passphrase.
		base += fmt.Sprintf("|%x|%d", e.HWChallenge, e.HWSlot)
	}
	return []byte(base)
}

// Key is a passphrase-derived encryption key. Deriving it is deliberately slow,
// so the TUI derives once at unlock and reuses it for every save.
type Key struct {
	key     []byte
	kdf     string
	salt    []byte
	n, r, p int

	// hwChallenge and hwSlot are carried so a key derived once can re-seal the
	// vault without asking the token again, and so a cached key can be matched
	// against the envelope it belongs to.
	hwChallenge []byte
	hwSlot      int
	hwOnly      bool
}

// NeedsHardware reports whether this key was derived with a hardware token.
func (k *Key) NeedsHardware() bool { return k != nil && k.kdf == KDFArgon2idHMAC }

// HardwareSlot reports which token slot this key was derived against, or 0.
func (k *Key) HardwareSlot() int {
	if k == nil {
		return 0
	}
	return k.hwSlot
}

// KDF reports which key-derivation function this key was built with.
func (k *Key) KDF() string {
	if k == nil {
		return ""
	}
	return k.kdf
}

// NewKey derives a fresh key with a random salt and the default KDF.
func NewKey(passphrase string) (*Key, error) { return NewKeyWithKDF(passphrase, DefaultKDF) }

// NewKeyWithKDF derives a fresh key using the named KDF at its default cost.
func NewKeyWithKDF(passphrase, kdf string) (*Key, error) {
	if passphrase == "" {
		return nil, errors.New("passphrase is empty")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	switch kdf {
	case KDFArgon2id:
		return deriveKey(Pass(passphrase), KDFArgon2id, salt, defaultArgonMemory, defaultArgonTime, defaultArgonThreads, nil, 0)
	case KDFScrypt:
		return deriveKey(Pass(passphrase), KDFScrypt, salt, defaultScryptN, defaultScryptR, defaultScryptP, nil, 0)
	default:
		return nil, fmt.Errorf("unsupported kdf %q (want %s or %s)", kdf, KDFArgon2id, KDFScrypt)
	}
}

// NewHardwareKey derives a fresh key bound to a hardware token's slot, with a
// random salt and a random challenge. The passphrase may be empty, which makes
// the token the only factor: convenient, and still far better than a plaintext
// vault, but it means whoever holds the key holds the vault.
func NewHardwareKey(u Unlock, slot int) (*Key, error) {
	if u.Hardware == nil {
		return nil, ErrHardwareRequired
	}
	if slot != 1 && slot != 2 {
		return nil, fmt.Errorf("hardware slot must be 1 or 2, got %d", slot)
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	challenge := make([]byte, hardwareChallengeLen)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	k, err := deriveKey(u, KDFArgon2idHMAC, salt,
		defaultArgonMemory, defaultArgonTime, defaultArgonThreads, challenge, slot)
	if err != nil {
		return nil, err
	}
	k.hwOnly = u.Passphrase == ""
	return k, nil
}

func deriveKey(u Unlock, kdf string, salt []byte, n, r, p int, challenge []byte, slot int) (*Key, error) {
	var raw []byte
	switch kdf {
	case KDFArgon2id:
		// n=memory KiB, r=time, p=threads.
		raw = argon2.IDKey([]byte(u.Passphrase), salt, uint32(r), uint32(n), uint8(p), keyLen)
	case KDFArgon2idHMAC:
		material, err := hardwareMaterial(u, challenge, slot)
		if err != nil {
			return nil, err
		}
		raw = argon2.IDKey(material, salt, uint32(r), uint32(n), uint8(p), keyLen)
		for i := range material {
			material[i] = 0
		}
	case KDFScrypt:
		k, err := scrypt.Key([]byte(u.Passphrase), salt, n, r, p, keyLen)
		if err != nil {
			return nil, fmt.Errorf("derive key: %w", err)
		}
		raw = k
	default:
		return nil, fmt.Errorf("unsupported kdf %q", kdf)
	}
	return &Key{
		key: raw, kdf: kdf, salt: salt, n: n, r: r, p: p,
		hwChallenge: append([]byte(nil), challenge...), hwSlot: slot,
	}, nil
}

// hardwareMaterial is what Argon2id actually hashes for a token-backed vault:
// the passphrase followed by the token's 20-byte response. The response is a
// fixed length and goes last, so no passphrase can be confused with a
// passphrase-plus-response of another split.
func hardwareMaterial(u Unlock, challenge []byte, slot int) ([]byte, error) {
	if u.Hardware == nil {
		return nil, ErrHardwareRequired
	}
	if len(challenge) == 0 {
		return nil, errors.New("vault header has no hardware challenge")
	}
	response, err := u.Hardware(challenge)
	if err != nil {
		return nil, fmt.Errorf("ask the YubiKey: %w", err)
	}
	if len(response) != hardwareResponseLen {
		return nil, fmt.Errorf("the YubiKey returned %d bytes, want an %d-byte HMAC-SHA1",
			len(response), hardwareResponseLen)
	}
	out := make([]byte, 0, len(u.Passphrase)+len(response))
	out = append(out, u.Passphrase...)
	return append(out, response...), nil
}

// hardwareResponseLen is the length of an HMAC-SHA1 response. It is spelled
// out here rather than imported so the model keeps no dependency on the
// smart-card package.
const hardwareResponseLen = 20

// Zero overwrites the derived key material. Call it when locking.
func (k *Key) Zero() {
	if k == nil {
		return
	}
	for i := range k.key {
		k.key[i] = 0
	}
	k.key = nil
}

// Seal encrypts plain into a vault envelope.
func (k *Key) Seal(plain []byte) ([]byte, error) {
	if k == nil || len(k.key) == 0 {
		return nil, errors.New("key has been zeroed")
	}
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	e := &envelope{
		Tpduck: vaultVersion, KDF: k.kdf,
		N: k.n, R: k.r, P: k.p,
		Salt: k.salt, Nonce: nonce,
		HWChallenge: k.hwChallenge, HWSlot: k.hwSlot, HWOnly: k.hwOnly,
	}
	e.Ciphertext = aead.Seal(nil, nonce, plain, e.aad())
	return json.MarshalIndent(e, "", "  ")
}

// IsEncrypted reports whether data is a vault envelope rather than a plaintext
// store.
func IsEncrypted(data []byte) bool {
	var probe struct {
		Tpduck int    `json:"tpduck"`
		KDF    string `json:"kdf"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Tpduck > 0 && probe.KDF != ""
}

// Open decrypts a vault envelope and returns the plaintext along with the key,
// so the caller can re-seal without paying for the KDF again.
func Open(data []byte, passphrase string) ([]byte, *Key, error) {
	return OpenVault(data, Pass(passphrase))
}

// OpenVault is Open for a vault that may also need a hardware token.
func OpenVault(data []byte, u Unlock) ([]byte, *Key, error) {
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, nil, fmt.Errorf("parse vault: %w", err)
	}
	if e.Tpduck != vaultVersion {
		return nil, nil, fmt.Errorf("unsupported vault version %d (this build understands %d)", e.Tpduck, vaultVersion)
	}
	if len(e.Salt) == 0 || len(e.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, nil, errors.New("vault header is malformed")
	}
	if err := checkParams(&e); err != nil {
		return nil, nil, err
	}
	if e.KDF == KDFArgon2idHMAC && u.Hardware == nil {
		return nil, nil, ErrHardwareRequired
	}
	k, err := deriveKey(u, e.KDF, e.Salt, e.N, e.R, e.P, e.HWChallenge, e.HWSlot)
	if err != nil {
		return nil, nil, err
	}
	k.hwOnly = e.HWOnly
	aead, err := chacha20poly1305.NewX(k.key)
	if err != nil {
		k.Zero()
		return nil, nil, err
	}
	plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, e.aad())
	if err != nil {
		k.Zero()
		return nil, nil, ErrWrongPassphrase
	}
	return plain, k, nil
}

// checkParams refuses absurd cost parameters rather than trying to allocate
// them: a hostile file could otherwise ask for terabytes of KDF memory.
func checkParams(e *envelope) error {
	switch e.KDF {
	case KDFScrypt:
		if e.N < 1<<10 || e.N > 1<<22 || e.R < 1 || e.R > 64 || e.P < 1 || e.P > 16 {
			return fmt.Errorf("vault kdf parameters out of range (n=%d r=%d p=%d)", e.N, e.R, e.P)
		}
	case KDFArgon2id, KDFArgon2idHMAC:
		// n=memory KiB (1 MiB .. 2 GiB), r=time, p=threads.
		if e.N < 1<<10 || e.N > 2<<20 || e.R < 1 || e.R > 32 || e.P < 1 || e.P > 16 {
			return fmt.Errorf("vault kdf parameters out of range (memory=%dKiB time=%d threads=%d)", e.N, e.R, e.P)
		}
		if e.KDF == KDFArgon2idHMAC {
			if len(e.HWChallenge) == 0 || len(e.HWChallenge) > 64 {
				return fmt.Errorf("vault hardware challenge is %d bytes, want 1..64", len(e.HWChallenge))
			}
			if e.HWSlot != 1 && e.HWSlot != 2 {
				return fmt.Errorf("vault names hardware slot %d, want 1 or 2", e.HWSlot)
			}
		}
	default:
		return fmt.Errorf("unsupported kdf %q (this build understands %s, %s and %s)",
			e.KDF, KDFArgon2id, KDFArgon2idHMAC, KDFScrypt)
	}
	return nil
}

// Encrypt seals plain under a freshly derived key. Prefer Key.Seal when
// encrypting repeatedly; this pays the full KDF cost every call.
func Encrypt(plain []byte, passphrase string) ([]byte, error) {
	k, err := NewKey(passphrase)
	if err != nil {
		return nil, err
	}
	defer k.Zero()
	return k.Seal(plain)
}

// Decrypt opens a vault envelope and discards the key.
func Decrypt(data []byte, passphrase string) ([]byte, error) {
	plain, k, err := Open(data, passphrase)
	if k != nil {
		k.Zero()
	}
	return plain, err
}

// ConstantTimeEqualString compares two secrets without leaking their contents
// through timing. Used when confirming a new passphrase.
func ConstantTimeEqualString(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// zeroString drops a secret from a struct field.
//
// Go strings are immutable and may be interned or copied by the runtime, so
// this cannot guarantee the bytes are gone from memory -- it only removes the
// reference we control. The protection that actually matters is discarding the
// decrypted store and zeroing the key material (which is a []byte and can be
// overwritten) when the vault locks.
func zeroString(s *string) { *s = "" }

// open decrypts an envelope with this key, re-deriving only if the envelope
// uses a different salt or cost than the key was built with.
func (k *Key) open(e *envelope) ([]byte, error) {
	key := k
	if e.KDF != k.kdf || !bytes.Equal(e.Salt, k.salt) || e.N != k.n || e.R != k.r || e.P != k.p ||
		!bytes.Equal(e.HWChallenge, k.hwChallenge) || e.HWSlot != k.hwSlot {
		return nil, errors.New("vault was re-encrypted with different parameters; unlock again")
	}
	aead, err := chacha20poly1305.NewX(key.key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, e.Nonce, e.Ciphertext, e.aad())
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	return plain, nil
}

// portableKey is how a derived key travels to and from the agent. It carries
// the KDF parameters and salt alongside the key material, so an imported key
// can be matched against the envelope it is meant to open.
type portableKey struct {
	KDF         string `json:"kdf"`
	N           int    `json:"n"`
	R           int    `json:"r"`
	P           int    `json:"p"`
	Salt        []byte `json:"salt"`
	HWChallenge []byte `json:"hw_challenge,omitempty"`
	HWSlot      int    `json:"hw_slot,omitempty"`
	Key         []byte `json:"key"`
}

// Export serialises a derived key. The result is key material: it must only
// ever travel somewhere already trusted with the vault's contents.
func (k *Key) Export() ([]byte, error) {
	if k == nil || len(k.key) == 0 {
		return nil, errors.New("key has been zeroed")
	}
	return json.Marshal(portableKey{
		KDF: k.kdf, N: k.n, R: k.r, P: k.p, Salt: k.salt,
		HWChallenge: k.hwChallenge, HWSlot: k.hwSlot, Key: k.key,
	})
}

// ImportKey rebuilds a key from Export. It does not verify the key against a
// vault; opening one will fail cleanly if it does not match.
func ImportKey(data []byte) (*Key, error) {
	var p portableKey
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	if len(p.Key) != keyLen || len(p.Salt) == 0 {
		return nil, errors.New("key material is malformed")
	}
	switch p.KDF {
	case KDFScrypt, KDFArgon2id:
	case KDFArgon2idHMAC:
		if len(p.HWChallenge) == 0 || (p.HWSlot != 1 && p.HWSlot != 2) {
			return nil, errors.New("key material is malformed")
		}
	default:
		return nil, fmt.Errorf("unsupported kdf %q", p.KDF)
	}
	return &Key{
		key: p.Key, kdf: p.KDF, salt: p.Salt, n: p.N, r: p.R, p: p.P,
		hwChallenge: p.HWChallenge, hwSlot: p.HWSlot,
	}, nil
}

// MatchesVault reports whether this key was derived for the vault at path,
// comparing the salt and cost recorded in its envelope. A cached key from a
// different vault is then a miss rather than a confusing decryption failure.
func (k *Key) MatchesVault(path string) bool {
	if k == nil {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil || !IsEncrypted(data) {
		return false
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return false
	}
	return e.KDF == k.kdf && bytes.Equal(e.Salt, k.salt) &&
		e.N == k.n && e.R == k.r && e.P == k.p &&
		bytes.Equal(e.HWChallenge, k.hwChallenge) && e.HWSlot == k.hwSlot
}

// HardwareBinding describes how a vault is tied to a hardware token.
type HardwareBinding struct {
	// Needed is false for an ordinary passphrase-only vault.
	Needed bool
	// Slot is which of the token's two slots answers the challenge.
	Slot int
	// NoPassphrase says the token is the only factor, so nothing should be
	// prompted for.
	NoPassphrase bool
}

// VaultHardware reports how the vault at path is bound to a hardware token, so
// a caller can arrange one before prompting for anything.
func VaultHardware(path string) HardwareBinding {
	data, err := os.ReadFile(path)
	if err != nil || !IsEncrypted(data) {
		return HardwareBinding{}
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return HardwareBinding{}
	}
	if e.KDF != KDFArgon2idHMAC {
		return HardwareBinding{}
	}
	return HardwareBinding{Needed: true, Slot: e.HWSlot, NoPassphrase: e.HWOnly}
}
