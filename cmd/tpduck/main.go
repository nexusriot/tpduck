// Command tpduck is a terminal TOTP/HOTP authenticator.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/nexusriot/tpduck/internal/agent"
	"github.com/nexusriot/tpduck/internal/clipboard"
	"github.com/nexusriot/tpduck/internal/controller"
	"github.com/nexusriot/tpduck/internal/keyring"
	"github.com/nexusriot/tpduck/internal/model"
	"github.com/nexusriot/tpduck/internal/version"
	"github.com/nexusriot/tpduck/internal/view"
)

const usage = `tpduck -- terminal TOTP/HOTP authenticator

Usage:
  tpduck [flags]                    open the interactive UI

Codes
  tpduck code <query>               print one code
  tpduck verify <query> <code>      check a code a server showed you
  tpduck resync <query> <code>      realign an HOTP counter

Accounts
  tpduck list [-tags work]          list accounts (never prints secrets)
  tpduck add <uri|file|image.png>   import a URI, a backup, or a QR screenshot
  tpduck add -secret S -name N ...  add an account from its parts
  tpduck pin <query>                pin/unpin an account
  tpduck tag [<query> <tags>]       list tags, or set them on an account
  tpduck order <issuer|used>        set the list ordering
  tpduck rm <query>                 delete an account

Moving accounts in and out
  tpduck export [query]             print otpauth:// URIs (SECRETS)
  tpduck qr <query>                 print a scannable QR code (SECRET)
  tpduck migrate                    print migration QR codes for every account
  tpduck backup [-encrypt] <file>   write every account to a file (SECRETS)
  tpduck restore <file>             import a backup written by any supported app
  tpduck versions                   list retained copies of the vault
  tpduck undo [-version N]          put a retained copy back

Vault
  tpduck encrypt | decrypt          add or remove the vault passphrase
  tpduck profiles                   list named vaults (use with -p)
  tpduck agent <run|status|stop|forget>  cache the key for a few minutes
  tpduck keyring <status|set|forget>  manage the stored passphrase
  tpduck offset <seconds|auto|none> compensate for an unsyncable clock

Other
  tpduck skew                       compare the system clock to network time
  tpduck yubikey <list|code|put|delete|rename>   credentials stored on a YubiKey
  tpduck completion <bash|zsh|fish> print a shell completion script
  tpduck version                    print the version
  tpduck help                       this message

Flags:
  -config <path>     vault location (default: the user config dir)
  -idle-lock <dur>   auto-lock after inactivity, 0 disables (default 5m)
  -clip-clear <dur>  clear copied codes after this long, 0 disables (default 15s)
  -ntp <host:port>   server for the clock check (default pool.ntp.org:123)
  -keyring           read the vault passphrase from the OS keyring
  -window <n>        periods either side to accept when verifying (default 1)
  -batch <n>         accounts per migration QR (default 10)
  -reader <name>     smart-card reader to use for yubikey commands
  -p, -profile <n>   use a named profile instead of the default vault
  -agent             use a running tpduck agent (default true)
  -format <fmt>      backup/export format: uri, aegis, andotp
  -encrypt           with "backup": encrypt the file
  -tags a,b          with "add": tag the account; with "list": filter by tag
  -touch             with "yubikey put": require a touch
  -agent-ttl <dur>   how long the agent keeps a key (default 15m)
  -version <n>       with "undo": which retained copy (1 is the most recent)
  -copy              with "code": copy instead of printing
  -json              with "list": machine-readable output
  -force             do not ask for confirmation (rm, restore, undo,
                     yubikey delete)

Fields for "tpduck add" without a URI:
  -secret <base32>   the shared secret (required)
  -name <name>       account name (required)
  -issuer <name>     service name
  -type <kind>       totp, hotp or steam (default totp)
  -algo <alg>        SHA1, SHA256 or SHA512 (default SHA1)
  -digits <n>        6 or 8 (default 6; Steam codes are always 5 characters)
  -period <sec>      seconds per code (default 30)
  -counter <n>       starting counter, for hotp
  -notes <text>      a free-text note

The passphrase for an encrypted vault is read from the terminal, from the OS
keyring with -keyring, or from TPDUCK_PASSPHRASE when that is set (useful for
scripts, but it exposes the passphrase to anything that can read the process
environment).
`

type flags struct {
	config     string
	idleLock   time.Duration
	clipClear  time.Duration
	ntp        string
	useKeyring bool
	profile    string
	useAgent   bool
	agentTTL   time.Duration
	format     string
	tags       string
	encrypted  bool
	version    int
	window     int
	batch      int
	reader     string
	copyCode   bool
	jsonOut    bool
	force      bool

	// account fields for "add"
	secret  string
	issuer  string
	name    string
	algo    string
	digits  int
	period  int
	otpType string
	counter uint64
	notes   string
	touch   bool
}

func main() {
	var f flags
	fs := flag.NewFlagSet("tpduck", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	fs.StringVar(&f.config, "config", "", "vault path")
	fs.DurationVar(&f.idleLock, "idle-lock", 5*time.Minute, "auto-lock after inactivity")
	fs.DurationVar(&f.clipClear, "clip-clear", clipboard.DefaultClearAfter, "clear the clipboard after this long")
	fs.StringVar(&f.ntp, "ntp", model.DefaultNTPServer, "NTP server for the clock check")
	fs.BoolVar(&f.useKeyring, "keyring", false, "read the vault passphrase from the OS keyring")
	fs.StringVar(&f.profile, "p", "", "named profile to use instead of the default vault")
	fs.StringVar(&f.profile, "profile", "", "named profile to use instead of the default vault")
	fs.BoolVar(&f.useAgent, "agent", true, "use a running tpduck agent to avoid re-deriving the key")
	fs.DurationVar(&f.agentTTL, "agent-ttl", 0, "how long the agent should keep a key (default 15m)")
	fs.StringVar(&f.format, "format", string(model.FormatURI), "backup format: "+strings.Join(model.BackupFormats(), ", "))
	fs.StringVar(&f.tags, "tags", "", "comma-separated tags (for add)")
	fs.BoolVar(&f.encrypted, "encrypt", false, "with backup: encrypt the file with a passphrase")
	fs.IntVar(&f.version, "version", 0, "with restore-version: which retained copy (1 is most recent)")
	fs.IntVar(&f.window, "window", model.DefaultVerifyWindow, "periods either side to accept when verifying")
	fs.IntVar(&f.batch, "batch", model.DefaultMigrationBatch, "accounts per migration QR code")
	fs.StringVar(&f.reader, "reader", "", "smart-card reader name")
	fs.BoolVar(&f.copyCode, "copy", false, "copy the code instead of printing it")
	fs.BoolVar(&f.jsonOut, "json", false, "machine-readable output")
	fs.BoolVar(&f.force, "force", false, "do not ask for confirmation")
	fs.StringVar(&f.secret, "secret", "", "Base32 secret (for add)")
	fs.StringVar(&f.issuer, "issuer", "", "issuer (for add)")
	fs.StringVar(&f.name, "name", "", "account name (for add)")
	fs.StringVar(&f.algo, "algo", string(model.AlgoSHA1), "SHA1, SHA256 or SHA512 (for add)")
	fs.IntVar(&f.digits, "digits", model.DefaultDigits, "6 or 8 (for add)")
	fs.IntVar(&f.period, "period", model.DefaultPeriod, "seconds per code (for add)")
	fs.StringVar(&f.otpType, "type", string(model.TypeTOTP), "totp or hotp (for add)")
	fs.Uint64Var(&f.counter, "counter", 0, "initial HOTP counter (for add)")
	fs.StringVar(&f.notes, "notes", "", "free-text note (for add)")
	fs.BoolVar(&f.touch, "touch", false, "with yubikey put: require a touch to use the credential")
	// Collect positional words while parsing flags wherever they appear.
	// Go's flag package stops at the first non-flag word, so without this loop
	// "tpduck yubikey put -secret ..." would leave -secret unparsed: the flags
	// sit behind two subcommand words.
	var args []string
	rest := os.Args[1:]
	for {
		if err := fs.Parse(rest); err != nil {
			os.Exit(2)
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		args = append(args, rest[0])
		rest = rest[1:]
	}

	if err := run(&f, args); err != nil {
		fmt.Fprintln(os.Stderr, "tpduck:", err)
		os.Exit(1)
	}
}

func run(f *flags, args []string) error {
	path, err := resolveVault(f)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return runTUI(f, path)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "version":
		fmt.Printf("tpduck %s\n", version.Full())
		return nil
	case "completion":
		return cmdCompletion(rest)
	case "code":
		return cmdCode(f, path, rest)
	case "verify":
		return cmdVerify(f, path, rest)
	case "resync":
		return cmdResync(f, path, rest)
	case "list":
		return cmdList(f, path)
	case "add", "import":
		return cmdAdd(f, path, rest)
	case "rm", "delete":
		return cmdRemove(f, path, rest)
	case "pin":
		return cmdPin(path, rest)
	case "order":
		return cmdOrder(path, rest)
	case "export":
		return cmdExport(f, path, rest)
	case "qr":
		return cmdQR(path, rest)
	case "migrate":
		return cmdMigrate(f, path)
	case "backup":
		return cmdBackup(f, path, rest)
	case "restore":
		return cmdRestore(f, path, rest)
	case "encrypt":
		return cmdEncrypt(f, path)
	case "decrypt":
		return cmdDecrypt(f, path)
	case "keyring":
		return cmdKeyring(path, rest)
	case "offset":
		return cmdOffset(f, path, rest)
	case "skew":
		return cmdSkew(f, path)
	case "yubikey", "yk":
		return cmdYubikey(f, rest)
	case "agent":
		return cmdAgent(f, path, rest)
	case "profiles":
		return cmdProfiles()
	case "tag":
		return cmdTag(f, path, rest)
	case "versions":
		return cmdVersions(path)
	case "undo", "restore-version":
		return cmdRestoreVersion(f, path, rest)
	default:
		return fmt.Errorf("unknown command %q (try: tpduck help)", cmd)
	}
}

func vaultPath(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	return model.DefaultConfigPath()
}

// resolveVault picks the vault: an explicit -config wins, then a -p profile,
// then the default.
func resolveVault(f *flags) (string, error) {
	if f.config != "" {
		return f.config, nil
	}
	return model.ProfilePath(f.profile)
}

func runTUI(f *flags, path string) error {
	v := view.New()
	c, err := controller.New(v, controller.Options{
		Path:       path,
		IdleLock:   f.idleLock,
		ClipClear:  f.clipClear,
		NTPServer:  f.ntp,
		UseKeyring: f.useKeyring,
	})
	if err != nil {
		return err
	}
	c.Start(250 * time.Millisecond)
	return nil
}

// --- passphrase handling ----------------------------------------------------

// readPassphrase asks the terminal, falling back to TPDUCK_PASSPHRASE.
func readPassphrase(prompt string) (string, error) {
	if p, ok := os.LookupEnv("TPDUCK_PASSPHRASE"); ok {
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", errors.New("vault is encrypted and stdin is not a terminal; set TPDUCK_PASSPHRASE or use -keyring")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// vaultPassphrase resolves the passphrase for an encrypted vault, preferring
// the keyring when the user asked for it.
func vaultPassphrase(f *flags, path string) (string, error) {
	if f != nil && f.useKeyring {
		if pass, err := keyring.Get(path); err == nil && pass != "" {
			return pass, nil
		}
	}
	return readPassphrase("Passphrase: ")
}

// openVault loads the vault, prompting only if it is actually encrypted.
//
// An agent, when one is running, supplies the already-derived key, which skips
// both the prompt and the key derivation. Falling back to asking is always
// safe: a cached key that no longer matches the vault is simply a miss.
func openVault(f *flags, path string) (*model.Store, *model.Key, error) {
	encrypted, err := model.IsVaultEncrypted(path)
	if err != nil {
		return nil, nil, err
	}
	if !encrypted {
		s, err := model.LoadStore(path)
		return s, nil, err
	}
	if f != nil && f.useAgent {
		if store, key, ok := openViaAgent(path); ok {
			return store, key, nil
		}
	}
	pass, err := vaultPassphrase(f, path)
	if err != nil {
		return nil, nil, err
	}
	store, key, err := model.OpenVaultFile(path, pass)
	if err != nil {
		return nil, nil, err
	}
	if f != nil && f.useAgent && agent.Running() {
		if blob, err := key.Export(); err == nil {
			_ = agent.Put(path, blob, f.agentTTL)
		}
	}
	return store, key, nil
}

func openViaAgent(path string) (*model.Store, *model.Key, bool) {
	blob, err := agent.Get(path)
	if err != nil {
		return nil, nil, false
	}
	key, err := model.ImportKey(blob)
	if err != nil || !key.MatchesVault(path) {
		// Stale entry: the vault was re-encrypted elsewhere.
		_ = agent.Drop(path)
		return nil, nil, false
	}
	store, err := model.LoadStoreWithKey(path, key)
	if err != nil {
		key.Zero()
		_ = agent.Drop(path)
		return nil, nil, false
	}
	return store, key, true
}
