package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/clipboard"
	"github.com/nexusriot/tpduck/internal/controller"
	"github.com/nexusriot/tpduck/internal/keyring"
	"github.com/nexusriot/tpduck/internal/model"
)

// saveVault wraps a store write so a concurrent modification is reported as
// something the user can act on rather than as an opaque failure.
func saveVault(store *model.Store, path string, key *model.Key) error {
	err := store.SaveWithKey(path, key)
	if errors.Is(err, model.ErrVaultChanged) {
		return fmt.Errorf("%w\n       nothing was written. Another tpduck or a sync tool changed the vault;\n       re-run this command to work from the current version", err)
	}
	return err
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// confirm asks a yes/no question unless -force was given.
func confirm(force bool, question string) (bool, error) {
	if force {
		return true, nil
	}
	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, nil
	}
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes", nil
}

// --- codes ---

func cmdCode(f *flags, path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck code <query>")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	code, err := model.Generate(*acc, store.Now())
	if err != nil {
		return err
	}
	// HOTP codes are single-use, so printing one without advancing the counter
	// would hand out the same code forever.
	dirty := false
	if acc.Kind() == model.TypeHOTP {
		if err := store.AdvanceHOTP(acc.ID); err != nil {
			return err
		}
		dirty = true
	}
	store.MarkUsed(acc.ID)
	dirty = true
	if dirty {
		if err := saveVault(store, path, key); err != nil {
			return fmt.Errorf("save: %w", err)
		}
	}
	if f.copyCode {
		var t clipboard.Transient
		if err := t.Copy(code.Value, f.clipClear, nil); err != nil {
			return err
		}
		if f.clipClear > 0 {
			// The clear is scheduled in this process, so it has to outlive the
			// command; without waiting, exiting cancels it.
			fmt.Fprintf(os.Stderr, "copied; clearing clipboard in %s\n", f.clipClear)
			time.Sleep(f.clipClear + 500*time.Millisecond)
			_ = t.Flush()
		}
		return nil
	}
	fmt.Println(code.Value)
	return nil
}

func cmdVerify(f *flags, path string, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tpduck verify <query> <code>")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	res, err := model.Verify(*acc, strings.TrimSpace(args[1]), store.Now(), f.window)
	if err != nil {
		return err
	}
	switch {
	case res.OK && res.Offset == 0:
		fmt.Printf("match: %s is showing this code now\n", acc.Label())
		return nil
	case res.OK:
		fmt.Printf("match, but %+d window(s) away -- check your clock (tpduck skew)\n", res.Offset)
		return nil
	default:
		fmt.Printf("no match for %s within %d window(s)\n", acc.Label(), f.window)
		os.Exit(1)
		return nil
	}
}

func cmdResync(f *flags, path string, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: tpduck resync <query> <code>")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	n, err := store.ResyncHOTP(acc.ID, strings.TrimSpace(args[1]), model.DefaultResyncLookahead)
	if err != nil {
		return err
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	fmt.Printf("%s counter resynced to %d\n", acc.Label(), n)
	return nil
}

// --- accounts ---

func cmdList(f *flags, path string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	store.Sort()
	accounts := store.Accounts
	if t := strings.TrimSpace(f.tags); t != "" {
		var kept []model.Account
		for _, a := range accounts {
			for _, want := range strings.Split(t, ",") {
				if a.HasTag(strings.TrimSpace(want)) {
					kept = append(kept, a)
					break
				}
			}
		}
		accounts = kept
	}
	if f.jsonOut {
		// Secrets are deliberately omitted: "list" is for finding an account,
		// "export" is the command that hands out credentials.
		type row struct {
			ID       string   `json:"id"`
			Issuer   string   `json:"issuer"`
			Name     string   `json:"name"`
			Type     string   `json:"type"`
			Algo     string   `json:"algo"`
			Digits   int      `json:"digits"`
			Period   int      `json:"period,omitempty"`
			Counter  uint64   `json:"counter,omitempty"`
			Tags     []string `json:"tags,omitempty"`
			Pinned   bool     `json:"pinned,omitempty"`
			LastUsed int64    `json:"last_used_at_unix,omitempty"`
		}
		rows := make([]row, 0, len(accounts))
		for _, a := range accounts {
			r := row{ID: a.ID, Issuer: a.Issuer, Name: a.Name, Type: string(a.Kind()),
				Algo: string(a.Algo), Digits: a.Digits, Tags: a.Tags,
				Pinned: a.Pinned, LastUsed: a.LastUsedAt}
			if a.Kind() == model.TypeHOTP {
				r.Counter = a.Counter
			} else {
				r.Period = a.Period
			}
			rows = append(rows, r)
		}
		return writeJSON(rows)
	}
	for _, a := range accounts {
		extra := fmt.Sprintf("%ds", a.Period)
		if a.Kind() == model.TypeHOTP {
			extra = fmt.Sprintf("counter=%d", a.Counter)
		}
		pin := " "
		if a.Pinned {
			pin = "*"
		}
		tags := ""
		if len(a.Tags) > 0 {
			tags = "  [" + strings.Join(a.Tags, ",") + "]"
		}
		fmt.Printf("%s %-32s  %-5s  %-6s  %d digits  %s%s\n",
			pin, a.Label(), strings.ToUpper(string(a.Kind())), a.Algo, a.Digits, extra, tags)
	}
	return nil
}

func cmdAdd(f *flags, path string, args []string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()

	var accounts []model.Account
	switch {
	case len(args) == 1:
		accounts, err = controller.ResolveImport(args[0])
		if err != nil {
			return err
		}
	case len(args) == 0 && f.secret != "":
		acc, err := accountFromFlags(f)
		if err != nil {
			return err
		}
		accounts = []model.Account{acc}
	default:
		return errors.New("usage: tpduck add <uri|file|image.png>   or   tpduck add -secret S -name N [-issuer I ...]")
	}

	var ids []string
	for _, acc := range accounts {
		acc.ID = store.UniqueID(model.MakeID(acc), -1)
		store.Accounts = append(store.Accounts, acc)
		ids = append(ids, acc.ID)
	}
	if len(ids) == 0 {
		return errors.New("nothing to add")
	}
	// Report only after the write lands: saying "added" and then failing to
	// save tells the user two contradictory things.
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Println("added", id)
	}
	return nil
}

func accountFromFlags(f *flags) (model.Account, error) {
	kind := model.OTPType(strings.ToLower(f.otpType))
	switch kind {
	case model.TypeTOTP, model.TypeHOTP, model.TypeSteam:
	default:
		return model.Account{}, fmt.Errorf("type must be totp, hotp or steam, got %q", f.otpType)
	}
	acc := model.Account{
		Issuer:  strings.TrimSpace(f.issuer),
		Name:    strings.TrimSpace(f.name),
		Secret:  model.NormalizeSecret(f.secret),
		Digits:  f.digits,
		Period:  f.period,
		Algo:    model.Algo(strings.ToUpper(f.algo)),
		Type:    kind,
		Counter: f.counter,
		Notes:   f.notes,
		AddedAt: time.Now().Unix(),
	}
	if strings.TrimSpace(f.tags) != "" {
		for _, t := range strings.Split(f.tags, ",") {
			if t = strings.TrimSpace(t); t != "" {
				acc.Tags = append(acc.Tags, t)
			}
		}
	}
	if acc.Name == "" {
		return acc, errors.New("-name is required")
	}
	if err := acc.Validate(); err != nil {
		return acc, err
	}
	acc.ID = model.MakeID(acc)
	return acc, nil
}

func cmdRemove(f *flags, path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck rm <query>")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	ok, err := confirm(f.force, fmt.Sprintf("Delete %s?", acc.Label()))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "not deleted")
		return nil
	}
	i := store.FindIndexByID(acc.ID)
	store.Accounts = append(store.Accounts[:i], store.Accounts[i+1:]...)
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "deleted")
	return nil
}

func cmdPin(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck pin <query>")
	}
	store, key, err := openVault(nil, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	pinned, err := store.TogglePinned(acc.ID)
	if err != nil {
		return err
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	state := "unpinned"
	if pinned {
		state = "pinned"
	}
	fmt.Printf("%s %s\n", acc.Label(), state)
	return nil
}

func cmdOrder(path string, args []string) error {
	store, key, err := openVault(nil, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	if len(args) == 0 {
		order := store.Order
		if order == "" {
			order = model.SortByIssuer
		}
		fmt.Println(order)
		return nil
	}
	switch model.SortOrder(args[0]) {
	case model.SortByIssuer:
		store.Order = model.SortByIssuer
	case model.SortByUsed:
		store.Order = model.SortByUsed
	default:
		return fmt.Errorf("order must be %q or %q", model.SortByIssuer, model.SortByUsed)
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	fmt.Println(store.Order)
	return nil
}

// --- moving accounts in and out ---

func selectAccounts(store *model.Store, args []string) ([]model.Account, error) {
	store.Sort()
	if len(args) == 0 {
		return store.Accounts, nil
	}
	acc, err := store.Find(args[0])
	if err != nil {
		return nil, err
	}
	return []model.Account{*acc}, nil
}

func cmdExport(f *flags, path string, args []string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	accounts, err := selectAccounts(store, args)
	if err != nil {
		return err
	}
	data, err := model.RenderBackup(accounts, model.BackupFormat(f.format))
	if err != nil {
		return err
	}
	os.Stdout.Write(data)
	return nil
}

func cmdQR(path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck qr <query>")
	}
	store, key, err := openVault(nil, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	acc, err := store.Find(args[0])
	if err != nil {
		return err
	}
	out, err := model.QRANSI(acc.URI())
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s -- this QR contains the secret\n", acc.Label())
	fmt.Print(out)
	return nil
}

func cmdMigrate(f *flags, path string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	store.Sort()
	uris, err := model.BuildMigrationURIs(store.Accounts, f.batch)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d account(s) in %d QR code(s); each contains secrets\n", len(store.Accounts), len(uris))
	for i, u := range uris {
		fmt.Fprintf(os.Stderr, "\n--- batch %d of %d ---\n", i+1, len(uris))
		out, err := model.QRANSI(u)
		if err != nil {
			return err
		}
		fmt.Print(out)
	}
	return nil
}

func cmdBackup(f *flags, path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck backup [-format uri|aegis|andotp] [-encrypt] <file>")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	store.Sort()
	if len(store.Accounts) == 0 {
		return errors.New("vault is empty")
	}
	data, err := model.RenderBackup(store.Accounts, model.BackupFormat(f.format))
	if err != nil {
		return err
	}
	note := "this file contains secrets in plaintext"
	if f.encrypted {
		pass, err := readPassphrase("Backup passphrase: ")
		if err != nil {
			return err
		}
		if pass == "" {
			return errors.New("passphrase is empty")
		}
		if _, isEnv := os.LookupEnv("TPDUCK_PASSPHRASE"); !isEnv {
			again, err := readPassphrase("Confirm passphrase: ")
			if err != nil {
				return err
			}
			if !model.ConstantTimeEqualString(pass, again) {
				return errors.New("passphrases do not match")
			}
		}
		if data, err = model.Encrypt(data, pass); err != nil {
			return err
		}
		note = "encrypted; there is no recovery if you forget the passphrase"
	}
	// 0600 regardless: an unencrypted backup holds every secret.
	if err := os.WriteFile(args[0], data, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %d account(s) to %s -- %s\n", len(store.Accounts), args[0], note)
	return nil
}

func cmdRestore(f *flags, path string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck restore <file>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	if model.IsEncrypted(data) {
		pass, err := readPassphrase("Backup passphrase: ")
		if err != nil {
			return err
		}
		if data, err = model.Decrypt(data, pass); err != nil {
			return err
		}
	}
	accounts, format, err := model.ParseBackup(data)
	if err != nil {
		return err
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	ok, err := confirm(f.force, fmt.Sprintf("Import %d account(s) from the %s backup?", len(accounts), format))
	if err != nil || !ok {
		fmt.Fprintln(os.Stderr, "not imported")
		return nil
	}
	var ids []string
	for _, acc := range accounts {
		acc.ID = store.UniqueID(model.MakeID(acc), -1)
		store.Accounts = append(store.Accounts, acc)
		ids = append(ids, acc.ID)
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Println("added", id)
	}
	return nil
}

// --- vault ---

func cmdEncrypt(f *flags, path string) error {
	encrypted, err := model.IsVaultEncrypted(path)
	if err != nil {
		return err
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	verb := "Set"
	if encrypted {
		verb = "New"
	}
	pass, err := readPassphrase(verb + " passphrase: ")
	if err != nil {
		return err
	}
	if pass == "" {
		return errors.New("passphrase is empty (use `tpduck decrypt` to remove encryption)")
	}
	if _, isEnv := os.LookupEnv("TPDUCK_PASSPHRASE"); !isEnv {
		again, err := readPassphrase("Confirm passphrase: ")
		if err != nil {
			return err
		}
		if !model.ConstantTimeEqualString(pass, again) {
			return errors.New("passphrases do not match")
		}
	}
	newKey, err := model.NewKey(pass)
	if err != nil {
		return err
	}
	defer newKey.Zero()
	if err := store.SaveWithKey(path, newKey); err != nil {
		return err
	}
	// Any stored passphrase is stale now.
	_ = keyring.Delete(path)
	fmt.Fprintln(os.Stderr, "vault encrypted:", path)
	if f.useKeyring {
		if err := keyring.Set(path, pass); err != nil {
			fmt.Fprintln(os.Stderr, "keyring:", err)
		} else {
			fmt.Fprintln(os.Stderr, "passphrase stored in the OS keyring")
		}
	}
	return nil
}

func cmdDecrypt(f *flags, path string) error {
	encrypted, err := model.IsVaultEncrypted(path)
	if err != nil {
		return err
	}
	if !encrypted {
		return errors.New("vault is already stored in plaintext")
	}
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	if err := store.SaveWithKey(path, nil); err != nil {
		return err
	}
	_ = keyring.Delete(path)
	fmt.Fprintln(os.Stderr, "WARNING: secrets are now stored in plaintext at", path)
	return nil
}

func cmdKeyring(path string, args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	switch action {
	case "status":
		if !keyring.Available() {
			fmt.Println("no OS keyring is reachable from this session")
			return nil
		}
		if _, err := keyring.Get(path); err != nil {
			fmt.Println("keyring available; no passphrase stored for this vault")
			return nil
		}
		fmt.Println("keyring available; a passphrase is stored for this vault")
		return nil
	case "set":
		encrypted, err := model.IsVaultEncrypted(path)
		if err != nil {
			return err
		}
		if !encrypted {
			return errors.New("vault is not encrypted; run `tpduck encrypt` first")
		}
		pass, err := readPassphrase("Passphrase: ")
		if err != nil {
			return err
		}
		// Refuse to store something that does not actually open the vault.
		if _, k, err := model.OpenVaultFile(path, pass); err != nil {
			return err
		} else {
			k.Zero()
		}
		if err := keyring.Set(path, pass); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "stored")
		return nil
	case "forget":
		if err := keyring.Delete(path); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "forgotten")
		return nil
	default:
		return fmt.Errorf("usage: tpduck keyring <status|set|forget>")
	}
}

func cmdOffset(f *flags, path string, args []string) error {
	store, key, err := openVault(f, path)
	if err != nil {
		return err
	}
	defer key.Zero()
	if len(args) == 0 {
		fmt.Printf("%+d\n", store.TimeOffsetSeconds)
		return nil
	}
	switch args[0] {
	case "none", "0":
		store.TimeOffsetSeconds = 0
	case "auto":
		skew, err := model.ClockSkew(f.ntp, 5*time.Second)
		if err != nil {
			return err
		}
		// Local clock is `skew` ahead of real time, so codes need that removed.
		store.TimeOffsetSeconds = -int64(skew.Round(time.Second).Seconds())
	default:
		n, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			return fmt.Errorf("offset must be a number of seconds, \"auto\" or \"none\"")
		}
		store.TimeOffsetSeconds = n
	}
	if err := saveVault(store, path, key); err != nil {
		return err
	}
	fmt.Printf("%+d\n", store.TimeOffsetSeconds)
	if store.TimeOffsetSeconds != 0 {
		fmt.Fprintln(os.Stderr, "note: this masks a wrong system clock rather than fixing it")
	}
	return nil
}

func cmdSkew(f *flags, path string) error {
	period := model.DefaultPeriod
	// Reading the vault is optional here: the clock check is useful even when
	// the vault is locked, so a failure to open it is not fatal.
	if store, key, err := openVault(f, path); err == nil {
		for _, a := range store.Accounts {
			if a.Kind() == model.TypeTOTP && a.Period > 0 && a.Period < period {
				period = a.Period
			}
		}
		key.Zero()
	}
	skew, err := model.ClockSkew(f.ntp, 5*time.Second)
	if err != nil {
		return err
	}
	text, bad := model.SkewVerdict(skew, period)
	fmt.Println(text)
	if bad {
		os.Exit(1)
	}
	return nil
}
