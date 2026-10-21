# tpduck

A terminal authenticator for TOTP, HOTP and Steam Guard codes, written in Go.

![tpduck](tpduck.png)

- RFC 6238 (TOTP), RFC 4226 (HOTP) and Steam Guard, SHA-1/SHA-256/SHA-512
- Vault encrypted at rest with Argon2id + XChaCha20-Poly1305, locked when idle,
  optionally unlocked from the OS keyring
- Imports `otpauth://` URIs, Google Authenticator exports, Aegis, andOTP, 2FAS
  and KeePassXC backups, and QR codes out of a screenshot
- Exports the same ways, including batched migration QR codes
- Clipboard copies that clear themselves, and ask clipboard managers not to
  record them
- Verify a code, resynchronise an HOTP counter, check your clock
- Stores credentials on a YubiKey, moves an account onto one, and can seal the
  vault itself to a YubiKey so the file alone will not open
- Named profiles, tags, and an agent that keeps the vault open briefly
- Keeps the last few versions of the vault, so a deletion is recoverable
- Works as a TUI or as a plain CLI for scripts

## Install

Packages are built for Debian/Ubuntu and Fedora/RHEL:

```
sudo dpkg -i tpduck_0.4.0_amd64.deb      # or
sudo rpm -i tpduck-0.4.0-1.x86_64.rpm
```

With Go:

```
go install github.com/nexusriot/tpduck/cmd/tpduck@latest
```

From a checkout:

```
make build        # ./bin/tpduck
make install      # into /usr/local, with man page and completions
```

## Usage

Run `tpduck` with no arguments for the interactive UI. Press `?` for the key
list.

| Key | Action |
| --- | --- |
| `↑` `↓` | move between accounts; details follow the cursor |
| `/` | search issuer, name, notes and tags; `tag:work` filters by tag (`Enter` keeps the filter, `Esc` clears it) |
| `A` `E` `D` | add, edit, delete |
| `I` | import a URI, a backup file, or a QR screenshot |
| `X` | export the selected account (QR + `otpauth://` URI) |
| `N` | advance the counter of an HOTP account |
| `C` | copy the current code |
| `V` | verify a code a server showed you |
| `R` | reveal or hide the stored secret |
| `F` | pin or unpin an account |
| `O` | switch between alphabetical and most-recently-used ordering |
| `Y` | resynchronise an HOTP counter |
| `M` | export every account as migration QR codes |
| `P` | set, change or remove the vault passphrase |
| `L` | lock now |
| `K` | compare the system clock to network time |
| `?` | show the key list |
| `Q`, `Ctrl-Q` | quit |

`Enter` copies the highlighted code. The mouse works too.

### Command line

```
tpduck code <query>               print one code
tpduck code -peek <query>         print it without consuming it
tpduck verify <query> <code>      check a code a server showed you
tpduck resync <query> <code>      realign an HOTP counter
tpduck list [-json] [-tags a,b]   list accounts (never prints secrets)
tpduck add <uri|file|image.png>   import a URI, a backup, or a QR screenshot
tpduck add -secret S -name N ...  add an account from its parts
tpduck rm|pin <query>             delete, or pin to the top of the list
tpduck order issuer|used          set the list ordering
tpduck export [query]             print otpauth:// URIs (SECRETS)
tpduck qr <query>                 print a scannable QR code (SECRET)
tpduck migrate                    migration QR codes for every account
tpduck backup|restore <file>      move the whole vault in or out
tpduck versions | undo            list and restore retained copies
tpduck tag [<query> <tags>]       list tags, or set them on an account
tpduck profiles                   list named vaults (use with -p)
tpduck agent run|status|stop|forget   cache the key for a few minutes
tpduck encrypt | decrypt          add or remove the vault passphrase
tpduck encrypt -yubikey           seal the vault to a YubiKey as well
tpduck keyring status|set|forget  manage the stored passphrase
tpduck offset <seconds|auto|none> compensate for an unsyncable clock
tpduck skew                       compare the system clock to network time
tpduck yubikey list|code|put|delete|rename    credentials on a YubiKey
tpduck yubikey put <query>        move a vault account onto the key
tpduck yubikey password set|remove   protect the key's own credentials
tpduck yubikey reset              wipe every credential on the key
tpduck completion bash|zsh|fish   print a shell completion script
```

A query is an exact ID, an exact `Issuer:name` label, or any unique
case-insensitive substring. An ambiguous query is refused rather than guessed.

Flags: `-config <path>`, `-p <profile>`, `-idle-lock <dur>` (default `5m`),
`-clip-clear <dur>` (default `15s`), `-keyring`, `-agent`, `-agent-ttl <dur>`
(default `15m`), `-format <fmt>`, `-encrypt`, `-tags a,b`, `-window <n>`,
`-batch <n>`, `-version <n>`, `-ntp <host:port>`, `-reader <name>`, `-touch`,
`-copy`, `-json`, `-force`, `-peek`, `-yubikey`, `-slot <1|2>`, `-move`. `tpduck add` without a URI also takes `-secret`,
`-name`, `-issuer`, `-type`, `-algo`, `-digits`, `-period`, `-counter` and
`-notes`; run `tpduck help` for the full list.

### Keeping the vault open

An encrypted vault re-derives its key on every command, which costs about a
tenth of a second and a passphrase prompt. `tpduck agent run` keeps the derived
key in memory for 15 minutes so a sequence of commands does not re-ask. The
lifetime is absolute, as with `ssh-agent -t`; `tpduck agent forget` drops
everything immediately.

It listens on `$XDG_RUNTIME_DIR/tpduck-agent.sock`, mode 0600, or on a 0700
directory of its own under the temporary directory when there is no runtime
directory. `TPDUCK_AGENT_SOCK` overrides the location. Every command that opens
the vault uses a running agent unless you pass `-agent=false`.

### Profiles and tags

`tpduck -p work ...` uses a separate vault under `profiles/`; `tpduck profiles`
lists them. Accounts can carry tags, which `tpduck list -tags work` filters on
and the UI searches with `tag:work`.

### Moving in and out

`tpduck restore` sniffs the format, so the same command reads an Aegis export,
an andOTP or 2FAS JSON backup, a KeePassXC CSV, a list of `otpauth://` URIs, or
a Google Authenticator `otpauth-migration://` payload. Anything else that is
JSON is scanned for `otpauth://` URIs and `totp` fields, which covers Bitwarden,
1Password and most password-manager exports without a parser each. `tpduck add`
additionally accepts a path to a PNG, JPEG or GIF screenshot and reads the QR
code out of it.

`tpduck backup -format uri|aegis|andotp` writes the whole vault out, and
`-encrypt` seals it with its own passphrase so it is safe to put in cloud
storage.

Going the other way, `tpduck migrate` prints batched migration QR codes that
Google Authenticator's "Import accounts" reads directly. The migration format
has no Steam Guard, so Steam accounts are left out and named rather than
exported as a six-digit TOTP that would produce codes Steam rejects; use
`tpduck qr` for those.

### Reading a code without spending it

`tpduck code -peek <query>` prints the code and changes nothing: it does not
advance an HOTP counter, does not record the account as used, and does not
write the vault at all. That matters most for HOTP, where an ordinary read
burns a counter step you cannot get back, and it makes a polling script safe
against a vault something else is also writing.

## Where things are stored

The vault lives at `$XDG_CONFIG_HOME/tpduck/accounts.json` (or the platform
equivalent), written `0600` in a directory created `0700`. A vault left behind
by an older version under `totp-tui/` is copied across on first run; the
original is left in place.

Writes go to a temporary file and are renamed into position, so an interrupted
write cannot truncate an existing vault.

Saves are also guarded against lost updates. A store remembers what the file
held when it was read, and a write that would overwrite someone else's changes
-- another tpduck, or a sync tool -- is refused rather than silently winning.
The UI offers to keep your version or reload theirs; the CLI tells you nothing
was written and to re-run. An advisory lock (`accounts.json.lock`) makes the
check and the rename a single step on Unix.

## Encryption

By default the vault is **plaintext** — any process running as you can read
every secret. The UI says so in the Details panel until you set a passphrase
with `P` (or `tpduck encrypt`).

An encrypted vault is a JSON envelope: a random 16-byte salt, Argon2id
(64 MiB, 3 passes, 4 lanes) to derive a 32-byte key, and XChaCha20-Poly1305
with a random 24-byte nonce. The KDF parameters are authenticated, so they
cannot be downgraded without failing the tag; they are stored per vault and
range-checked on read, so a hostile file cannot ask for an absurd allocation.
Vaults written with scrypt by earlier versions still open, and are re-sealed
with Argon2id the next time the passphrase is set.

There is no recovery if you forget the passphrase.

Repeated wrong guesses in the UI are slowed down after the third attempt, on
top of the cost the KDF already imposes.

With `-keyring`, the passphrase can be kept in the OS secret store
(libsecret/D-Bus, Keychain, or Windows Credential Manager) and the vault opens
without asking. That is a deliberate trade: anything that can talk to your
secret service can read it back. It is off unless you ask for it, and it is
better than the alternative people actually pick, which is no encryption at
all. `tpduck keyring forget` removes it.

Locking (`L`, or `-idle-lock`) discards the decrypted accounts and zeroes the
derived key. Note that Go strings are immutable, so the secrets themselves
cannot be reliably scrubbed from memory; what locking guarantees is that the
key material is gone and the plaintext is no longer referenced.

Locking only means anything for an encrypted vault: there is no key to discard
otherwise, and the accounts are readable on disk regardless, so `L` and
`-idle-lock` do nothing until a passphrase is set.

For scripts, `TPDUCK_PASSPHRASE` is read instead of prompting. It exposes the
passphrase to anything that can read the process environment. A YubiKey's own
applet password is a separate secret and comes from `TPDUCK_YUBIKEY_PASSWORD`.

The vault can also be sealed to a YubiKey, so that the file plus the passphrase
is not enough on its own — see [YubiKey](#yubikey).

## The clipboard

A copied code is cleared after `-clip-clear` (15 seconds by default), and only
if the clipboard still holds what tpduck put there — overwriting something you
copied since would be worse than leaving a code behind.

Clearing is not enough on its own: a clipboard history manager has already
recorded the code by then, and keeps it long after tpduck has moved on. So the
copy is also marked as sensitive where the backend can say so:

| Backend | Marking |
| --- | --- |
| `wl-copy` (Wayland) | `--sensitive`, which becomes the `x-kde-passwordManagerHint` type that Klipper, cliphist and others look for. Needs wl-clipboard 2.3 or newer; older versions are detected and the copy goes through unmarked. |
| PowerShell (Windows) | `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` and `CanUploadToCloudClipboard`, which keep the code out of the Win+V history and out of cloud sync. |
| `xclip`, `xsel` (X11) | None. An X11 selection owner advertises one target at a time, so the hint cannot accompany the text. |
| `pbcopy` (macOS) | None. Setting `org.nspasteboard.ConcealedType` needs AppKit, and linking it would end the pure-Go cross-compile the release binaries depend on. |
| `clip.exe` (Windows) | None; it is the fallback for a machine without PowerShell. |

tpduck says which happened rather than letting you assume: the UI flashes
"copied (marked sensitive)" when the marking took, and `tpduck code -copy`
prints a note when it did not. Marking is a request, not a guarantee — a
clipboard manager is free to ignore it.

## Networking

tpduck never contacts the network on its own. The only outbound traffic is the
SNTP query made when you explicitly run `tpduck skew` or press `K`, which sends
a timestamp request and no account data.

## Recovering from a mistake

Whenever a write changes the vault's contents, the previous state is kept as
`accounts.json.1`, with five copies retained. `tpduck versions` lists them and
`tpduck undo` puts one back — including after a deletion, which is otherwise
unrecoverable. The restore is itself undoable.

"Changes the contents" means the accounts themselves: adding, editing or
deleting one, or changing a secret, a tag, a note or the pinning. Taking a code
also writes the vault, to record that the account was used and to advance an
HOTP counter, but that does not rotate the copies — otherwise an afternoon's
ordinary use would push the deletion you wanted to undo out of the history.

## YubiKey

`tpduck yubikey list` and `code` read OATH credentials from a YubiKey, and
`put`, `delete` and `rename` manage them, so a secret can live only on the key.
Password-protected applets are unlocked with the key's own challenge-response.

### Moving an account onto the key

`tpduck yubikey put <query>` takes the secret from the vault instead of making
you retype one it already holds. Nothing is removed until you ask:

```
tpduck yubikey put github           # copy it to the key, keep the vault's copy
tpduck yubikey put github -move     # and then delete the vault's copy
```

Before `-move` deletes anything, tpduck asks the key for a code and checks it
against the one it computes itself, so the credential is known to have landed
correctly. Counter-based accounts are the exception: asking a HOTP credential
for a code advances the key's counter, so they are not verified and `-move`
needs `-force`.

There is no way back. A credential on the key answers challenges but never
gives its secret up — that is the point of putting it there — so `tpduck` can
copy an account to the key and never from it. Steam Guard accounts cannot go on
the key at all: the OATH applet has no such type.

### The key's own password

`tpduck yubikey password set` protects the credentials stored on the key, so
somebody holding it cannot read codes off it. `remove` takes it off again, and
`tpduck yubikey reset` wipes the applet completely — every credential and the
password — which is the only way back into a key whose password was forgotten,
and destroys the only copy of each secret on it.

This password is a different secret from the vault passphrase and is read from
`TPDUCK_YUBIKEY_PASSWORD`, not `TPDUCK_PASSPHRASE`, so a script that supplies
one does not silently supply the other.

### Sealing the vault to the key

```
tpduck encrypt -yubikey            # passphrase AND key
tpduck encrypt -yubikey -slot 1    # using slot 1 instead of the default 2
```

The vault's key is then derived from the passphrase *and* an HMAC-SHA1
challenge-response from the YubiKey, so copying the file somewhere else does
not help: the slot's secret never leaves the key. Leave the passphrase empty
and the key becomes the only factor, which opens the vault with nothing typed.

The slot must already be programmed for challenge-response; tpduck deliberately
cannot program one, because writing a slot is destructive and belongs to
`ykman`:

```
ykman otp chalresp --touch 2       # --touch means the key must be touched
```

Opening a sealed vault needs no flag — the vault says it needs a key, and
tpduck asks for one. The derived key caches in the agent like any other, so
`tpduck agent run` means touching the key once rather than once per command.
Changing the passphrase keeps the binding; `tpduck decrypt` is how you remove
it.

**If the key is lost, the vault is gone.** Keep a `tpduck backup -encrypt`
somewhere safe before relying on this; a backup is sealed with its own
passphrase and never with the key, exactly so it survives losing one.

### Building with smart-card support

All of the above needs a build with smart-card support, which uses cgo and
links against libpcsclite:

```
./scripts/install-deps.sh --build    # libpcsclite-dev and a C toolchain
make build-pcsc                      # ./bin/tpduck-pcsc
make packages-pcsc                   # a tpduck-pcsc .deb/.rpm
```

`scripts/install-deps.sh` detects apt, dnf, yum, pacman, zypper or apk and
installs the right names; `--build` is the compile-time set, `--runtime` is
pcscd plus the clipboard helpers.

The default binaries are pure Go and have no smart-card support, so that they
cross-compile for the release packages; they say so when you ask for a key.
The `tpduck-pcsc` package declares `libpcsclite1` (or `pcsc-lite` on rpm) as a
hard dependency, because that build really does link it, and conflicts with
the plain `tpduck` package.

## Building and packaging

```
make build          # ./bin/tpduck for this machine
make build-pcsc     # ./bin/tpduck-pcsc, with YubiKey support (needs cgo)
make deps           # install the Linux build and runtime dependencies
make test           # unit and integration tests
make check          # gofmt check, go vet, tests under -race
make e2e            # end-to-end suite in a container, with no network
make e2e-pcsc       # end-to-end against a virtual YubiKey
make e2e-all        # both end-to-end suites
make dist           # cross-compiled tarballs + SHA256SUMS in ./dist
make packages       # .deb and .rpm in ./dist
make packages-pcsc  # tpduck-pcsc .deb and .rpm in ./dist/pcsc
make install        # into /usr/local, with man page and completions
make bump V=0.5.0   # set the version
```

The version lives in `internal/version/VERSION`, which the binary embeds, so
`go install` reports the same version the Makefile does. `tpduck version` also
prints the commit when the build was made inside a checkout.

`scripts/manifests.sh` renders the Homebrew formula, AUR `PKGBUILD` and Scoop
manifest from a built release, filling in the real checksums. CI runs the
checks, the cross-compile, the smart-card build, both end-to-end suites and the
package builds on every push, and fails if the `tpduck-pcsc` package stops
declaring `libpcsclite1`; tagging `v*` publishes the archives and packages.

`make packages` uses [nfpm](https://nfpm.goreleaser.com), which is pure Go, so
it needs neither root nor `dpkg`/`rpmbuild`. The packages install the binary,
the man page and completions for bash, zsh and fish.

## Tests

```
make check        # unit + integration, under the race detector
make e2e          # end-to-end, hermetic
make e2e-pcsc     # end-to-end against a virtual YubiKey
make e2e-all      # both
```

The unit and integration suite covers the RFC 6238 and RFC 4226 vectors, the
vault format (including tamper and KDF-downgrade attempts), every import and
export format, the YubiKey OATH protocol against a simulated card, and the TUI
itself driven against a simulated terminal.

The end-to-end suite builds a container, drops to an unprivileged user and runs
the shipped binary with `--network none` and a read-only root filesystem. It
checks file permissions, that encrypted vaults leak nothing, that the clipboard
really is cleared, that every importer reads a real fixture, and that the TUI
starts and exits on a pty.

The smart-card suite is separate because it needs a different build. It runs a
`-tags pcsc` binary against a *virtual* YubiKey: pcscd loads the vpcd driver,
a `vicc` process serves the simulated OATH and OTP applets over it, and tpduck
reaches it through the real libpcsclite. That is the only coverage the PC/SC
transport has, since the release binaries do not contain it. It covers moving
an account onto the key, the applet password and reset, and a vault sealed to
the key — including that a different key, or no key, does not open it. It needs
no hardware and no network.
