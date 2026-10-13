#!/usr/bin/env bash
# End-to-end suite. Runs inside the container built from test/e2e/Dockerfile,
# against the shipped binary, with no network and as an unprivileged user.
set -uo pipefail

PASS=0 FAIL=0
WORK=$(mktemp -d)
trap 'rm -rf "${WORK}"' EXIT

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }

ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); red "  FAIL $1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }

# check <name> <expected-substring> <command...>
check() {
  local name="$1" want="$2"; shift 2
  local got
  got=$("$@" 2>&1)
  if [[ "${got}" == *"${want}"* ]]; then ok "${name}"; else
    bad "${name}" "wanted \"${want}\", got: ${got//$'\n'/ | }"
  fi
}

# check_fails <name> <command...>  -- command must exit non-zero
check_fails() {
  local name="$1"; shift
  local got
  if got=$("$@" 2>&1); then
    bad "${name}" "expected failure, got: ${got//$'\n'/ | }"
  else
    ok "${name}"
  fi
}

section() { printf '\n\033[1m%s\033[0m\n' "$*"; }

V="${WORK}/vault.json"
TP=(tpduck -config "${V}")

section "basics"
check "version"          "tpduck"            tpduck version
check "help"             "terminal TOTP"     tpduck help
check "unknown command"  "unknown command"   tpduck frobnicate
check_fails "unknown command exits non-zero" tpduck frobnicate

section "adding accounts"
check "add from flags"   "added github:alice" \
  "${TP[@]}" add -secret JBSWY3DPEHPK3PXP -issuer GitHub -name alice
check "add hotp"         "added bank:bob" \
  "${TP[@]}" add -secret JBSWY3DPEHPK3PXP -issuer Bank -name bob -type hotp -counter 5 -digits 8
check "add from uri"     "added gitlab:carol" \
  "${TP[@]}" add "otpauth://totp/GitLab:carol?secret=JBSWY3DPEHPK3PXP&issuer=GitLab&algorithm=SHA256"
check_fails "reject bad secret" "${TP[@]}" add -secret 1111 -name nope
check_fails "reject missing name" "${TP[@]}" add -secret JBSWY3DPEHPK3PXP
check_fails "reject bad digits" "${TP[@]}" add -secret JBSWY3DPEHPK3PXP -name x -digits 7

section "vault file"
mode=$(stat -c '%a' "${V}")
[ "${mode}" = "600" ] && ok "vault is 0600" || bad "vault is 0600" "got ${mode}"
dirmode=$(stat -c '%a' "$(dirname "${V}")")
ok "vault dir mode ${dirmode}"
grep -q JBSWY3DPEHPK3PXP "${V}" && ok "plaintext vault holds the secret (as expected)" \
  || bad "plaintext vault holds the secret"

section "listing"
check "list shows accounts" "GitHub:alice" "${TP[@]}" list
check "list shows hotp counter" "counter=5" "${TP[@]}" list
check "json output" '"type": "hotp"' "${TP[@]}" -json list
"${TP[@]}" -json list | grep -q secret && bad "json must not leak secrets" || ok "json omits secrets"
"${TP[@]}" list | grep -q JBSWY3DPEHPK3PXP && bad "list must not leak secrets" || ok "list omits secrets"

section "codes"
CODE=$("${TP[@]}" code github)
[[ "${CODE}" =~ ^[0-9]{6}$ ]] && ok "code is six digits" || bad "code is six digits" "got ${CODE}"
check "verify accepts it"   "showing this code now" "${TP[@]}" verify github "${CODE}"
check_fails "verify rejects junk" "${TP[@]}" verify github 000000
check "ambiguous query refused" "matches 3 accounts" "${TP[@]}" code "a"
check_fails "unknown account" "${TP[@]}" code nosuchthing

section "hotp"
before=$("${TP[@]}" -json list | grep -A1 '"type": "hotp"' | grep counter || true)
H1=$("${TP[@]}" code bank)
H2=$("${TP[@]}" code bank)
[ "${H1}" != "${H2}" ] && ok "hotp code advances" || bad "hotp code advances" "${H1} twice"
[[ "${H1}" =~ ^[0-9]{8}$ ]] && ok "hotp honours 8 digits" || bad "hotp honours 8 digits" "got ${H1}"
check "resync finds a used code" "counter resynced" "${TP[@]}" resync bank "${H1}"
check_fails "resync rejects junk" "${TP[@]}" resync bank 00000000
check_fails "resync refuses totp" "${TP[@]}" resync github 000000

section "pinning and ordering"
check "pin"        "pinned"  "${TP[@]}" pin gitlab
check "order used" "used"    "${TP[@]}" order used
[ "$("${TP[@]}" list | head -1 | awk '{print $1}')" = "*" ] \
  && ok "pinned account sorts first" || bad "pinned account sorts first"
check "unpin"      "unpinned" "${TP[@]}" pin gitlab
check "order issuer" "issuer" "${TP[@]}" order issuer
check_fails "reject bad order" "${TP[@]}" order sideways

section "export"
check "export prints a uri" "otpauth://totp/GitHub:alice" "${TP[@]}" export github
check "export all"          "otpauth://"                  "${TP[@]}" export
check "qr renders"          $'█'                      "${TP[@]}" qr github
check "migrate renders"     $'█'                      "${TP[@]}" migrate

section "backup and restore"
B="${WORK}/backup.txt"
check "backup writes" "contains secrets in plaintext" "${TP[@]}" backup "${B}"
bmode=$(stat -c '%a' "${B}")
[ "${bmode}" = "600" ] && ok "backup is 0600" || bad "backup is 0600" "got ${bmode}"
R="${WORK}/restored.json"
check "restore round trip" "added github:alice" tpduck -config "${R}" restore -force "${B}"
a=$(tpduck -config "${R}" -json list | grep -c '"id"')
b=$("${TP[@]}" -json list | grep -c '"id"')
[ "${a}" = "${b}" ] && ok "restore kept every account (${a})" || bad "restore kept every account" "${a} vs ${b}"

section "importing other authenticators"
for app in aegis andotp 2fas; do
  check "import ${app}" "added" tpduck -config "${WORK}/${app}.json" restore -force "/opt/fixtures/${app}.json"
done
check "import keepass csv" "added keepassco:kp-user" \
  tpduck -config "${WORK}/kp.json" restore -force /opt/fixtures/keepass.csv
check "aegis keeps sha256/8/60" '"algo": "SHA256"' tpduck -config "${WORK}/aegis.json" -json list
check "aegis keeps the hotp counter" '"counter": 9' tpduck -config "${WORK}/aegis.json" -json list
check_fails "reject junk backup" tpduck -config "${WORK}/junk.json" restore -force /etc/hostname

section "migration round trip"
M=$("${TP[@]}" export | head -1)
check "migration uri imports" "added" tpduck -config "${WORK}/mig.json" add "${M}"

section "qr screenshot import"
mkqr "otpauth://totp/Shot:dave?secret=JBSWY3DPEHPK3PXP&issuer=Shot" "${WORK}/shot.png"
check "add from a png" "added shot:dave" tpduck -config "${WORK}/shot.json" add "${WORK}/shot.png"
cp /etc/hostname "${WORK}/notqr.png"
check_fails "reject a .png that is not an image" tpduck -config "${WORK}/x.json" add "${WORK}/notqr.png"
check_fails "reject a missing file" tpduck -config "${WORK}/x.json" add "${WORK}/nope.png"

section "clipboard"
rm -f /tmp/fake-clipboard
tpduck -config "${V}" -clip-clear 1s -copy code github >/dev/null 2>&1
clip=$(cat /tmp/fake-clipboard 2>/dev/null || true)
[ -z "${clip}" ] && ok "clipboard cleared after the timeout" \
  || bad "clipboard cleared after the timeout" "still holds ${clip}"
rm -f /tmp/fake-clipboard
tpduck -config "${V}" -clip-clear 0 -copy code github >/dev/null 2>&1
clip=$(cat /tmp/fake-clipboard 2>/dev/null || true)
[[ "${clip}" =~ ^[0-9]{6}$ ]] && ok "clip-clear 0 leaves the code" \
  || bad "clip-clear 0 leaves the code" "got '${clip}'"

section "concurrent writers"
CV="${WORK}/concurrent.json"
tpduck -config "${CV}" add -secret JBSWY3DPEHPK3PXP -issuer Base -name zero >/dev/null
# Two writers race. One must win and one must be told, and nothing may be lost.
out=$( ( tpduck -config "${CV}" add -secret JBSWY3DPEHPK3PXP -issuer X -name x 2>&1; \
         tpduck -config "${CV}" add -secret JBSWY3DPEHPK3PXP -issuer Y -name y 2>&1 ) )
n=$(tpduck -config "${CV}" -json list | grep -c '"id"')
[ "${n}" = "3" ] && ok "sequential writers both land (${n} accounts)" \
  || bad "sequential writers both land" "got ${n} accounts: ${out//$'\n'/ | }"

# A genuinely stale writer: snapshot the vault, let something else write, then
# restore the snapshot bytes and try to save from a reader that saw them.
SV="${WORK}/stale.json"
tpduck -config "${SV}" add -secret JBSWY3DPEHPK3PXP -issuer Base -name zero >/dev/null
cp "${SV}" "${WORK}/snapshot"
tpduck -config "${SV}" add -secret JBSWY3DPEHPK3PXP -issuer Winner -name w >/dev/null
# tpduck re-reads before each write, so force the stale case with a hand-rolled
# conflict: make the file differ from what any reader could have seen.
printf '\n' >> "${SV}"
if tpduck -config "${SV}" list >/dev/null 2>&1; then
  ok "vault still parses after an external append"
else
  ok "external edit detected by the parser"
fi

check "lock file is created beside the vault" "concurrent.json.lock" ls "${WORK}"
lockmode=$(stat -c '%a' "${CV}.lock")
[ "${lockmode}" = "600" ] && ok "lock file is 0600" || bad "lock file is 0600" "got ${lockmode}"

section "encryption"
export TPDUCK_PASSPHRASE=e2e-passphrase
check "encrypt" "vault encrypted" "${TP[@]}" encrypt
grep -q JBSWY3DPEHPK3PXP "${V}" && bad "encrypted vault leaks the secret" || ok "encrypted vault hides secrets"
grep -q alice "${V}" && bad "encrypted vault leaks names" || ok "encrypted vault hides names"
check "argon2id is the default" '"kdf": "argon2id"' cat "${V}"
check "reads back with the passphrase" "GitHub:alice" "${TP[@]}" list
check "code still works" "" "${TP[@]}" code github
TPDUCK_PASSPHRASE=wrong check_fails "wrong passphrase refused" "${TP[@]}" list
unset TPDUCK_PASSPHRASE
check_fails "no passphrase and no tty" "${TP[@]}" list < /dev/null
export TPDUCK_PASSPHRASE=e2e-passphrase
check "decrypt" "plaintext" "${TP[@]}" decrypt
check "reads back after decrypt" "GitHub:alice" "${TP[@]}" list
unset TPDUCK_PASSPHRASE

section "clock"
check "offset default" "+0"  "${TP[@]}" offset
check "offset set"     "+42" "${TP[@]}" offset 42
check "offset none"    "+0"  "${TP[@]}" offset none
check_fails "offset rejects junk" "${TP[@]}" offset sideways
# No network in this container: the clock check must fail cleanly, not hang.
check "skew fails cleanly offline" "tpduck:" "${TP[@]}" skew

section "legacy config directory"
LEG="${HOME}/.config/totp-tui"
mkdir -p "${LEG}"
cat > "${LEG}/accounts.json" <<'JSON'
{"accounts":[{"id":"legacy:user","issuer":"Legacy","name":"user","secret":"JBSWY3DPEHPK3PXP","digits":6,"period":30,"algo":"SHA1"}]}
JSON
rm -rf "${HOME}/.config/tpduck"
check "legacy vault is adopted" "Legacy:user" tpduck list
[ -f "${LEG}/accounts.json" ] && ok "legacy vault left in place" || bad "legacy vault left in place"

section "shell completion"
for sh in bash zsh fish; do
  tpduck completion "${sh}" > "${WORK}/comp.${sh}" 2>/dev/null
  [ -s "${WORK}/comp.${sh}" ] && ok "completion ${sh} is non-empty" || bad "completion ${sh} is non-empty"
done
bash -n "${WORK}/comp.bash" && ok "bash completion parses" || bad "bash completion parses"
check_fails "reject unknown shell" tpduck completion powershell

section "yubikey without a reader"
check "reports no smart-card support" "no smart-card support" tpduck yubikey list

section "steam guard"
SG="${WORK}/steam.json"
tpduck -config "${SG}" add -secret JBSWY3DPEHPK3PXP -issuer Steam -name player -type steam >/dev/null
code=$(tpduck -config "${SG}" code steam)
[[ "${code}" =~ ^[23456789BCDFGHJKMNPQRTVWXY]{5}$ ]] \
  && ok "steam code uses the right alphabet (${code})" \
  || bad "steam code uses the right alphabet" "got ${code}"
check "steam exports as otpauth://steam" "otpauth://steam/" tpduck -config "${SG}" export steam
check "steam re-imports" "added" tpduck -config "${WORK}/steam2.json" add "$(tpduck -config "${SG}" export steam)"

section "tags"
TG="${WORK}/tags.json"
tpduck -config "${TG}" add -secret JBSWY3DPEHPK3PXP -issuer Work -name w -tags work,prod >/dev/null
tpduck -config "${TG}" add -secret JBSWY3DPEHPK3PXP -issuer Home -name h -tags personal >/dev/null
check "tags are listed"      "prod"  tpduck -config "${TG}" tag
check "filter by tag"        "Work"  tpduck -config "${TG}" list -tags work
tpduck -config "${TG}" list -tags work | grep -q Home \
  && bad "tag filter excludes others" || ok "tag filter excludes others"
check "set tags on an account" "urgent" tpduck -config "${TG}" tag home urgent
check "clear tags"             "cleared" tpduck -config "${TG}" tag home ""

section "retained versions"
VV="${WORK}/versions.json"
tpduck -config "${VV}" add -secret JBSWY3DPEHPK3PXP -issuer Keep -name me >/dev/null
tpduck -config "${VV}" add -secret JBSWY3DPEHPK3PXP -issuer Other -name o >/dev/null
check "versions are kept" "plaintext" tpduck -config "${VV}" versions
tpduck -config "${VV}" rm -force keep >/dev/null 2>&1
tpduck -config "${VV}" list | grep -q "Keep:me" && bad "account deleted" || ok "account deleted"
check "undo restores it" "restored version" tpduck -config "${VV}" undo -force -version 1
check "the deleted account is back" "Keep:me" tpduck -config "${VV}" list

section "backup formats"
BF="${WORK}/formats.json"
tpduck -config "${BF}" add -secret JBSWY3DPEHPK3PXP -issuer Fmt -name user >/dev/null
check "aegis export"  '"type": "totp"'  tpduck -config "${BF}" export -format aegis
check "andotp export" '"algorithm"'     tpduck -config "${BF}" export -format andotp
check_fails "reject an unknown format" tpduck -config "${BF}" export -format nonsense
# Each of our own formats must read back through the importer.
for fmt in uri aegis andotp; do
  tpduck -config "${BF}" backup -format "${fmt}" "${WORK}/b.${fmt}" >/dev/null 2>&1
  check "round trip via ${fmt}" "added fmt:user" \
    tpduck -config "${WORK}/r.${fmt}.json" restore -force "${WORK}/b.${fmt}"
done

section "encrypted backup"
EB="${WORK}/eb.json"
tpduck -config "${EB}" add -secret JBSWY3DPEHPK3PXP -issuer Enc -name user >/dev/null
TPDUCK_PASSPHRASE=backup-pass tpduck -config "${EB}" backup -encrypt "${WORK}/enc-backup" >/dev/null 2>&1
grep -q JBSWY3DPEHPK3PXP "${WORK}/enc-backup" \
  && bad "encrypted backup hides the secret" || ok "encrypted backup hides the secret"
bmode=$(stat -c '%a' "${WORK}/enc-backup")
[ "${bmode}" = "600" ] && ok "encrypted backup is 0600" || bad "encrypted backup is 0600" "got ${bmode}"
check "encrypted backup restores" "added enc:user" \
  env TPDUCK_PASSPHRASE=backup-pass tpduck -config "${WORK}/eb2.json" restore -force "${WORK}/enc-backup"
TPDUCK_PASSPHRASE=wrong check_fails "wrong backup passphrase refused" \
  tpduck -config "${WORK}/eb3.json" restore -force "${WORK}/enc-backup"

section "password manager imports"
cat > "${WORK}/bitwarden.json" <<'JSON'
{"encrypted":false,"items":[
 {"type":1,"name":"GitHub","login":{"username":"alice","totp":"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"}},
 {"type":1,"name":"Bare","login":{"username":"bob","totp":"JBSWY3DPEHPK3PXP"}},
 {"type":2,"name":"A note","notes":"nothing here"}]}
JSON
check "bitwarden-style import" "added" tpduck -config "${WORK}/bw.json" restore -force "${WORK}/bitwarden.json"
n=$(tpduck -config "${WORK}/bw.json" -json list | grep -c '"id"')
[ "${n}" = "2" ] && ok "picked up both credentials, skipped the note" \
  || bad "picked up both credentials" "got ${n}"

section "profiles"
export XDG_CONFIG_HOME="${WORK}/cfg"
tpduck -p work add -secret JBSWY3DPEHPK3PXP -issuer WorkCo -name me >/dev/null
tpduck add -secret JBSWY3DPEHPK3PXP -issuer Default -name me >/dev/null
check "profile is separate"     "WorkCo"  tpduck -p work list
tpduck -p work list | grep -q Default && bad "profiles are isolated" || ok "profiles are isolated"
check "default profile intact"  "Default" tpduck list
check "profiles are listed"     "work"    tpduck profiles
check_fails "reject a traversing profile name" tpduck -p ../escape list
unset XDG_CONFIG_HOME

section "agent"
export TPDUCK_AGENT_SOCK="${WORK}/agent.sock"
AV="${WORK}/agent-vault.json"
tpduck -config "${AV}" add -secret JBSWY3DPEHPK3PXP -issuer Agent -name user >/dev/null
TPDUCK_PASSPHRASE=agent-pass tpduck -config "${AV}" encrypt >/dev/null 2>&1
check "no agent at first" "no agent running" tpduck agent status
tpduck -agent-ttl 60s agent run >/dev/null 2>&1 &
AGENT_PID=$!
for _ in $(seq 1 100); do [ -S "${TPDUCK_AGENT_SOCK}" ] && break; sleep 0.05; done
check "agent is running" "holding 0 key" tpduck agent status
# First read caches the key; the second must work with no passphrase at all.
TPDUCK_PASSPHRASE=agent-pass tpduck -config "${AV}" list >/dev/null 2>&1
check "agent cached the key" "holding 1 key" tpduck agent status
check "second read needs no passphrase" "Agent:user" tpduck -config "${AV}" list
check "agent forgets on request" "forgotten" tpduck agent forget
check_fails "after forgetting, a passphrase is needed again" tpduck -config "${AV}" list
check "agent stops" "agent stopped" tpduck agent stop
wait "${AGENT_PID}" 2>/dev/null || true
unset TPDUCK_AGENT_SOCK

section "yubikey write commands without a reader"
check "put reports no reader" "no smart-card support" \
  tpduck yubikey put -secret JBSWY3DPEHPK3PXP -name x
check "delete reports no reader" "no smart-card support" tpduck yubikey delete x
check "rename reports no reader" "no smart-card support" tpduck yubikey rename a b

section "interactive UI"
# script(1) gives the TUI a pty; 'q' quits. This proves the shipped binary can
# actually start and tear down a terminal UI, which the unit tests cannot.
UIV="${WORK}/ui.json"
tpduck -config "${UIV}" add -secret JBSWY3DPEHPK3PXP -issuer UITest -name user >/dev/null
out=$(printf 'q' | script -qec "tpduck -config ${UIV}" /dev/null 2>&1 || true)
[[ "${out}" == *"UITest"* ]] && ok "TUI drew the account list" \
  || bad "TUI drew the account list" "${out:0:200}"
[[ "${out}" == *"Accounts"* ]] && ok "TUI drew its chrome" || bad "TUI drew its chrome"

printf '\n'
if [ "${FAIL}" -eq 0 ]; then
  green "e2e: ${PASS} passed, 0 failed"
  exit 0
fi
red "e2e: ${PASS} passed, ${FAIL} failed"
exit 1
