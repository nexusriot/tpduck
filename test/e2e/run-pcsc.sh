#!/usr/bin/env bash
# Smart-card end-to-end suite: a tpduck built with -tags pcsc, talking to a
# virtual YubiKey through libpcsclite, pcscd and vpcd.
set -uo pipefail

PASS=0 FAIL=0
WORK=$(mktemp -d)

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
section() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); red "  FAIL $1"; [ -n "${2:-}" ] && printf '       %s\n' "$2"; }

check() {
  local name="$1" want="$2"; shift 2
  local got
  got=$("$@" 2>&1)
  if [[ "${got}" == *"${want}"* ]]; then ok "${name}"; else
    bad "${name}" "wanted \"${want}\", got: ${got//$'\n'/ | }"
  fi
}

check_fails() {
  local name="$1"; shift
  local got
  if got=$("$@" 2>&1); then
    bad "${name}" "expected failure, got: ${got//$'\n'/ | }"
  else
    ok "${name}"
  fi
}

VICC_PID=""
PCSCD_PID=""
cleanup() {
  [ -n "${VICC_PID}" ] && kill "${VICC_PID}" 2>/dev/null
  [ -n "${PCSCD_PID}" ] && kill "${PCSCD_PID}" 2>/dev/null
  rm -rf "${WORK}"
}
trap cleanup EXIT

SECRET=JBSWY3DPEHPK3PXP

# port_listening <hex port> -- vpcd listens on 0x8C7B once pcscd loads it.
port_listening() {
  grep -qi ":$1 .* 0A " /proc/net/tcp 2>/dev/null
}

# transport_up -- true once tpduck can reach a reader at all. Authentication
# errors still count: the PC/SC chain is what we are waiting for.
transport_up() {
  local out
  out=$(tpduck yubikey list 2>&1)
  [[ "${out}" != *"pcsc:"* ]]
}

wait_until() {
  local what="$1" tries="$2"; shift 2
  for _ in $(seq 1 "${tries}"); do
    if "$@"; then return 0; fi
    sleep 0.1
  done
  bad "${what}" "timed out"
  return 1
}

# start_card <extra vicc args...> -- (re)start pcscd and the virtual YubiKey.
start_card() {
  [ -n "${VICC_PID}" ] && { kill "${VICC_PID}" 2>/dev/null; wait "${VICC_PID}" 2>/dev/null; VICC_PID=""; }
  [ -n "${PCSCD_PID}" ] && { kill "${PCSCD_PID}" 2>/dev/null; wait "${PCSCD_PID}" 2>/dev/null; PCSCD_PID=""; }
  rm -rf /run/pcscd
  mkdir -p /run/pcscd

  pcscd --foreground --error >"${WORK}/pcscd.log" 2>&1 &
  PCSCD_PID=$!
  wait_until "vpcd started listening" 100 port_listening 8C7B || return 1

  vicc "$@" >"${WORK}/vicc.log" 2>&1 &
  VICC_PID=$!
  wait_until "the virtual card attached" 150 transport_up || return 1
}

section "environment"
check "tpduck has smart-card support" "tpduck" tpduck version
tpduck yubikey list 2>&1 | grep -q "no smart-card support" \
  && bad "this build has smart-card support" "it was built without -tags pcsc" \
  || ok "this build has smart-card support"
check "no reader before the card attaches" "pcsc" tpduck yubikey list

section "a virtual YubiKey appears"
start_card -credentials "30/GitHub:alice=${SECRET},Bank:bob=${SECRET}:8:SHA256:hotp,60/Touchy:carol=${SECRET}" -touch "60/Touchy:carol"
check "list reaches the key"    "GitHub:alice"   tpduck yubikey list
check "list shows the applet version" "OATH 5.4.3" tpduck yubikey list
check "hotp credential listed"  "HOTP"           tpduck yubikey list
check "sha256 reported"         "SHA256"         tpduck yubikey list
check "touch credential flagged" "(touch)"       tpduck yubikey list

section "codes come off the card"
code=$(tpduck yubikey code "30/GitHub:alice" 2>/dev/null)
[[ "${code}" =~ ^[0-9]{6}$ ]] && ok "code is six digits (${code})" \
  || bad "code is six digits" "got '${code}'"
# The code must be the one the secret implies, not just well-formed.
want=$(tpduck -config "${WORK}/ref.json" add -secret "${SECRET}" -issuer GitHub -name alice >/dev/null 2>&1; \
       tpduck -config "${WORK}/ref.json" code github 2>/dev/null)
[ "${code}" = "${want}" ] && ok "card code matches the same secret computed locally" \
  || bad "card code matches locally" "card=${code} local=${want}"
check_fails "unknown credential refused" tpduck yubikey code no-such-thing
check "touch credential asks for a touch" "touch" tpduck yubikey code "60/Touchy:carol"

section "writing to the key"
check "put stores a credential" "stored" \
  tpduck yubikey put -secret "${SECRET}" -issuer Acme -name dave
check "the new credential is listed" "Acme:dave" tpduck yubikey list
newcode=$(tpduck yubikey code "Acme:dave" 2>/dev/null)
[[ "${newcode}" =~ ^[0-9]{6}$ ]] && ok "the stored credential produces a code" \
  || bad "the stored credential produces a code" "got '${newcode}'"

check "put with a period prefixes the name" "stored 60/Acme:eve" \
  tpduck yubikey put -secret "${SECRET}" -issuer Acme -name eve -period 60
check "rename" "renamed" tpduck yubikey rename "Acme:dave" "Acme:dave2"
check "the renamed credential is listed" "Acme:dave2" tpduck yubikey list
check "delete" "deleted" tpduck yubikey delete -force "Acme:dave2"
tpduck yubikey list 2>&1 | grep -q "Acme:dave2" \
  && bad "deleted credential is gone" || ok "deleted credential is gone"
check_fails "delete a credential that is not there" tpduck yubikey delete -force nope
check_fails "put rejects a bad secret" tpduck yubikey put -secret 1111 -name x

section "a password-protected applet"
start_card -credentials "30/GitHub:alice=${SECRET}" -password "s3cret"
check_fails "locked applet refuses without a password" tpduck yubikey list
check "the right password unlocks it" "GitHub:alice" \
  env TPDUCK_PASSPHRASE=s3cret tpduck yubikey list
check_fails "the wrong password is refused" \
  env TPDUCK_PASSPHRASE=nope tpduck yubikey list
check "codes work once unlocked" "" \
  env TPDUCK_PASSPHRASE=s3cret tpduck yubikey code "30/GitHub:alice"

section "the key going away"
kill "${VICC_PID}" 2>/dev/null; wait "${VICC_PID}" 2>/dev/null; VICC_PID=""
sleep 1
check_fails "unplugging the card is reported, not a crash" tpduck yubikey list

printf '\n'
if [ "${FAIL}" -eq 0 ]; then
  green "pcsc e2e: ${PASS} passed, 0 failed"
  exit 0
fi
red "pcsc e2e: ${PASS} passed, ${FAIL} failed"
echo "--- pcscd log ---"; tail -20 "${WORK}/pcscd.log" 2>/dev/null
echo "--- vicc log ---";  tail -20 "${WORK}/vicc.log" 2>/dev/null
exit 1
