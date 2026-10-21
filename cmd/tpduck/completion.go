package main

import (
	"errors"
	"fmt"
	"os"
)

// Completion scripts call `tpduck list` and take the account label off each
// line, so labels can be completed without the shell ever seeing a secret.
//
// The label is the first field, except on a pinned account, whose line starts
// with a "*" marker -- awk does not count the leading blank of an unpinned
// line as a field, so a plain $2 would offer "TOTP" for everything unpinned.
const bashCompletion = `# tpduck bash completion
# install: tpduck completion bash > /etc/bash_completion.d/tpduck
_tpduck() {
  local cur prev cmds
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmds="code verify resync list add rm pin order tag export qr migrate backup restore versions undo encrypt decrypt keyring agent profiles offset skew yubikey completion version help"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    code|verify|resync|qr|export|rm|pin|tag)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$(tpduck list 2>/dev/null | awk '{print ($1 == "*") ? $2 : $1}')" -- "$cur") )
      fi
      ;;
    order)   COMPREPLY=( $(compgen -W "issuer used" -- "$cur") ) ;;
    keyring) COMPREPLY=( $(compgen -W "status set forget" -- "$cur") ) ;;
    agent)   COMPREPLY=( $(compgen -W "run status stop forget" -- "$cur") ) ;;
    offset)  COMPREPLY=( $(compgen -W "auto none" -- "$cur") ) ;;
    yubikey) COMPREPLY=( $(compgen -W "list code put delete rename password reset" -- "$cur") ) ;;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
    backup|restore|add) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
  esac
  case "$prev" in
    -config) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
    -slot)   COMPREPLY=( $(compgen -W "1 2" -- "$cur") ) ;;
    -format) COMPREPLY=( $(compgen -W "uri aegis andotp" -- "$cur") ) ;;
    put)     COMPREPLY=( $(compgen -W "$(tpduck list 2>/dev/null | awk '{print ($1 == "*") ? $2 : $1}')" -- "$cur") ) ;;
    password) COMPREPLY=( $(compgen -W "set remove" -- "$cur") ) ;;
  esac
}
complete -F _tpduck tpduck
`

const zshCompletion = `#compdef tpduck
# install: tpduck completion zsh > "${fpath[1]}/_tpduck"
_tpduck_accounts() {
  local -a accounts
  accounts=(${(f)"$(tpduck list 2>/dev/null | awk '{print ($1 == "*") ? $2 : $1}')"})
  compadd -a accounts
}
_tpduck() {
  local -a cmds
  cmds=(
    'code:print one code'
    'verify:check a code'
    'resync:realign an HOTP counter'
    'list:list accounts'
    'add:import a URI, backup or QR image'
    'rm:delete an account'
    'pin:pin or unpin an account'
    'order:set the list ordering'
    'tag:list tags, or set them on an account'
    'export:print otpauth URIs'
    'qr:print a QR code'
    'migrate:print migration QR codes'
    'backup:write every account to a file'
    'restore:import a backup'
    'versions:list retained copies of the vault'
    'undo:put a retained copy back'
    'encrypt:set a vault passphrase'
    'decrypt:remove the vault passphrase'
    'keyring:manage the stored passphrase'
    'agent:cache the derived key for a few minutes'
    'profiles:list the named vaults'
    'offset:compensate for a wrong clock'
    'skew:check the system clock'
    'yubikey:use a YubiKey'
    'completion:print a completion script'
    'version:print the version'
    'help:show help'
  )
  if (( CURRENT == 2 )); then
    _describe 'command' cmds
    return
  fi
  case "${words[2]}" in
    code|verify|resync|qr|export|rm|pin|tag) (( CURRENT == 3 )) && _tpduck_accounts ;;
    order)      compadd issuer used ;;
    keyring)    compadd status set forget ;;
    agent)      compadd run status stop forget ;;
    offset)     compadd auto none ;;
    yubikey)    compadd list code put delete rename password reset ;;
    completion) compadd bash zsh fish ;;
    backup|restore|add) _files ;;
  esac
  case "${words[CURRENT-1]}" in
    -slot)    compadd 1 2 ;;
    -format)  compadd uri aegis andotp ;;
    put)      _tpduck_accounts ;;
    password) compadd set remove ;;
  esac
}
_tpduck "$@"
`

const fishCompletion = `# tpduck fish completion
# install: tpduck completion fish > ~/.config/fish/completions/tpduck.fish
function __tpduck_accounts
    tpduck list 2>/dev/null | awk '{print ($1 == "*") ? $2 : $1}'
end
function __tpduck_no_cmd
    set -l t (commandline -opc)
    test (count $t) -eq 1
end
function __tpduck_cmd_is
    set -l t (commandline -opc)
    test (count $t) -ge 2 -a "$t[2]" = "$argv[1]"
end

complete -c tpduck -f
for pair in 'code:print one code' 'verify:check a code' 'resync:realign an HOTP counter' \
            'list:list accounts' 'add:import a URI, backup or QR image' 'rm:delete an account' \
            'pin:pin or unpin an account' 'order:set the list ordering' 'export:print otpauth URIs' \
            'qr:print a QR code' 'migrate:print migration QR codes' 'backup:write accounts to a file' \
            'restore:import a backup'
    'versions:list retained copies of the vault'
    'undo:put a retained copy back' 'encrypt:set a vault passphrase' 'decrypt:remove the passphrase' \
            'keyring:manage the stored passphrase'
    'agent:cache the derived key for a few minutes'
    'profiles:list the named vaults' 'offset:compensate for a wrong clock' \
            'skew:check the system clock' 'yubikey:use a YubiKey' 'completion:print a completion script' \
            'version:print the version' 'help:show help'
    set -l parts (string split -m1 ':' $pair)
    complete -c tpduck -n __tpduck_no_cmd -a $parts[1] -d $parts[2]
end

for sub in code verify resync qr export rm pin tag
    complete -c tpduck -n "__tpduck_cmd_is $sub" -a '(__tpduck_accounts)'
end
complete -c tpduck -n '__tpduck_cmd_is order' -a 'issuer used'
complete -c tpduck -n '__tpduck_cmd_is keyring' -a 'status set forget'
complete -c tpduck -n '__tpduck_cmd_is agent' -a 'run status stop forget'
complete -c tpduck -n '__tpduck_cmd_is offset' -a 'auto none'
complete -c tpduck -n '__tpduck_cmd_is yubikey' -a 'list code put delete rename password reset'
complete -c tpduck -n '__tpduck_cmd_is completion' -a 'bash zsh fish'
for sub in add backup restore
    complete -c tpduck -n "__tpduck_cmd_is $sub" -F
end
complete -c tpduck -l config -r -d 'vault path'
complete -c tpduck -l keyring -d 'read the passphrase from the OS keyring'
complete -c tpduck -l json -d 'machine-readable output'
complete -c tpduck -l profile -r -d 'named profile to use'
complete -c tpduck -l force -d 'do not ask for confirmation'
complete -c tpduck -l peek -d 'read a code without consuming it'
complete -c tpduck -l yubikey -d 'seal the vault to a YubiKey as well'
complete -c tpduck -l slot -r -a '1 2' -d 'YubiKey challenge-response slot'
complete -c tpduck -l move -d 'remove the vault copy after yubikey put'
`

func cmdCompletion(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tpduck completion <bash|zsh|fish>")
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		return fmt.Errorf("unknown shell %q (want bash, zsh or fish)", args[0])
	}
	_ = os.Stdout.Sync()
	return nil
}
