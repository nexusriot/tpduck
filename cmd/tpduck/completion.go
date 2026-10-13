package main

import (
	"errors"
	"fmt"
	"os"
)

// Completion scripts call `tpduck list` and strip the leading pin column, so
// account labels can be completed without the shell ever seeing a secret.
const bashCompletion = `# tpduck bash completion
# install: tpduck completion bash > /etc/bash_completion.d/tpduck
_tpduck() {
  local cur prev cmds
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmds="code verify resync list add rm pin order export qr migrate backup restore encrypt decrypt keyring offset skew yubikey completion version help"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
    return
  fi
  case "${COMP_WORDS[1]}" in
    code|verify|resync|qr|export|rm|pin)
      if [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=( $(compgen -W "$(tpduck list 2>/dev/null | awk '{print $2}')" -- "$cur") )
      fi
      ;;
    order)   COMPREPLY=( $(compgen -W "issuer used" -- "$cur") ) ;;
    keyring) COMPREPLY=( $(compgen -W "status set forget" -- "$cur") ) ;;
    offset)  COMPREPLY=( $(compgen -W "auto none" -- "$cur") ) ;;
    yubikey) COMPREPLY=( $(compgen -W "list code" -- "$cur") ) ;;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
    backup|restore|add) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
  esac
  case "$prev" in
    -config) COMPREPLY=( $(compgen -f -- "$cur") ) ;;
  esac
}
complete -F _tpduck tpduck
`

const zshCompletion = `#compdef tpduck
# install: tpduck completion zsh > "${fpath[1]}/_tpduck"
_tpduck_accounts() {
  local -a accounts
  accounts=(${(f)"$(tpduck list 2>/dev/null | awk '{print $2}')"})
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
    'export:print otpauth URIs'
    'qr:print a QR code'
    'migrate:print migration QR codes'
    'backup:write every account to a file'
    'restore:import a backup'
    'encrypt:set a vault passphrase'
    'decrypt:remove the vault passphrase'
    'keyring:manage the stored passphrase'
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
    code|verify|resync|qr|export|rm|pin) (( CURRENT == 3 )) && _tpduck_accounts ;;
    order)      compadd issuer used ;;
    keyring)    compadd status set forget ;;
    offset)     compadd auto none ;;
    yubikey)    compadd list code ;;
    completion) compadd bash zsh fish ;;
    backup|restore|add) _files ;;
  esac
}
_tpduck "$@"
`

const fishCompletion = `# tpduck fish completion
# install: tpduck completion fish > ~/.config/fish/completions/tpduck.fish
function __tpduck_accounts
    tpduck list 2>/dev/null | awk '{print $2}'
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
            'restore:import a backup' 'encrypt:set a vault passphrase' 'decrypt:remove the passphrase' \
            'keyring:manage the stored passphrase' 'offset:compensate for a wrong clock' \
            'skew:check the system clock' 'yubikey:use a YubiKey' 'completion:print a completion script' \
            'version:print the version' 'help:show help'
    set -l parts (string split -m1 ':' $pair)
    complete -c tpduck -n __tpduck_no_cmd -a $parts[1] -d $parts[2]
end

for sub in code verify resync qr export rm pin
    complete -c tpduck -n "__tpduck_cmd_is $sub" -a '(__tpduck_accounts)'
end
complete -c tpduck -n '__tpduck_cmd_is order' -a 'issuer used'
complete -c tpduck -n '__tpduck_cmd_is keyring' -a 'status set forget'
complete -c tpduck -n '__tpduck_cmd_is offset' -a 'auto none'
complete -c tpduck -n '__tpduck_cmd_is yubikey' -a 'list code'
complete -c tpduck -n '__tpduck_cmd_is completion' -a 'bash zsh fish'
for sub in add backup restore
    complete -c tpduck -n "__tpduck_cmd_is $sub" -F
end
complete -c tpduck -l config -r -d 'vault path'
complete -c tpduck -l keyring -d 'read the passphrase from the OS keyring'
complete -c tpduck -l json -d 'machine-readable output'
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
