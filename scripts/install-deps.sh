#!/usr/bin/env bash
# Install the Linux packages tpduck needs to build and to run.
#
#   ./scripts/install-deps.sh            build + runtime dependencies
#   ./scripts/install-deps.sh --runtime  only what a user needs
#   ./scripts/install-deps.sh --dry-run  print the command, install nothing
#
# tpduck's release binaries are pure Go and need none of this. These packages
# are for building the smart-card variant (`make build-pcsc`), which uses cgo,
# and for the optional helpers tpduck shells out to.
set -euo pipefail

MODE=all
DRY_RUN=0
for arg in "$@"; do
  case "${arg}" in
    --runtime) MODE=runtime ;;
    --build)   MODE=build ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option ${arg}" >&2; exit 2 ;;
  esac
done

# detect the package manager rather than the distribution: derivatives are
# numerous and all of them keep the tool their parent used.
if   command -v apt-get >/dev/null 2>&1; then FAMILY=debian
elif command -v dnf     >/dev/null 2>&1; then FAMILY=fedora
elif command -v yum     >/dev/null 2>&1; then FAMILY=rhel
elif command -v pacman  >/dev/null 2>&1; then FAMILY=arch
elif command -v zypper  >/dev/null 2>&1; then FAMILY=suse
elif command -v apk     >/dev/null 2>&1; then FAMILY=alpine
else
  echo "install-deps: no supported package manager found" >&2
  echo "needed: a C toolchain, pkg-config, the pcsc-lite development headers," >&2
  echo "        and at runtime pcscd plus a clipboard helper" >&2
  exit 1
fi

# BUILD: libpcsclite's headers are what the cgo binding compiles against, so
# `make build-pcsc` fails without them. RUNTIME: pcscd is the daemon that
# talks to the key, and the clipboard helpers are what "copy" shells out to.
case "${FAMILY}" in
  debian)
    BUILD="build-essential pkg-config libpcsclite-dev"
    RUNTIME="pcscd libpcsclite1 wl-clipboard xclip"
    INSTALL=(sudo apt-get install -y --no-install-recommends)
    REFRESH=(sudo apt-get update)
    ;;
  fedora)
    BUILD="gcc pkgconf-pkg-config pcsc-lite-devel"
    RUNTIME="pcsc-lite wl-clipboard xclip"
    INSTALL=(sudo dnf install -y)
    REFRESH=(true)
    ;;
  rhel)
    BUILD="gcc pkgconfig pcsc-lite-devel"
    RUNTIME="pcsc-lite xclip"
    INSTALL=(sudo yum install -y)
    REFRESH=(true)
    ;;
  arch)
    BUILD="base-devel pkgconf pcsclite"
    RUNTIME="pcsclite wl-clipboard xclip"
    INSTALL=(sudo pacman -S --needed --noconfirm)
    REFRESH=(true)
    ;;
  suse)
    BUILD="gcc pkg-config pcsc-lite-devel"
    RUNTIME="pcsc-lite wl-clipboard xclip"
    INSTALL=(sudo zypper install -y)
    REFRESH=(true)
    ;;
  alpine)
    BUILD="build-base pkgconf pcsc-lite-dev"
    RUNTIME="pcsc-lite xclip"
    INSTALL=(sudo apk add)
    REFRESH=(true)
    ;;
esac

case "${MODE}" in
  all)     PACKAGES="${BUILD} ${RUNTIME}" ;;
  build)   PACKAGES="${BUILD}" ;;
  runtime) PACKAGES="${RUNTIME}" ;;
esac

echo "detected ${FAMILY}; installing: ${PACKAGES}"
if [ "${DRY_RUN}" = "1" ]; then
  echo "${REFRESH[*]}"
  echo "${INSTALL[*]} ${PACKAGES}"
  exit 0
fi
"${REFRESH[@]}"
# shellcheck disable=SC2086 -- the package list is deliberately word-split.
"${INSTALL[@]}" ${PACKAGES}

echo
echo "done. Build the smart-card variant with: make build-pcsc"
