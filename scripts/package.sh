#!/usr/bin/env bash
# Build .deb and .rpm packages from the tarballs produced by build.sh.
#
# Uses nfpm, which is pure Go and needs neither root nor dpkg/rpmbuild, so the
# same command works on any machine that has Go.
set -euo pipefail

cd "$(dirname "$0")/.."

BINARY=tpduck
DIST_DIR=${DIST_DIR:-dist}
# internal/version/VERSION is the single source of truth, the same file the
# binary embeds; a release overrides VERSION from the tag.
VERSION=${VERSION:-$(cat internal/version/VERSION 2>/dev/null || echo dev)}
ARCHES=${ARCHES:-"amd64 arm64"}
FORMATS=${FORMATS:-"deb rpm"}
# FLAVOUR is "default" (pure Go, no shared libraries) or "pcsc" (built with
# -tags pcsc, which links libpcsclite and so declares it as a dependency).
FLAVOUR=${FLAVOUR:-default}
NFPM_VERSION=${NFPM_VERSION:-v2.48.0}

# Package versions may not carry a leading "v" or a git "-dirty" suffix.
PKG_VERSION=${VERSION#v}
PKG_VERSION=${PKG_VERSION//-dirty/}
PKG_VERSION=${PKG_VERSION//[^0-9A-Za-z.+~-]/.}
# A bare commit hash is not a version; fall back to something installable.
if [[ ! ${PKG_VERSION} =~ ^[0-9] ]]; then
  PKG_VERSION="0.0.0+${PKG_VERSION}"
fi

# type -P searches PATH only. `command -v` would find this very function and
# send us into an infinite "nfpm: command not found" loop.
NFPM_BIN=$(type -P nfpm || true)

run_nfpm() {
  if [ -n "${NFPM_BIN}" ]; then
    "${NFPM_BIN}" "$@"
  else
    go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" "$@"
  fi
}

case "${FLAVOUR}" in
  default)
    PKG_NAME=tpduck
    PKG_CONFLICTS=tpduck-pcsc
    # Nothing is linked in, so nothing is required.
    PKG_DEPENDS=""
    ;;
  pcsc)
    PKG_NAME=tpduck-pcsc
    PKG_CONFLICTS=tpduck
    # The cgo build links against libpcsclite, so the library is required at
    # runtime, not merely suggested. The package manager names differ.
    case " ${FORMATS} " in
      *" rpm "*) PKG_DEPENDS="pcsc-lite" ;;
    esac
    PKG_DEPENDS="${PKG_DEPENDS:-libpcsclite1}"
    ;;
  *)
    echo "package: unknown flavour ${FLAVOUR} (want default or pcsc)" >&2
    exit 1
    ;;
esac

for arch in ${ARCHES}; do
  tarball="${DIST_DIR}/${BINARY}_${VERSION}_linux_${arch}.tar.gz"
  if [ ! -f "${tarball}" ]; then
    echo "missing ${tarball}; run scripts/build.sh first" >&2
    exit 1
  fi

  stage=$(mktemp -d)
  trap 'rm -rf "${stage}"' EXIT
  tar -xzf "${tarball}" -C "${stage}" --strip-components=1

  for format in ${FORMATS}; do
    # The dependency name differs between deb and rpm, so the config is
    # rendered per format rather than once per architecture.
    depends="${PKG_DEPENDS}"
    if [ "${FLAVOUR}" = "pcsc" ]; then
      case "${format}" in
        deb) depends="libpcsclite1" ;;
        rpm) depends="pcsc-lite" ;;
      esac
    fi

    config="${stage}/nfpm-${format}.yaml"
    STAGE="${stage}" PKG_ARCH="${arch}" PKG_VERSION="${PKG_VERSION}" \
      PKG_NAME="${PKG_NAME}" PKG_CONFLICTS="${PKG_CONFLICTS}" PKG_DEPENDS="${depends}" \
      envsubst '${STAGE} ${PKG_ARCH} ${PKG_VERSION} ${PKG_NAME} ${PKG_CONFLICTS} ${PKG_DEPENDS}' \
      < packaging/nfpm.yaml > "${config}"

    # An empty dependency would render as a blank list entry, which nfpm
    # rejects; drop the whole stanza instead.
    if [ -z "${depends}" ]; then
      sed -i '/^depends:$/,+1d' "${config}"
    fi

    run_nfpm package --config "${config}" --packager "${format}" --target "${DIST_DIR}/"
  done

  rm -rf "${stage}"
  trap - EXIT
done

echo
echo "packages in ${DIST_DIR}:"
ls -1 "${DIST_DIR}"/*.deb "${DIST_DIR}"/*.rpm 2>/dev/null || true
