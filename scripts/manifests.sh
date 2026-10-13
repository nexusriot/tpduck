#!/usr/bin/env bash
# Fill the packaging templates with a release's version and checksums.
#
# Run after scripts/build.sh, so the sums describe artefacts that exist:
#   make dist && ./scripts/manifests.sh
set -euo pipefail

cd "$(dirname "$0")/.."

DIST_DIR=${DIST_DIR:-dist}
OUT_DIR=${OUT_DIR:-${DIST_DIR}/manifests}
# internal/version/VERSION is the single source of truth, the same file the
# binary embeds; a release overrides VERSION from the tag.
VERSION=${VERSION:-$(cat internal/version/VERSION 2>/dev/null || echo dev)}
BARE=${VERSION#v}

if [ ! -f "${DIST_DIR}/SHA256SUMS" ]; then
  echo "manifests: no ${DIST_DIR}/SHA256SUMS; run scripts/build.sh first" >&2
  exit 1
fi

# sum <suffix> -- the checksum of the archive ending in that suffix.
sum() {
  local suffix=$1 line
  line=$(grep -E "tpduck_${VERSION}_${suffix}\$" "${DIST_DIR}/SHA256SUMS" || true)
  if [ -z "${line}" ]; then
    echo "manifests: no checksum for ${suffix}" >&2
    return 1
  fi
  awk '{print $1}' <<<"${line}"
}

mkdir -p "${OUT_DIR}"

render() {
  local src=$1 dst=$2
  sed \
    -e "s|@VERSION@|${BARE}|g" \
    -e "s|@SHA_LINUX_AMD64@|$(sum linux_amd64.tar.gz)|g" \
    -e "s|@SHA_LINUX_ARM64@|$(sum linux_arm64.tar.gz)|g" \
    -e "s|@SHA_DARWIN_AMD64@|$(sum darwin_amd64.tar.gz)|g" \
    -e "s|@SHA_DARWIN_ARM64@|$(sum darwin_arm64.tar.gz)|g" \
    -e "s|@SHA_WINDOWS_AMD64@|$(sum windows_amd64.zip)|g" \
    -e "s|@SHA_WINDOWS_ARM64@|$(sum windows_arm64.zip)|g" \
    "${src}" > "${dst}"
  echo "  ${dst}"
}

echo "rendering manifests for ${VERSION}"
render packaging/homebrew/tpduck.rb "${OUT_DIR}/tpduck.rb"
render packaging/aur/PKGBUILD       "${OUT_DIR}/PKGBUILD"
render packaging/scoop/tpduck.json  "${OUT_DIR}/tpduck.json"
