#!/usr/bin/env bash
# Cross-compile tpduck for every platform in $PLATFORMS and write tarballs,
# completions and a SHA256SUMS file into ./dist.
set -euo pipefail

cd "$(dirname "$0")/.."

BINARY=tpduck
DIST_DIR=${DIST_DIR:-dist}
# internal/version/VERSION is the single source of truth, the same file the
# binary embeds; a release overrides VERSION from the tag.
VERSION=${VERSION:-$(cat internal/version/VERSION 2>/dev/null || echo dev)}
PLATFORMS=${PLATFORMS:-"linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"}
LDFLAGS="-s -w -X github.com/nexusriot/tpduck/internal/version.Override=${VERSION}"

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}"

# Completions are generated once by a native build; they are identical for
# every target, so there is no need to run a cross-compiled binary.
native="${DIST_DIR}/.native-${BINARY}"
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "${native}" ./cmd/tpduck
mkdir -p "${DIST_DIR}/completions"
for shell in bash zsh fish; do
  "${native}" completion "${shell}" > "${DIST_DIR}/completions/${BINARY}.${shell}"
done

echo "building ${BINARY} ${VERSION}"
for platform in ${PLATFORMS}; do
  goos=${platform%/*}
  goarch=${platform#*/}
  outdir="${DIST_DIR}/${BINARY}_${VERSION}_${goos}_${goarch}"
  mkdir -p "${outdir}"

  ext=""
  [ "${goos}" = "windows" ] && ext=".exe"

  CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -trimpath -ldflags "${LDFLAGS}" -o "${outdir}/${BINARY}${ext}" ./cmd/tpduck

  cp README.md "${outdir}/"
  cp docs/${BINARY}.1 "${outdir}/"
  cp -r "${DIST_DIR}/completions" "${outdir}/completions"

  # Windows users expect a zip; everyone else expects a tarball.
  if [ "${goos}" = "windows" ] && command -v zip >/dev/null 2>&1; then
    ( cd "${DIST_DIR}" && zip -qr "$(basename "${outdir}").zip" "$(basename "${outdir}")" )
    archive="${outdir}.zip"
  else
    tar -C "${DIST_DIR}" -czf "${outdir}.tar.gz" "$(basename "${outdir}")"
    archive="${outdir}.tar.gz"
  fi
  rm -rf "${outdir}"
  printf '  %-28s %s\n' "${goos}/${goarch}" "$(basename "${archive}")"
done

rm -f "${native}"

( cd "${DIST_DIR}" && sha256sum ./*.tar.gz ./*.zip 2>/dev/null > SHA256SUMS )
echo "wrote ${DIST_DIR}/SHA256SUMS"
