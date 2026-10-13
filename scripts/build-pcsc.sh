#!/usr/bin/env bash
# Build the smart-card variant: tpduck with -tags pcsc, which uses cgo and
# links against libpcsclite.
#
# Unlike scripts/build.sh this cannot cross-compile without a cross toolchain,
# so by default it builds only for the machine it runs on. Output goes to its
# own directory so it never collides with the pure-Go archives.
set -euo pipefail

cd "$(dirname "$0")/.."

BINARY=tpduck
DIST_DIR=${DIST_DIR:-dist/pcsc}
# internal/version/VERSION is the single source of truth, the same file the
# binary embeds; a release overrides VERSION from the tag.
VERSION=${VERSION:-$(cat internal/version/VERSION 2>/dev/null || echo dev)}
GOARCH_HOST=$(go env GOARCH)
ARCHES=${ARCHES:-${GOARCH_HOST}}
LDFLAGS="-s -w -X github.com/nexusriot/tpduck/internal/version.Override=${VERSION}"

if ! pkg-config --exists libpcsclite 2>/dev/null; then
  echo "build-pcsc: libpcsclite development files are missing." >&2
  echo "            run ./scripts/install-deps.sh --build" >&2
  exit 1
fi

rm -rf "${DIST_DIR}"
mkdir -p "${DIST_DIR}/completions"

native="${DIST_DIR}/.native-${BINARY}"
CGO_ENABLED=0 go build -trimpath -ldflags "${LDFLAGS}" -o "${native}" ./cmd/tpduck
for shell in bash zsh fish; do
  "${native}" completion "${shell}" > "${DIST_DIR}/completions/${BINARY}.${shell}"
done
rm -f "${native}"

echo "building ${BINARY} ${VERSION} (smart-card variant)"
for goarch in ${ARCHES}; do
  if [ "${goarch}" != "${GOARCH_HOST}" ] && [ -z "${CC:-}" ]; then
    echo "  skipping linux/${goarch}: cgo needs a cross compiler; set CC=" >&2
    continue
  fi
  outdir="${DIST_DIR}/${BINARY}_${VERSION}_linux_${goarch}"
  mkdir -p "${outdir}"

  CGO_ENABLED=1 GOOS=linux GOARCH="${goarch}" \
    go build -trimpath -tags pcsc -ldflags "${LDFLAGS}" -o "${outdir}/${BINARY}" ./cmd/tpduck

  cp README.md "${outdir}/"
  cp docs/${BINARY}.1 "${outdir}/"
  cp -r "${DIST_DIR}/completions" "${outdir}/completions"

  tar -C "${DIST_DIR}" -czf "${outdir}.tar.gz" "$(basename "${outdir}")"
  rm -rf "${outdir}"
  printf '  %-28s %s\n' "linux/${goarch}" "$(basename "${outdir}.tar.gz")"
done

( cd "${DIST_DIR}" && sha256sum ./*.tar.gz > SHA256SUMS )
echo "wrote ${DIST_DIR}/SHA256SUMS"
