#!/usr/bin/env bash
# Build the smart-card end-to-end image and run the suite inside it.
#
# This is the only place the PC/SC transport is compiled and executed: the
# release binaries are pure Go, so nothing else covers that code. The card is
# virtual (pcscd + vpcd + our vicc process), and everything is local, so the
# container runs with no network.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-tpduck-e2e-pcsc}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo e2e)}
DOCKER=${DOCKER:-docker}

if ! command -v "${DOCKER}" >/dev/null 2>&1; then
  echo "e2e-pcsc: ${DOCKER} is not installed" >&2
  exit 2
fi
if ! "${DOCKER}" info >/dev/null 2>&1; then
  echo "e2e-pcsc: cannot talk to the ${DOCKER} daemon" >&2
  exit 2
fi

echo "building ${IMAGE} (${VERSION})"
"${DOCKER}" build \
  --build-arg "VERSION=${VERSION}" \
  -f test/e2e/Dockerfile.pcsc \
  -t "${IMAGE}" \
  . "$@"

echo
echo "running the smart-card suite with no network"
# pcscd needs to create /run/pcscd and bind a socket, so this container is not
# run read-only; the main suite is the one that checks unprivileged behaviour.
exec "${DOCKER}" run --rm \
  --network none \
  "${IMAGE}"
