#!/usr/bin/env bash
# Build the end-to-end image and run the suite inside it.
#
# The container runs with --network none, so the suite cannot reach anything:
# what it exercises is the binary and the filesystem, nothing else. Building
# the image does need network for the module cache the first time.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-tpduck-e2e}
VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo e2e)}
DOCKER=${DOCKER:-docker}

if ! command -v "${DOCKER}" >/dev/null 2>&1; then
  echo "e2e: ${DOCKER} is not installed" >&2
  exit 2
fi
if ! "${DOCKER}" info >/dev/null 2>&1; then
  echo "e2e: cannot talk to the ${DOCKER} daemon" >&2
  exit 2
fi

echo "building ${IMAGE} (${VERSION})"
"${DOCKER}" build \
  --build-arg "VERSION=${VERSION}" \
  -f test/e2e/Dockerfile \
  -t "${IMAGE}" \
  . "$@"

echo
echo "running the suite with no network"
exec "${DOCKER}" run --rm \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,exec,mode=1777 \
  --tmpfs /home/duck:rw,mode=0700,uid=1000,gid=1000 \
  "${IMAGE}"
