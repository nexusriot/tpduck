# Hermetic end-to-end image for tpduck.
#
# The build stage compiles the binary and the QR fixture generator; the runtime
# stage carries no toolchain, so the suite exercises the shipped artefact the
# way a user would. scripts/e2e.sh runs it with --network none.

FROM golang:1.25-bookworm AS build
WORKDIR /src

# Dependencies first so edits to the source do not re-download the module cache.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=e2e
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/nexusriot/tpduck/internal/version.Override=${VERSION}" -o /out/tpduck ./cmd/tpduck \
 && CGO_ENABLED=0 go build -trimpath -o /out/mkqr ./test/e2e/mkqr

FROM debian:bookworm-slim

# bsdutils supplies script(1), used to give the TUI a pty; ncurses-base
# supplies the terminfo entries tcell needs to drive one.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates bsdutils ncurses-base \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/tpduck /usr/bin/tpduck
COPY --from=build /out/mkqr   /usr/bin/mkqr
COPY test/e2e/fixtures /opt/fixtures
COPY test/e2e/run.sh   /usr/bin/e2e

# A stand-in for a real clipboard helper. tpduck looks for wl-copy, xclip,
# xsel and pbcopy in that order; this lets the suite check that copying and
# the automatic clear actually work, which is otherwise untestable headlessly.
RUN printf '%s\n' \
    '#!/bin/sh' \
    'if [ "$3" = "-o" ]; then cat /tmp/fake-clipboard 2>/dev/null || true; else cat > /tmp/fake-clipboard; fi' \
    > /usr/local/bin/xclip \
 && chmod +x /usr/local/bin/xclip /usr/bin/e2e

# Run as an ordinary user: the vault's 0600/0700 permissions are part of what
# is being tested, and root would mask mistakes.
RUN useradd --create-home --shell /bin/bash duck
USER duck
WORKDIR /home/duck
ENV HOME=/home/duck XDG_CONFIG_HOME=/home/duck/.config TERM=xterm

ENTRYPOINT ["/usr/bin/e2e"]
