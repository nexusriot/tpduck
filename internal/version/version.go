// Package version reports which tpduck this is.
//
// The single source of truth is the VERSION file beside this one. It is
// embedded, so a plain `go build` or `go install` reports a real version
// rather than "dev"; release builds override it through -ldflags, and the
// Makefile and packaging scripts read the same file.
package version

import (
	_ "embed"
	"fmt"
	"runtime/debug"
	"strings"
)

//go:embed VERSION
var versionFile string

// Override is set at build time with -ldflags "-X .../internal/version.Override=v1.2.3".
// It wins over the embedded file, so a release can stamp the exact tag.
var Override string

// String returns the version, without a leading "v".
func String() string {
	if v := strings.TrimSpace(Override); v != "" {
		return strings.TrimPrefix(v, "v")
	}
	if v := strings.TrimSpace(versionFile); v != "" {
		return strings.TrimPrefix(v, "v")
	}
	return "dev"
}

// Full returns the version along with the commit the toolchain stamped in, so
// a bug report identifies the build and not just the release it came from.
func Full() string {
	out := String()
	rev, dirty, ok := vcs()
	if !ok {
		return out
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if dirty {
		return fmt.Sprintf("%s (%s, dirty)", out, rev)
	}
	return fmt.Sprintf("%s (%s)", out, rev)
}

// vcs pulls the revision out of the build info the Go toolchain records for
// builds made inside a repository.
func vcs() (revision string, dirty bool, ok bool) {
	info, available := debug.ReadBuildInfo()
	if !available {
		return "", false, false
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	return revision, dirty, revision != ""
}
