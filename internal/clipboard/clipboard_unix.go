//go:build !windows

package clipboard

// platformHelpers lists the clipboard tools to try, in order. Wayland first,
// then X11, then macOS.
//
// Only wl-copy can say "this is a password": wl-clipboard turns --sensitive
// into the x-kde-passwordManagerHint MIME type that Klipper, cliphist and
// others look for, and ignores it before version 2.3. The X11 tools own the
// selection with exactly one target at a time, so they cannot offer that hint
// alongside the text, and pbcopy has no equivalent for macOS's
// org.nspasteboard.ConcealedType. For those the clearing timer is the only
// protection there is.
func platformHelpers() []helper {
	const noHint = " cannot mark a copy as sensitive, so a clipboard manager may keep it"
	return []helper{
		{
			name:      "wl-copy",
			write:     []string{"wl-copy"},
			sensitive: []string{"wl-copy", "--sensitive"},
			read:      []string{"wl-paste", "--no-newline"},
			clear:     []string{"wl-copy", "--clear"},
		},
		{
			name: "xclip", write: []string{"xclip", "-selection", "clipboard"},
			read:          []string{"xclip", "-selection", "clipboard", "-o"},
			sensitiveNote: "xclip" + noHint,
		},
		{
			name: "xsel", write: []string{"xsel", "--clipboard", "--input"},
			read:          []string{"xsel", "--clipboard", "--output"},
			clear:         []string{"xsel", "--clipboard", "--delete"},
			sensitiveNote: "xsel" + noHint,
		},
		{
			name: "pbcopy", write: []string{"pbcopy"}, read: []string{"pbpaste"},
			sensitiveNote: "pbcopy" + noHint,
		},
	}
}
