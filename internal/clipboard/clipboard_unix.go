//go:build !windows

package clipboard

// platformHelpers lists the clipboard tools to try, in order. Wayland first,
// then X11, then macOS.
func platformHelpers() []helper {
	return []helper{
		{name: "wl-copy", write: []string{"wl-copy"}, read: []string{"wl-paste", "--no-newline"}, clear: []string{"wl-copy", "--clear"}},
		{name: "xclip", write: []string{"xclip", "-selection", "clipboard"}, read: []string{"xclip", "-selection", "clipboard", "-o"}},
		{name: "xsel", write: []string{"xsel", "--clipboard", "--input"}, read: []string{"xsel", "--clipboard", "--output"}, clear: []string{"xsel", "--clipboard", "--delete"}},
		{name: "pbcopy", write: []string{"pbcopy"}, read: []string{"pbpaste"}},
	}
}
