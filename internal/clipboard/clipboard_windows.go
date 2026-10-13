//go:build windows

package clipboard

// platformHelpers uses PowerShell, which is present on every supported Windows
// version and can both read and write the clipboard. clip.exe can only write,
// so it is the fallback: without a read, a scheduled clear cannot tell whether
// the clipboard is still ours, and Transient falls back to clearing anyway.
func platformHelpers() []helper {
	const ps = "powershell"
	return []helper{
		{
			name:  "powershell",
			write: []string{ps, "-NoProfile", "-NonInteractive", "-Command", "$input | Set-Clipboard"},
			read:  []string{ps, "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"},
			clear: []string{ps, "-NoProfile", "-NonInteractive", "-Command", "Set-Clipboard -Value $null"},
		},
		{name: "clip", write: []string{"clip"}},
	}
}
