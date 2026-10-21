//go:build windows

package clipboard

// platformHelpers uses PowerShell, which is present on every supported Windows
// version and can both read and write the clipboard. clip.exe can only write,
// so it is the fallback: without a read, a scheduled clear cannot tell whether
// the clipboard is still ours, and Transient falls back to clearing anyway.
//
// Set-Clipboard cannot mark content, so the sensitive write goes through a
// DataObject carrying the three formats Windows documents for this:
// ExcludeClipboardContentFromMonitorProcessing, CanIncludeInClipboardHistory
// and CanUploadToCloudClipboard. Together they keep a copied code out of the
// Win+V history and out of cloud sync to the user's other machines.
func platformHelpers() []helper {
	const ps = "powershell"
	const sensitiveScript = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$text = [Console]::In.ReadToEnd()
$data = New-Object System.Windows.Forms.DataObject
$data.SetText($text)
foreach ($fmt in 'ExcludeClipboardContentFromMonitorProcessing',
                 'CanIncludeInClipboardHistory',
                 'CanUploadToCloudClipboard') {
  $ms = New-Object System.IO.MemoryStream
  $ms.WriteByte(0)
  $data.SetData($fmt, $ms)
}
[System.Windows.Forms.Clipboard]::SetDataObject($data, $true)
`
	return []helper{
		{
			name:  "powershell",
			write: []string{ps, "-NoProfile", "-NonInteractive", "-Command", "$input | Set-Clipboard"},
			sensitive: []string{ps, "-NoProfile", "-NonInteractive", "-STA",
				"-Command", sensitiveScript},
			read:  []string{ps, "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"},
			clear: []string{ps, "-NoProfile", "-NonInteractive", "-Command", "Set-Clipboard -Value $null"},
		},
		{
			name: "clip", write: []string{"clip"},
			sensitiveNote: "clip.exe cannot mark a copy as sensitive, so Windows clipboard history may keep it",
		},
	}
}
