package test

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
	"rsc.io/qr"
)

// writeQRPNG renders text as a real QR code image, scaled up the way a
// screenshot of a setup page would be.
func writeQRPNG(t *testing.T, path, text string, scale, quiet int) {
	t.Helper()
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		t.Fatal(err)
	}
	side := (code.Size + quiet*2) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			mx, my := x/scale-quiet, y/scale-quiet
			c := color.Gray{Y: 255}
			if mx >= 0 && my >= 0 && mx < code.Size && my < code.Size && code.Black(mx, my) {
				c = color.Gray{Y: 0}
			}
			img.SetGray(x, y, c)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
}

// This also proves the QR codes tpduck renders are structurally valid: the
// image is built from the same encoder the export path uses.
func TestDecodeQRImage(t *testing.T) {
	dir := t.TempDir()
	want := "otpauth://totp/GitHub:alice@example.com?algorithm=SHA1&digits=6&issuer=GitHub&period=30&secret=JBSWY3DPEHPK3PXP"
	path := filepath.Join(dir, "enroll.png")
	writeQRPNG(t, path, want, 6, 4)

	got, err := m.DecodeQRImage(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("decoded %q, want %q", got, want)
	}
	// And the decoded URI must import cleanly.
	acc, err := m.ParseOtpauthURI(got)
	if err != nil {
		t.Fatalf("decoded URI does not parse: %v", err)
	}
	if acc.Issuer != "GitHub" || acc.Name != "alice@example.com" {
		t.Errorf("got %+v", acc)
	}
}

func TestDecodeQRImageErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := m.DecodeQRImage(filepath.Join(dir, "missing.png")); err == nil {
		t.Error("missing file accepted")
	}
	// A valid image with no QR in it.
	blank := filepath.Join(dir, "blank.png")
	img := image.NewGray(image.Rect(0, 0, 64, 64))
	f, _ := os.Create(blank)
	_ = png.Encode(f, img)
	f.Close()
	if _, err := m.DecodeQRImage(blank); err == nil {
		t.Error("blank image accepted")
	}
	// A file that is not an image at all.
	notimg := filepath.Join(dir, "notes.txt")
	_ = os.WriteFile(notimg, []byte("hello"), 0o600)
	if _, err := m.DecodeQRImage(notimg); err == nil {
		t.Error("non-image accepted")
	}
}
