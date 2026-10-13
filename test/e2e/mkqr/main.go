// Command mkqr renders text as a QR code PNG. It exists so the end-to-end
// suite can produce the kind of screenshot a user would feed to `tpduck add`,
// without committing a binary fixture.
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"

	"rsc.io/qr"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: mkqr <text> <out.png>")
		os.Exit(2)
	}
	code, err := qr.Encode(os.Args[1], qr.M)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
	const scale, quiet = 8, 4
	side := (code.Size + quiet*2) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			mx, my := x/scale-quiet, y/scale-quiet
			g := color.Gray{Y: 255}
			if mx >= 0 && my >= 0 && mx < code.Size && my < code.Size && code.Black(mx, my) {
				g = color.Gray{Y: 0}
			}
			img.SetGray(x, y, g)
		}
	}
	f, err := os.Create(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
