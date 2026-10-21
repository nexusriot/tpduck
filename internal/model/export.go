package model

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"net/url"
	"os"
	"strings"

	"github.com/makiuchi-d/gozxing"
	zxqr "github.com/makiuchi-d/gozxing/qrcode"
	"rsc.io/qr"
)

// URI renders the account as an otpauth:// URI, the interchange format every
// authenticator understands. The label carries the issuer as a prefix and the
// issuer= parameter repeats it, which is what the Key URI spec recommends.
func (a Account) URI() string {
	label := a.Name
	if a.Issuer != "" {
		label = a.Issuer + ":" + a.Name
	}
	q := url.Values{}
	q.Set("secret", NormalizeSecret(a.Secret))
	if a.Issuer != "" {
		q.Set("issuer", a.Issuer)
	}
	q.Set("algorithm", string(a.Algo))
	digits := a.Digits
	if digits == 0 {
		digits = DefaultDigits
	}
	q.Set("digits", fmt.Sprintf("%d", digits))
	switch a.Kind() {
	case TypeHOTP:
		q.Set("counter", fmt.Sprintf("%d", a.Counter))
	default:
		// Steam uses the otpauth://steam/ host, so the period still applies.
		// A zero period would render as "period=0", which every reader --
		// including this one -- rejects, so fall back to the default rather
		// than emitting a URI that cannot be imported anywhere.
		period := a.Period
		if period <= 0 {
			period = DefaultPeriod
		}
		q.Set("period", fmt.Sprintf("%d", period))
	}
	u := url.URL{
		Scheme:   "otpauth",
		Host:     string(a.Kind()),
		Path:     "/" + label,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// QRBlocks renders text as a QR code using Unicode half-blocks, so one text row
// carries two QR rows and the result stays square in a terminal. The quiet zone
// is included; without it many scanners refuse to read the code.
//
// The caller MUST render the result as black on white (see QRANSI, or set the
// colours on the widget). Dark modules are drawn as foreground: on a dark
// terminal background an uncoloured QR comes out inverted, and while many
// scanners cope with that, plenty do not.
func QRBlocks(text string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", fmt.Errorf("encode qr: %w", err)
	}
	const quiet = 2
	size := code.Size
	total := size + quiet*2

	dark := func(x, y int) bool {
		x -= quiet
		y -= quiet
		if x < 0 || y < 0 || x >= size || y >= size {
			return false
		}
		return code.Black(x, y)
	}

	var b strings.Builder
	for y := 0; y < total; y += 2 {
		for x := 0; x < total; x++ {
			top, bottom := dark(x, y), dark(x, y+1)
			switch {
			case top && bottom:
				b.WriteRune('█')
			case top:
				b.WriteRune('▀')
			case bottom:
				b.WriteRune('▄')
			default:
				b.WriteRune(' ')
			}
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// QRANSI wraps QRBlocks in the SGR codes that force black-on-white, for
// printing to a terminal from the CLI.
func QRANSI(text string) (string, error) {
	blocks, err := QRBlocks(text)
	if err != nil {
		return "", err
	}
	const (
		on  = "\x1b[30;47m"
		off = "\x1b[0m"
	)
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(blocks, "\n"), "\n") {
		b.WriteString(on)
		b.WriteString(line)
		b.WriteString(off)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// DecodeQRImage reads a QR code out of a PNG, JPEG or GIF file and returns the
// text it holds. Enrolling usually means scanning a code off a web page, and a
// screenshot is the only form of it most people can get at from a terminal.
func DecodeQRImage(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	img, format, err := image.Decode(f)
	if err != nil {
		return "", fmt.Errorf("decode image: %w", err)
	}
	bmp, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", fmt.Errorf("prepare %s image: %w", format, err)
	}
	// TRY_HARDER costs a little time and finds codes that are rotated, small
	// or sitting in the corner of a screenshot.
	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}
	res, err := zxqr.NewQRCodeReader().Decode(bmp, hints)
	if err != nil {
		return "", fmt.Errorf("no QR code found in %s", path)
	}
	return res.GetText(), nil
}
