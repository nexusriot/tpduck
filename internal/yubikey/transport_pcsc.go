//go:build pcsc

// This transport talks to a real card reader through PC/SC. It needs cgo and
// libpcsclite-dev, so it is behind a build tag: the default build stays pure
// Go and cross-compiles for the release packages.
//
//	go build -tags pcsc ./cmd
package yubikey

import (
	"fmt"
	"strings"

	"github.com/ebfe/scard"
)

type pcscTransport struct {
	ctx  *scard.Context
	card *scard.Card
}

// Connect finds a connected YubiKey and opens its OATH applet. `reader` may be
// a substring of the reader name; empty means the first reader that answers as
// an OATH applet.
func Connect(reader string) (*Session, error) {
	var out *Session
	err := connectApplet(reader, "OATH", func(t Transport) error {
		s, err := Open(t)
		out = s
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ConnectOTP finds a connected YubiKey and opens its OTP applet, which is the
// one that answers HMAC-SHA1 challenge-response.
func ConnectOTP(reader string) (*OTPSession, error) {
	var out *OTPSession
	err := connectApplet(reader, "OTP", func(t Transport) error {
		s, err := OpenOTP(t)
		out = s
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// connectApplet walks the candidate readers and hands each one's transport to
// open, stopping at the first that answers. A machine can easily have a
// built-in reader alongside the key, and only one of them holds the applet, so
// refusing to choose would make tpduck unusable on exactly those machines.
func connectApplet(reader, applet string, open func(Transport) error) error {
	ctx, err := scard.EstablishContext()
	if err != nil {
		return fmt.Errorf("pcsc: %w (is pcscd running?)", err)
	}
	readers, err := ctx.ListReaders()
	if err != nil {
		ctx.Release()
		return fmt.Errorf("pcsc: list readers: %w", err)
	}
	candidates, err := pickReaders(readers, reader)
	if err != nil {
		ctx.Release()
		return err
	}

	var lastErr error
	for _, name := range candidates {
		card, err := ctx.Connect(name, scard.ShareShared, scard.ProtocolAny)
		if err != nil {
			lastErr = fmt.Errorf("pcsc: connect to %q: %w", name, err)
			continue
		}
		t := &pcscTransport{ctx: ctx, card: card}
		if err := open(t); err == nil {
			return nil
		} else {
			lastErr = fmt.Errorf("%s: %w", name, err)
		}
		_ = card.Disconnect(scard.LeaveCard)
	}
	ctx.Release()
	if lastErr == nil {
		lastErr = fmt.Errorf("no reader held a card with a %s applet", applet)
	}
	return fmt.Errorf("pcsc: no %s applet on any reader (%s): %w",
		applet, strings.Join(candidates, ", "), lastErr)
}

// pickReaders returns the readers to try, most likely first.
func pickReaders(readers []string, want string) ([]string, error) {
	if len(readers) == 0 {
		return nil, fmt.Errorf("pcsc: no smart-card readers found")
	}
	if want != "" {
		var matched []string
		for _, r := range readers {
			if strings.Contains(strings.ToLower(r), strings.ToLower(want)) {
				matched = append(matched, r)
			}
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("pcsc: no reader matching %q (have: %s)", want, strings.Join(readers, ", "))
		}
		return matched, nil
	}
	// A reader that says "yubikey" is tried first; the rest follow in order.
	var first, rest []string
	for _, r := range readers {
		if strings.Contains(strings.ToLower(r), "yubikey") {
			first = append(first, r)
		} else {
			rest = append(rest, r)
		}
	}
	return append(first, rest...), nil
}

func (p *pcscTransport) Transmit(apdu []byte) ([]byte, error) {
	resp, err := p.card.Transmit(apdu)
	if err != nil {
		return nil, fmt.Errorf("pcsc: transmit: %w", err)
	}
	return resp, nil
}

func (p *pcscTransport) Close() error {
	var err error
	if p.card != nil {
		err = p.card.Disconnect(scard.LeaveCard)
	}
	if p.ctx != nil {
		p.ctx.Release()
	}
	return err
}
