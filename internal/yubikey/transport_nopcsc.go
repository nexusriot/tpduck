//go:build !pcsc

package yubikey

import "errors"

// ErrNoPCSC is returned when this build cannot talk to a card reader.
var ErrNoPCSC = errors.New("this build has no smart-card support; rebuild with -tags pcsc (needs libpcsclite)")

// Connect is the no-hardware stand-in for the PC/SC transport.
func Connect(reader string) (*Session, error) { return nil, ErrNoPCSC }

// ConnectOTP is the same stand-in for the challenge-response applet.
func ConnectOTP(reader string) (*OTPSession, error) { return nil, ErrNoPCSC }
