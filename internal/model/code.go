package model

import (
	"fmt"
	"time"
)

// Code is one generated OTP plus how long it stays valid.
type Code struct {
	Value  string
	Remain int  // seconds left in the window; 0 for HOTP
	Static bool // true for HOTP, whose code only changes when the counter does
}

// Generate produces the current code for an account, handling both TOTP and
// HOTP. HOTP does not advance the counter here -- see Store.AdvanceHOTP.
func Generate(a Account, now time.Time) (Code, error) {
	switch a.Kind() {
	case TypeSteam:
		period := a.Period
		if period <= 0 {
			period = DefaultPeriod
		}
		raw, remain, err := totpRaw(a.Secret, a.Algo, period, now)
		if err != nil {
			return Code{}, err
		}
		return Code{Value: steamCode(raw), Remain: remain}, nil
	case TypeHOTP:
		key, err := decodeBase32(a.Secret)
		if err != nil {
			return Code{}, fmt.Errorf("secret decode: %w", err)
		}
		if len(key) == 0 {
			return Code{}, errEmptySecret
		}
		raw, err := Hotp(key, a.Counter, a.Algo)
		if err != nil {
			return Code{}, err
		}
		return Code{Value: truncateCode(raw, a.Digits), Static: true}, nil
	default:
		v, remain, err := Totp(a.Secret, a.Algo, a.Period, a.Digits, now)
		if err != nil {
			return Code{}, err
		}
		return Code{Value: v, Remain: remain}, nil
	}
}

// AdvanceHOTP increments a counter-based account's counter, which is what
// "use this code" means for HOTP.
func (s *Store) AdvanceHOTP(id string) error {
	i := s.FindIndexByID(id)
	if i < 0 {
		return fmt.Errorf("no account with id %q", id)
	}
	if s.Accounts[i].Kind() != TypeHOTP {
		return fmt.Errorf("%s is not a counter-based account", s.Accounts[i].Label())
	}
	s.Accounts[i].Counter++
	return nil
}
