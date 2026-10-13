package model

import (
	"crypto/subtle"
	"fmt"
	"time"
)

// DefaultVerifyWindow is how many periods either side of now a code is accepted
// when verifying, matching what most servers allow.
const DefaultVerifyWindow = 1

// DefaultResyncLookahead is how far forward a counter is searched when
// resynchronising an HOTP account.
const DefaultResyncLookahead = 50

// VerifyResult describes where a code was found relative to the current
// position.
type VerifyResult struct {
	OK bool
	// Offset is the number of periods (TOTP) or counter steps (HOTP) away from
	// the current position at which the code matched.
	Offset int
}

// Verify checks whether code is one this account currently produces, searching
// `window` periods either side for TOTP, or `window` steps forward for HOTP.
// It is the quickest way to tell a mistyped secret from a skewed clock.
func Verify(a Account, code string, now time.Time, window int) (VerifyResult, error) {
	if window < 0 {
		window = 0
	}
	if a.Kind() == TypeHOTP {
		for i := 0; i <= window; i++ {
			cand := a
			cand.Counter = a.Counter + uint64(i)
			got, err := Generate(cand, now)
			if err != nil {
				return VerifyResult{}, err
			}
			if constantTimeEqual(got.Value, code) {
				return VerifyResult{OK: true, Offset: i}, nil
			}
		}
		return VerifyResult{}, nil
	}
	period := a.Period
	if period <= 0 {
		period = DefaultPeriod
	}
	// Search outwards from zero so the smallest offset wins; a code that is
	// valid both now and one step away should report "now".
	for i := 0; i <= window; i++ {
		for _, off := range dedupeOffsets(i) {
			at := now.Add(time.Duration(off*period) * time.Second)
			got, err := Generate(a, at)
			if err != nil {
				return VerifyResult{}, err
			}
			if constantTimeEqual(got.Value, code) {
				return VerifyResult{OK: true, Offset: off}, nil
			}
		}
	}
	return VerifyResult{}, nil
}

func dedupeOffsets(i int) []int {
	if i == 0 {
		return []int{0}
	}
	return []int{-i, i}
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ResyncHOTP finds the counter value that produces code and moves the account
// just past it. A counter-based account whose counter has fallen behind the
// server is otherwise unusable without editing it by hand.
func (s *Store) ResyncHOTP(id, code string, lookahead int) (uint64, error) {
	i := s.FindIndexByID(id)
	if i < 0 {
		return 0, fmt.Errorf("no account with id %q", id)
	}
	acc := s.Accounts[i]
	if acc.Kind() != TypeHOTP {
		return 0, fmt.Errorf("%s is not a counter-based account", acc.Label())
	}
	if lookahead <= 0 {
		lookahead = DefaultResyncLookahead
	}
	// Search both directions. The usual desync is our counter having run ahead
	// of the server's -- every code generated and not submitted advances us --
	// so the matching counter is normally *behind*, and a forward-only search
	// would fail in exactly the case people need this for.
	match, ok, err := searchCounter(acc, code, lookahead)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("no counter within %d steps either side of %d produces that code",
			lookahead, acc.Counter)
	}
	// Move past the matched counter: that code has now been used.
	s.Accounts[i].Counter = match + 1
	return s.Accounts[i].Counter, nil
}

// searchCounter looks for the counter producing code, trying the current value
// first and then alternating outwards.
func searchCounter(acc Account, code string, lookahead int) (uint64, bool, error) {
	try := func(c uint64) (bool, error) {
		cand := acc
		cand.Counter = c
		got, err := Generate(cand, time.Now())
		if err != nil {
			return false, err
		}
		return constantTimeEqual(got.Value, code), nil
	}
	if ok, err := try(acc.Counter); err != nil || ok {
		return acc.Counter, ok, err
	}
	for d := 1; d <= lookahead; d++ {
		if acc.Counter >= uint64(d) {
			c := acc.Counter - uint64(d)
			if ok, err := try(c); err != nil || ok {
				return c, ok, err
			}
		}
		c := acc.Counter + uint64(d)
		if ok, err := try(c); err != nil || ok {
			return c, ok, err
		}
	}
	return 0, false, nil
}
