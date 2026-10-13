package model

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func ParseOtpauthURI(raw string) (*Account, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	// Scheme and host are case-insensitive per RFC 3986; Go does not fold them.
	if !strings.EqualFold(u.Scheme, "otpauth") {
		return nil, fmt.Errorf("not an otpauth uri")
	}
	var kind OTPType
	switch {
	case strings.EqualFold(u.Host, string(TypeTOTP)):
		kind = TypeTOTP
	case strings.EqualFold(u.Host, string(TypeHOTP)):
		kind = TypeHOTP
	case strings.EqualFold(u.Host, string(TypeSteam)):
		kind = TypeSteam
	default:
		return nil, fmt.Errorf("unsupported otpauth type %q (want totp, hotp or steam)", u.Host)
	}

	// label is "Issuer:AccountName" or just "AccountName".
	// u.Path is already percent-decoded by url.Parse; decoding it a second time
	// would corrupt labels that legitimately contain a "%" sequence.
	label := strings.TrimPrefix(u.Path, "/")

	q := u.Query()
	qIssuer := strings.TrimSpace(q.Get("issuer"))
	secret := q.Get("secret")
	algoStr := strings.ToUpper(q.Get("algorithm"))
	digitsStr := q.Get("digits")
	periodStr := q.Get("period")
	counterStr := q.Get("counter")

	if strings.TrimSpace(secret) == "" {
		return nil, fmt.Errorf("missing secret in otpauth")
	}
	if err := ValidateSecret(secret); err != nil {
		return nil, fmt.Errorf("invalid secret: %w", err)
	}

	// Always split the label; many providers include both issuer in label and query.
	var labelIssuer, labelName string
	if parts := strings.SplitN(label, ":", 2); len(parts) == 2 {
		labelIssuer, labelName = parts[0], parts[1]
	} else {
		labelName = label
	}

	// Prefer query issuer, fall back to label issuer.
	issuer := qIssuer
	if issuer == "" {
		issuer = strings.TrimSpace(labelIssuer)
	}
	name := strings.TrimSpace(labelName)
	if name == "" {
		return nil, fmt.Errorf("missing account name in otpauth label")
	}

	// Algorithm, digits, period with sane defaults
	algo := AlgoSHA1
	switch algoStr {
	case "", "SHA1":
		algo = AlgoSHA1
	case "SHA256":
		algo = AlgoSHA256
	case "SHA512":
		algo = AlgoSHA512
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algoStr)
	}

	digits := DefaultDigits
	if kind == TypeSteam {
		// Steam codes are always five characters; a digits parameter on a
		// steam URI is noise rather than a contradiction.
		digits = SteamDigits
	} else if digitsStr != "" {
		v, err := strconv.Atoi(digitsStr)
		if err != nil || (v != 6 && v != 8) {
			return nil, fmt.Errorf("unsupported digits: %s", digitsStr)
		}
		digits = v
	}

	period := DefaultPeriod
	if periodStr != "" {
		v, err := strconv.Atoi(periodStr)
		if err != nil || v < MinPeriod || v > MaxPeriod {
			return nil, fmt.Errorf("unsupported period: %s", periodStr)
		}
		period = v
	}

	// HOTP is counter-based; the spec makes counter mandatory for it, and a
	// wrong starting counter produces codes the server silently rejects.
	var counter uint64
	if kind == TypeHOTP {
		if counterStr == "" {
			return nil, fmt.Errorf("hotp uri is missing the required counter parameter")
		}
		v, err := strconv.ParseUint(counterStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid counter: %s", counterStr)
		}
		counter = v
	}

	acc := &Account{
		Issuer:  issuer,
		Name:    name,
		Secret:  NormalizeSecret(secret),
		Digits:  digits,
		Period:  period,
		Algo:    algo,
		Type:    kind,
		Counter: counter,
		AddedAt: time.Now().Unix(),
	}
	acc.ID = MakeID(*acc)
	return acc, nil
}
