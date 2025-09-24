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
	if u.Scheme != "otpauth" || u.Host != "totp" {
		return nil, fmt.Errorf("not an otpauth totp uri")
	}

	// label is "Issuer:AccountName" or just "AccountName"
	label := strings.TrimPrefix(u.Path, "/")
	label, _ = url.PathUnescape(label)

	q := u.Query()
	qIssuer := q.Get("issuer")
	secret := q.Get("secret")
	algoStr := strings.ToUpper(q.Get("algorithm"))
	digitsStr := q.Get("digits")
	periodStr := q.Get("period")

	if secret == "" {
		return nil, fmt.Errorf("missing secret in otpauth")
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
		issuer = labelIssuer
	}
	name := labelName

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

	digits := 6
	if digitsStr != "" {
		if v, err := strconv.Atoi(digitsStr); err == nil && (v == 6 || v == 8) {
			digits = v
		}
	}

	period := 30
	if periodStr != "" {
		if v, err := strconv.Atoi(periodStr); err == nil && v > 0 {
			period = v
		}
	}

	acc := &Account{
		Issuer:  issuer,
		Name:    name,
		Secret:  NormalizeSecret(secret),
		Digits:  digits,
		Period:  period,
		Algo:    algo,
		AddedAt: time.Now().Unix(),
	}
	acc.ID = MakeID(*acc)
	return acc, nil
}
