package model

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"net/url"
)

// DefaultMigrationBatch is how many accounts go into one export QR. Google
// Authenticator splits large exports the same way; a QR holding too much
// becomes dense enough that phone cameras struggle.
const DefaultMigrationBatch = 10

// BuildMigrationURIs encodes accounts as one or more otpauth-migration:// URIs,
// the format Google Authenticator's own export produces and reads. It returns
// one URI per batch, in order, along with the accounts it could not represent.
//
// Steam Guard is the only such account: the migration protobuf has no code for
// it, so an exported Steam credential would come back as a six-digit TOTP that
// quietly produces codes Steam never accepts. Skipping it and saying so is the
// only honest answer -- use `tpduck export` or `qr` for those.
func BuildMigrationURIs(accounts []Account, perBatch int) (uris []string, skipped []Account, err error) {
	exportable := make([]Account, 0, len(accounts))
	for _, a := range accounts {
		if a.Kind() == TypeSteam {
			skipped = append(skipped, a)
			continue
		}
		exportable = append(exportable, a)
	}
	accounts = exportable
	if len(accounts) == 0 {
		if len(skipped) > 0 {
			return nil, skipped, fmt.Errorf("the migration format cannot carry Steam Guard accounts; nothing else to export")
		}
		return nil, nil, fmt.Errorf("nothing to export")
	}
	if perBatch <= 0 {
		perBatch = DefaultMigrationBatch
	}
	batches := (len(accounts) + perBatch - 1) / perBatch
	uris = make([]string, 0, batches)
	for b := 0; b < batches; b++ {
		end := (b + 1) * perBatch
		if end > len(accounts) {
			end = len(accounts)
		}
		payload, err := encodeMigrationPayload(accounts[b*perBatch:end], batches, b)
		if err != nil {
			return nil, skipped, err
		}
		q := url.Values{}
		q.Set("data", base64.StdEncoding.EncodeToString(payload))
		uris = append(uris, (&url.URL{
			Scheme:   migrationScheme,
			Host:     "offline",
			RawQuery: q.Encode(),
		}).String())
	}
	return uris, skipped, nil
}

func encodeMigrationPayload(accounts []Account, batchSize, batchIndex int) ([]byte, error) {
	var payload []byte
	for _, a := range accounts {
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(NormalizeSecret(a.Secret))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.Label(), err)
		}
		var p []byte
		p = append(p, pbBytes(1, raw)...)
		p = append(p, pbBytes(2, []byte(a.Name))...)
		if a.Issuer != "" {
			p = append(p, pbBytes(3, []byte(a.Issuer))...)
		}
		algo := uint64(1) // SHA1
		switch a.Algo {
		case AlgoSHA256:
			algo = 2
		case AlgoSHA512:
			algo = 3
		}
		p = append(p, pbVarintField(4, algo)...)
		digits := uint64(1) // DIGIT_COUNT_SIX
		if a.Digits == 8 {
			digits = 2
		}
		p = append(p, pbVarintField(5, digits)...)
		typ := uint64(2) // OTP_TYPE_TOTP
		if a.Kind() == TypeHOTP {
			typ = 1
			p = append(p, pbVarintField(6, typ)...)
			p = append(p, pbVarintField(7, a.Counter)...)
		} else {
			p = append(p, pbVarintField(6, typ)...)
		}
		payload = append(payload, pbBytes(1, p)...)
	}
	payload = append(payload, pbVarintField(2, 1)...) // version
	payload = append(payload, pbVarintField(3, uint64(batchSize))...)
	payload = append(payload, pbVarintField(4, uint64(batchIndex))...)
	return payload, nil
}

// --- minimal protobuf wire writer ---

func pbVarint(v uint64) []byte {
	var out []byte
	for v >= 0x80 {
		out = append(out, byte(v)|0x80)
		v >>= 7
	}
	return append(out, byte(v))
}

func pbVarintField(num int, v uint64) []byte {
	out := pbVarint(uint64(num)<<3 | 0)
	return append(out, pbVarint(v)...)
}

func pbBytes(num int, body []byte) []byte {
	out := pbVarint(uint64(num)<<3 | 2)
	out = append(out, pbVarint(uint64(len(body)))...)
	return append(out, body...)
}
