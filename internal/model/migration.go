package model

import (
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Google Authenticator's export QR codes carry an otpauth-migration:// URI
// whose "data" parameter is a base64 protobuf. Rather than pull in a protobuf
// runtime for one message, the wire format is decoded directly -- it is only
// varints and length-delimited fields.
//
//	message MigrationPayload {
//	  repeated OtpParameters otp_parameters = 1;
//	  int32 version = 2; int32 batch_size = 3; int32 batch_index = 4;
//	}
//	message OtpParameters {
//	  bytes secret = 1; string name = 2; string issuer = 3;
//	  Algorithm algorithm = 4; DigitCount digits = 5; OtpType type = 6;
//	  int64 counter = 7;
//	}
const migrationScheme = "otpauth-migration"

// IsMigrationURI reports whether raw looks like a Google Authenticator export.
func IsMigrationURI(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && strings.EqualFold(u.Scheme, migrationScheme)
}

// ParseMigrationURI decodes every account in a Google Authenticator export.
func ParseMigrationURI(raw string) ([]Account, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(u.Scheme, migrationScheme) {
		return nil, fmt.Errorf("not an %s uri", migrationScheme)
	}
	// Read "data" out of the raw query rather than through url.Query(): query
	// decoding turns "+" into a space, and "+" is a standard base64 character,
	// so Query() silently corrupts any payload that contains one.
	data := rawQueryParam(u.RawQuery, "data")
	if data == "" {
		return nil, errors.New("migration uri has no data parameter")
	}
	payload, err := decodeBase64Loose(data)
	if err != nil {
		return nil, fmt.Errorf("decode migration data: %w", err)
	}
	return parseMigrationPayload(payload)
}

// rawQueryParam returns a query parameter percent-decoded but without the
// form-encoding rule that "+" means space.
func rawQueryParam(rawQuery, key string) string {
	for _, pair := range strings.Split(rawQuery, "&") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k != key {
			continue
		}
		if dec, err := url.PathUnescape(v); err == nil {
			return dec
		}
		return v
	}
	return ""
}

func decodeBase64Loose(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	// Tolerate a payload that has been through a form decoder already, which
	// would have replaced every "+" with a space.
	if strings.Contains(s, " ") {
		s = strings.ReplaceAll(s, " ", "+")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func parseMigrationPayload(buf []byte) ([]Account, error) {
	var accounts []Account
	for len(buf) > 0 {
		num, typ, rest, err := readTag(buf)
		if err != nil {
			return nil, err
		}
		buf = rest
		if num == 1 && typ == 2 { // otp_parameters
			var field []byte
			if field, buf, err = readBytes(buf); err != nil {
				return nil, err
			}
			acc, err := parseOtpParameters(field)
			if err != nil {
				return nil, err
			}
			accounts = append(accounts, acc)
			continue
		}
		if buf, err = skipField(typ, buf); err != nil {
			return nil, err
		}
	}
	if len(accounts) == 0 {
		return nil, errors.New("migration payload contained no accounts")
	}
	return accounts, nil
}

func parseOtpParameters(buf []byte) (Account, error) {
	acc := Account{Digits: DefaultDigits, Period: DefaultPeriod, Algo: AlgoSHA1, Type: TypeTOTP}
	var rawSecret []byte
	for len(buf) > 0 {
		num, typ, rest, err := readTag(buf)
		if err != nil {
			return acc, err
		}
		buf = rest
		switch {
		case num == 1 && typ == 2:
			if rawSecret, buf, err = readBytes(buf); err != nil {
				return acc, err
			}
		case num == 2 && typ == 2:
			var b []byte
			if b, buf, err = readBytes(buf); err != nil {
				return acc, err
			}
			acc.Name = string(b)
		case num == 3 && typ == 2:
			var b []byte
			if b, buf, err = readBytes(buf); err != nil {
				return acc, err
			}
			acc.Issuer = string(b)
		case num == 4 && typ == 0:
			var v uint64
			if v, buf, err = readVarint(buf); err != nil {
				return acc, err
			}
			switch v {
			case 0, 1:
				acc.Algo = AlgoSHA1 // 0 is "unspecified", which means SHA1
			case 2:
				acc.Algo = AlgoSHA256
			case 3:
				acc.Algo = AlgoSHA512
			default:
				return acc, fmt.Errorf("migration: unsupported algorithm %d", v)
			}
		case num == 5 && typ == 0:
			var v uint64
			if v, buf, err = readVarint(buf); err != nil {
				return acc, err
			}
			switch v {
			case 0, 1:
				acc.Digits = 6
			case 2:
				acc.Digits = 8
			default:
				return acc, fmt.Errorf("migration: unsupported digit count %d", v)
			}
		case num == 6 && typ == 0:
			var v uint64
			if v, buf, err = readVarint(buf); err != nil {
				return acc, err
			}
			switch v {
			case 1:
				acc.Type = TypeHOTP
			case 0, 2:
				acc.Type = TypeTOTP
			default:
				return acc, fmt.Errorf("migration: unsupported otp type %d", v)
			}
		case num == 7 && typ == 0:
			var v uint64
			if v, buf, err = readVarint(buf); err != nil {
				return acc, err
			}
			acc.Counter = v
		default:
			if buf, err = skipField(typ, buf); err != nil {
				return acc, err
			}
		}
	}
	if len(rawSecret) == 0 {
		return acc, errors.New("migration: account has no secret")
	}
	// The protobuf carries raw key bytes; the rest of tpduck speaks Base32.
	acc.Secret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(rawSecret)
	if strings.TrimSpace(acc.Name) == "" {
		return acc, errors.New("migration: account has no name")
	}
	// Google puts "Issuer:name" in the name field when there is no issuer field.
	if acc.Issuer == "" {
		if parts := strings.SplitN(acc.Name, ":", 2); len(parts) == 2 {
			acc.Issuer, acc.Name = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
	}
	acc.AddedAt = time.Now().Unix()
	acc.ID = MakeID(acc)
	return acc, acc.Validate()
}

// --- minimal protobuf wire reader ---

func readVarint(buf []byte) (uint64, []byte, error) {
	var v uint64
	for i := 0; i < len(buf); i++ {
		if i >= 10 {
			return 0, nil, errors.New("protobuf: varint too long")
		}
		v |= uint64(buf[i]&0x7F) << (7 * uint(i))
		if buf[i]&0x80 == 0 {
			return v, buf[i+1:], nil
		}
	}
	return 0, nil, errors.New("protobuf: truncated varint")
}

func readTag(buf []byte) (num int, typ int, rest []byte, err error) {
	v, rest, err := readVarint(buf)
	if err != nil {
		return 0, 0, nil, err
	}
	num, typ = int(v>>3), int(v&7)
	if num == 0 {
		return 0, 0, nil, errors.New("protobuf: field number 0")
	}
	return num, typ, rest, nil
}

func readBytes(buf []byte) ([]byte, []byte, error) {
	n, rest, err := readVarint(buf)
	if err != nil {
		return nil, nil, err
	}
	if n > uint64(len(rest)) {
		return nil, nil, errors.New("protobuf: truncated length-delimited field")
	}
	return rest[:n], rest[n:], nil
}

func skipField(typ int, buf []byte) ([]byte, error) {
	switch typ {
	case 0:
		_, rest, err := readVarint(buf)
		return rest, err
	case 1:
		if len(buf) < 8 {
			return nil, errors.New("protobuf: truncated 64-bit field")
		}
		return buf[8:], nil
	case 2:
		_, rest, err := readBytes(buf)
		return rest, err
	case 5:
		if len(buf) < 4 {
			return nil, errors.New("protobuf: truncated 32-bit field")
		}
		return buf[4:], nil
	default:
		return nil, fmt.Errorf("protobuf: unsupported wire type %d", typ)
	}
}
