package model

// Steam Guard codes are ordinary TOTP underneath -- same HMAC, same 30-second
// window -- but the truncated value is rendered as five characters of Steam's
// own alphabet rather than as decimal digits.
const (
	steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"
	// SteamDigits is the fixed length of a Steam Guard code.
	SteamDigits = 5
)

// steamCode renders a 31-bit dynamic-truncation value the way Steam does.
func steamCode(raw uint32) string {
	out := make([]byte, SteamDigits)
	v := raw
	for i := 0; i < SteamDigits; i++ {
		out[i] = steamAlphabet[v%uint32(len(steamAlphabet))]
		v /= uint32(len(steamAlphabet))
	}
	return string(out)
}
