package model

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DefaultNTPServer is queried only when the user explicitly asks for a skew
// check. tpduck never contacts the network on its own: the whole point of the
// tool is that it works offline.
const DefaultNTPServer = "pool.ntp.org:123"

// ntpEpochOffset is the gap between the NTP epoch (1900) and the Unix epoch.
const ntpEpochOffset = 2208988800

// ClockSkew queries an SNTP server and reports how far the local clock is from
// it. A skew beyond roughly half a TOTP period is the single most common cause
// of "the code doesn't work".
func ClockSkew(server string, timeout time.Duration) (time.Duration, error) {
	if server == "" {
		server = DefaultNTPServer
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return 0, fmt.Errorf("contact %s: %w", server, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, err
	}

	req := make([]byte, 48)
	req[0] = 0x1B // LI=0, VN=3, Mode=3 (client)

	sent := time.Now()
	if _, err := conn.Write(req); err != nil {
		return 0, fmt.Errorf("query %s: %w", server, err)
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return 0, fmt.Errorf("read from %s: %w", server, err)
	}
	received := time.Now()

	// Transmit timestamp occupies bytes 40..47: 32 bits of seconds since 1900
	// followed by a 32-bit binary fraction.
	secs := binary.BigEndian.Uint32(resp[40:44])
	frac := binary.BigEndian.Uint32(resp[44:48])
	if secs == 0 {
		return 0, fmt.Errorf("%s returned an empty timestamp", server)
	}
	nanos := (int64(frac) * 1e9) >> 32
	serverTime := time.Unix(int64(secs)-ntpEpochOffset, nanos)

	// Account for the round trip: the reply describes a moment roughly half a
	// round trip before it arrived.
	rtt := received.Sub(sent)
	local := sent.Add(rtt / 2)
	return local.Sub(serverTime), nil
}

// SkewVerdict turns a measured skew into a human sentence, given the shortest
// period in use.
func SkewVerdict(skew time.Duration, period int) (text string, bad bool) {
	if period <= 0 {
		period = DefaultPeriod
	}
	abs := skew
	if abs < 0 {
		abs = -abs
	}
	limit := time.Duration(period) * time.Second / 2
	sign := "ahead of"
	if skew < 0 {
		sign = "behind"
	}
	switch {
	case abs < time.Second:
		return fmt.Sprintf("clock is in sync (%+.1fs)", skew.Seconds()), false
	case abs < limit:
		return fmt.Sprintf("clock is %.1fs %s network time; codes should still work", abs.Seconds(), sign), false
	default:
		return fmt.Sprintf("clock is %.1fs %s network time -- codes will be rejected; sync your clock", abs.Seconds(), sign), true
	}
}
