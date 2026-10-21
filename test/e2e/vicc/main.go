// Command vicc is a virtual YubiKey. It serves the simulated OATH applet over
// the vpcd protocol, so pcscd presents it as a real smart-card reader and the
// PC/SC transport can be exercised without hardware.
//
// vpcd (from vsmartcard) is a pcsc-lite driver that listens on a TCP port and
// relays APDUs to whatever connects to it. The framing is a 2-byte big-endian
// length followed by the payload; a one-byte payload is a control message
// rather than an APDU.
package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nexusriot/tpduck/internal/yubikey"
)

// vpcd control bytes.
const (
	ctrlPowerOff = 0x00
	ctrlPowerOn  = 0x01
	ctrlReset    = 0x02
	ctrlGetATR   = 0x04
)

func main() {
	addr := flag.String("addr", "127.0.0.1:35963", "vpcd address to connect to")
	creds := flag.String("credentials", "", "credentials as name=secret[:digits[:algo]], comma separated")
	password := flag.String("password", "", "protect the applet with this password")
	touch := flag.String("touch", "", "comma-separated credential names that require a touch")
	hmac1 := flag.String("hmac-slot1", "", "programme OTP slot 1 for HMAC-SHA1 challenge-response with this secret")
	hmac2 := flag.String("hmac-slot2", "", "programme OTP slot 2 for HMAC-SHA1 challenge-response with this secret")
	wait := flag.Duration("wait", 30*time.Second, "how long to keep retrying the connection")
	flag.Parse()

	card := yubikey.NewSimCard(parseCredentials(*creds, *touch)...)
	if *password != "" {
		// Fixed device id and challenge so a run is reproducible.
		card.SetPassword(*password,
			[]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			[]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})
	}

	for slot, secret := range map[int]string{1: *hmac1, 2: *hmac2} {
		if secret != "" {
			card.SetHMACSlot(slot, []byte(secret), false)
		}
	}

	conn, err := dialWithRetry(*addr, *wait)
	if err != nil {
		log.Fatalf("vicc: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(os.Stderr, "vicc: serving a virtual YubiKey to %s\n", *addr)

	if err := serve(conn, card); err != nil && !errors.Is(err, io.EOF) {
		log.Fatalf("vicc: %v", err)
	}
}

// dialWithRetry waits for vpcd to come up; pcscd may still be starting.
func dialWithRetry(addr string, within time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(within)
	for {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			return conn, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("could not reach vpcd at %s: %w", addr, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func serve(conn net.Conn, card *yubikey.SimCard) error {
	for {
		payload, err := readFrame(conn)
		if err != nil {
			return err
		}
		// A single byte is a control message, not an APDU.
		if len(payload) == 1 {
			switch payload[0] {
			case ctrlGetATR:
				if err := writeFrame(conn, yubikey.ATR); err != nil {
					return err
				}
			case ctrlPowerOff, ctrlPowerOn, ctrlReset:
				// Powering the card down drops any authenticated state.
				card.Reset()
			default:
				fmt.Fprintf(os.Stderr, "vicc: unknown control byte 0x%02X\n", payload[0])
			}
			continue
		}
		resp, err := card.Transmit(payload)
		if err != nil {
			return err
		}
		if err := writeFrame(conn, resp); err != nil {
			return err
		}
	}
}

func readFrame(conn net.Conn) ([]byte, error) {
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(length[:])
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeFrame(conn net.Conn, body []byte) error {
	out := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(out[:2], uint16(len(body)))
	copy(out[2:], body)
	_, err := conn.Write(out)
	return err
}

// parseCredentials reads "name=secret[:digits[:algo]]" entries.
func parseCredentials(spec, touchList string) []yubikey.SimCredential {
	needsTouch := map[string]bool{}
	for _, n := range strings.Split(touchList, ",") {
		if n = strings.TrimSpace(n); n != "" {
			needsTouch[n] = true
		}
	}
	var out []yubikey.SimCredential
	for _, item := range strings.Split(spec, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, rest, ok := strings.Cut(item, "=")
		if !ok {
			log.Fatalf("vicc: bad credential %q (want name=secret)", item)
		}
		parts := strings.Split(rest, ":")
		c := yubikey.SimCredential{
			Name: name, Secret: parts[0], Digits: 6, Type: yubikey.TypeTOTP, Algo: "SHA1",
			Touch: needsTouch[name],
		}
		if len(parts) > 1 && parts[1] == "8" {
			c.Digits = 8
		}
		if len(parts) > 2 {
			c.Algo = strings.ToUpper(parts[2])
		}
		if len(parts) > 3 && strings.EqualFold(parts[3], "hotp") {
			c.Type = yubikey.TypeHOTP
		}
		out = append(out, c)
	}
	return out
}
