package yubikey

import (
	"encoding/binary"
	"fmt"
	"time"
)

// The unit tests drive the same simulated applet the end-to-end suite serves
// over a virtual reader, so there is one implementation of the protocol under
// test rather than one per harness.

func sampleCard() *SimCard {
	return NewSimCard(
		SimCredential{Name: "30/GitHub:alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Type: TypeTOTP, Algo: "SHA1"},
		SimCredential{Name: "Bank:bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Type: TypeHOTP, Algo: "SHA256"},
		SimCredential{Name: "60/Touchy:carol", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Type: TypeTOTP, Algo: "SHA512", Touch: true},
	)
}

// expectedCode is what the client should produce for a credential at a time.
func expectedCode(secretB32 string, at time.Time, period, digits int) string {
	c := make([]byte, 8)
	binary.BigEndian.PutUint64(c, uint64(at.Unix()/int64(period)))
	trunc, err := simTruncate(SimCredential{Secret: secretB32, Algo: "SHA1"}, c)
	if err != nil {
		panic(err)
	}
	raw := binary.BigEndian.Uint32(trunc) & 0x7FFFFFFF
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, raw%mod)
}
