package yubikey

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strings"
	"sync"
)

// SimCard is a software YubiKey OATH applet. It implements Transport, so the
// client can be exercised without hardware, and it is also what the end-to-end
// suite serves over a virtual smart-card reader -- one implementation of the
// applet rather than one per test harness.
type SimCard struct {
	mu    sync.Mutex
	creds []SimCredential

	// Chunk, when positive, forces responses to be returned in pieces so the
	// 61xx continuation path is exercised.
	Chunk int
	// Password, when set, makes the applet demand authentication.
	Password string
	// DeviceID salts the access key; a real key reports its own.
	DeviceID []byte
	// Challenge is what a locked applet offers for the response.
	Challenge []byte

	// HMACSlots holds the challenge-response secrets for OTP slots 1 and 2,
	// indexed by slot number. An empty entry is an unprogrammed slot.
	HMACSlots map[int][]byte
	// HMACTouch marks slots that will not answer until the key is touched.
	HMACTouch map[int]bool

	// otpSelected is true once the OTP applet has been selected; the two
	// applets share a card, and only one is current at a time.
	otpSelected bool

	// simAccess is the access key a client set with SET CODE. It stands in
	// for Password, since that is all the applet ever actually holds.
	simAccess []byte

	validated bool
	pending   []byte
	closed    bool
}

// simPasswordSet marks the applet as protected by a key set over the wire
// rather than by a password the test configured.
const simPasswordSet = "\x00set-over-the-wire"

// SimCredential is one credential held by the simulated applet.
type SimCredential struct {
	Name   string
	Secret string // Base32
	Digits byte
	Type   Type
	Algo   string
	Touch  bool
}

// defaultDeviceID stands in for the identifier a real key reports when its
// OATH applet is selected. It is always present on hardware, and the access
// key for a password is salted with it, so a card without one cannot have a
// password set at all.
var defaultDeviceID = []byte{0x74, 0x70, 0x64, 0x75, 0x63, 0x6B, 0x73, 0x69}

// NewSimCard builds a simulated applet holding the given credentials.
func NewSimCard(creds ...SimCredential) *SimCard {
	return &SimCard{
		creds:     creds,
		DeviceID:  append([]byte(nil), defaultDeviceID...),
		HMACSlots: map[int][]byte{},
		HMACTouch: map[int]bool{},
	}
}

// SetHMACSlot programmes an OTP slot for HMAC-SHA1 challenge-response, the way
// `ykman otp chalresp` would.
func (f *SimCard) SetHMACSlot(slot int, secret []byte, touch bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.HMACSlots == nil {
		f.HMACSlots = map[int][]byte{}
	}
	if f.HMACTouch == nil {
		f.HMACTouch = map[int]bool{}
	}
	f.HMACSlots[slot] = append([]byte(nil), secret...)
	f.HMACTouch[slot] = touch
}

// SetPassword turns on password protection with a fixed device id and
// challenge, so a test can reproduce the same exchange every run.
func (f *SimCard) SetPassword(password string, deviceID, challenge []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Password = password
	f.DeviceID = deviceID
	f.Challenge = challenge
	f.simAccess = nil
}

// Credentials returns a copy of what the card currently holds.
func (f *SimCard) Credentials() []SimCredential {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SimCredential(nil), f.creds...)
}

// Closed reports whether the transport was closed.
func (f *SimCard) Closed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// Close implements Transport.
func (f *SimCard) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// ATR is what a YubiKey 5 reports, used when the card is served over a
// virtual reader that has to answer a reset.
var ATR = []byte{
	0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80, 0x73,
	0xC0, 0x21, 0xC0, 0x57, 0x59, 0x75, 0x62, 0x69, 0x4B, 0x65, 0x79, 0x40,
}

// Reset clears the authenticated state, as powering the card down would.
func (f *SimCard) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validated = false
	f.pending = nil
	f.otpSelected = false
}

// Transmit implements Transport: one C-APDU in, one R-APDU out.
func (f *SimCard) Transmit(apdu []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.transmitLocked(apdu)
}

func (f *SimCard) transmitLocked(apdu []byte) ([]byte, error) {
	if len(apdu) < 4 {
		return statusWord(swWrongSyntax), nil
	}
	ins := apdu[1]
	var data []byte
	if len(apdu) > 4 {
		n := int(apdu[4])
		if 5+n > len(apdu) {
			return statusWord(swWrongSyntax), nil
		}
		data = apdu[5 : 5+n]
	}

	if ins == insSendRemaining {
		return f.drain(), nil
	}
	isSelect := ins == insSelect && apdu[2] == 0x04
	// Selecting an applet switches which one the following APDUs reach.
	if isSelect {
		f.otpSelected = bytes.Equal(data, otpAID)
		if f.otpSelected {
			return f.respond(nil)
		}
	}
	if f.otpSelected {
		if ins == insAPIRequest {
			return f.challengeResponse(apdu[2], data)
		}
		return statusWord(swWrongSyntax), nil
	}
	if f.Password != "" && !f.validated && !isSelect && ins != insValidate {
		return statusWord(swAuthRequired), nil
	}

	switch ins {
	case insSelect:
		if isSelect {
			out := tlv(tagVersion, []byte{5, 4, 3})
			if len(f.DeviceID) > 0 {
				out = append(out, tlv(tagName, f.DeviceID)...)
			}
			if f.Password != "" {
				out = append(out, tlv(tagChallenge, f.Challenge)...)
			}
			return f.respond(out)
		}
		return f.calculateAll(data)
	case insList:
		var out []byte
		for _, c := range f.creds {
			b, err := algoByte(c.Type, c.Algo)
			if err != nil {
				return statusWord(swWrongSyntax), nil
			}
			out = append(out, tlv(tagNameList, append([]byte{b}, []byte(c.Name)...))...)
		}
		return f.respond(out)
	case insCalculate:
		return f.calculate(data)
	case insValidate:
		return f.validate(data)
	case insPut:
		return f.put(data)
	case insDelete:
		return f.remove(data)
	case insRename:
		return f.rename(data)
	case insSetPwd:
		return f.setPassword(data)
	case insReset:
		if apdu[2] != 0xDE || apdu[3] != 0xAD {
			return statusWord(swWrongSyntax), nil
		}
		f.creds = nil
		f.Password, f.Challenge, f.validated = "", nil, false
		return f.respond(nil)
	}
	return statusWord(swWrongSyntax), nil
}

// challengeResponse answers the OTP applet's HMAC-SHA1 request.
func (f *SimCard) challengeResponse(p1 byte, challenge []byte) ([]byte, error) {
	slot := 0
	switch p1 {
	case p1ChalHMAC1:
		slot = 1
	case p1ChalHMAC2:
		slot = 2
	default:
		return statusWord(swWrongSyntax), nil
	}
	secret := f.HMACSlots[slot]
	if len(secret) == 0 {
		return statusWord(swNoSuchObject), nil
	}
	if f.HMACTouch[slot] {
		// A real key waits for the touch; the simulator cannot be touched, so
		// it reports the timeout a key would report if nobody did.
		return statusWord(swTouchTimeout), nil
	}
	mac := hmac.New(sha1.New, secret)
	mac.Write(challenge)
	return f.respond(mac.Sum(nil))
}

// setPassword stores a new access key, or clears it when the key TLV is empty.
func (f *SimCard) setPassword(data []byte) ([]byte, error) {
	var keyBlob, challenge, response []byte
	sawKey := false
	for _, t := range parseTLVs(data) {
		switch t.tag {
		case tagKey:
			keyBlob, sawKey = t.value, true
		case tagChallenge:
			challenge = t.value
		case tagResponse:
			response = t.value
		}
	}
	if !sawKey {
		return statusWord(swWrongSyntax), nil
	}
	if len(keyBlob) == 0 {
		f.Password, f.Challenge, f.simAccess = "", nil, nil
		return f.respond(nil)
	}
	if len(keyBlob) < 2 || keyBlob[0] != accessKeyAlgo {
		return statusWord(swWrongSyntax), nil
	}
	access := keyBlob[1:]
	// The applet checks that the caller can really compute responses under
	// the key it is being handed.
	mac := hmac.New(sha1.New, access)
	mac.Write(challenge)
	if !hmac.Equal(response, mac.Sum(nil)) {
		return statusWord(swWrongSignature), nil
	}
	f.simAccess = append([]byte(nil), access...)
	// A password is now set. The simulator keeps the access key directly
	// rather than a password, since that is all the applet ever sees.
	f.Password = simPasswordSet
	if len(f.Challenge) == 0 {
		f.Challenge = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	}
	f.validated = true
	return f.respond(nil)
}

func (f *SimCard) find(name string) (SimCredential, bool) {
	for _, c := range f.creds {
		if c.Name == name {
			return c, true
		}
	}
	return SimCredential{}, false
}

func (f *SimCard) calculate(data []byte) ([]byte, error) {
	var name string
	var chal []byte
	for _, t := range parseTLVs(data) {
		switch t.tag {
		case tagName:
			name = string(t.value)
		case tagChallenge:
			chal = t.value
		}
	}
	c, ok := f.find(name)
	if !ok {
		return statusWord(swNoSuchObject), nil
	}
	if c.Touch {
		return f.respond(tlv(tagTouch, nil))
	}
	trunc, err := simTruncate(c, chal)
	if err != nil {
		return statusWord(swWrongSyntax), nil
	}
	return f.respond(tlv(tagTruncated, append([]byte{c.Digits}, trunc...)))
}

func (f *SimCard) calculateAll(data []byte) ([]byte, error) {
	var chal []byte
	for _, t := range parseTLVs(data) {
		if t.tag == tagChallenge {
			chal = t.value
		}
	}
	var out []byte
	for _, c := range f.creds {
		out = append(out, tlv(tagName, []byte(c.Name))...)
		switch {
		case c.Touch:
			out = append(out, tlv(tagTouch, nil)...)
		case c.Type == TypeHOTP:
			out = append(out, tlv(tagHOTP, nil)...)
		default:
			trunc, err := simTruncate(c, chal)
			if err != nil {
				return statusWord(swWrongSyntax), nil
			}
			out = append(out, tlv(tagTruncated, append([]byte{c.Digits}, trunc...))...)
		}
	}
	return f.respond(out)
}

func (f *SimCard) validate(data []byte) ([]byte, error) {
	if f.Password == "" {
		f.validated = true
		return f.respond(nil)
	}
	var gotResponse, theirChallenge []byte
	for _, t := range parseTLVs(data) {
		switch t.tag {
		case tagResponse:
			gotResponse = t.value
		case tagChallenge:
			theirChallenge = t.value
		}
	}
	access := f.simAccess
	if access == nil {
		access = deriveAccessKey(f.Password, f.DeviceID)
	}
	mac := hmac.New(sha1.New, access)
	mac.Write(f.Challenge)
	if !hmac.Equal(gotResponse, mac.Sum(nil)) {
		return statusWord(swWrongSignature), nil
	}
	f.validated = true
	back := hmac.New(sha1.New, access)
	back.Write(theirChallenge)
	return f.respond(tlv(tagResponse, back.Sum(nil)))
}

func (f *SimCard) put(data []byte) ([]byte, error) {
	var name string
	var keyBlob []byte
	var touch bool
	for _, t := range parseTLVs(data) {
		switch t.tag {
		case tagName:
			name = string(t.value)
		case tagKey:
			keyBlob = t.value
		case tagProperty:
			touch = len(t.value) > 0 && t.value[0]&propRequireTouch != 0
		}
	}
	if name == "" || len(keyBlob) < 3 {
		return statusWord(swWrongSyntax), nil
	}
	typ, algo := decodeAlgoByte(keyBlob[0])
	c := SimCredential{
		Name:   name,
		Secret: base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(keyBlob[2:]),
		Digits: keyBlob[1],
		Type:   typ,
		Algo:   algo,
		Touch:  touch,
	}
	for i := range f.creds {
		if f.creds[i].Name == name {
			f.creds[i] = c
			return f.respond(nil)
		}
	}
	f.creds = append(f.creds, c)
	return f.respond(nil)
}

func (f *SimCard) remove(data []byte) ([]byte, error) {
	var name string
	for _, t := range parseTLVs(data) {
		if t.tag == tagName {
			name = string(t.value)
		}
	}
	for i := range f.creds {
		if f.creds[i].Name == name {
			f.creds = append(f.creds[:i], f.creds[i+1:]...)
			return f.respond(nil)
		}
	}
	return statusWord(swNoSuchObject), nil
}

func (f *SimCard) rename(data []byte) ([]byte, error) {
	var names []string
	for _, t := range parseTLVs(data) {
		if t.tag == tagName {
			names = append(names, string(t.value))
		}
	}
	if len(names) != 2 {
		return statusWord(swWrongSyntax), nil
	}
	for i := range f.creds {
		if f.creds[i].Name == names[0] {
			f.creds[i].Name = names[1]
			return f.respond(nil)
		}
	}
	return statusWord(swNoSuchObject), nil
}

// respond returns body with 9000, or the first chunk plus 61xx when chunking.
func (f *SimCard) respond(body []byte) ([]byte, error) {
	if f.Chunk <= 0 || len(body) <= f.Chunk {
		return append(body, 0x90, 0x00), nil
	}
	f.pending = body[f.Chunk:]
	head := append([]byte(nil), body[:f.Chunk]...)
	return append(head, 0x61, byte(minInt(len(f.pending), 0xFF))), nil
}

func (f *SimCard) drain() []byte {
	body := f.pending
	if f.Chunk > 0 && len(body) > f.Chunk {
		f.pending = body[f.Chunk:]
		head := append([]byte(nil), body[:f.Chunk]...)
		return append(head, 0x61, byte(minInt(len(f.pending), 0xFF)))
	}
	f.pending = nil
	return append(append([]byte(nil), body...), 0x90, 0x00)
}

func statusWord(code uint16) []byte { return []byte{byte(code >> 8), byte(code)} }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// simTruncate computes the dynamic truncation a real applet would return.
func simTruncate(c SimCredential, challenge []byte) ([]byte, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).
		DecodeString(strings.ToUpper(c.Secret))
	if err != nil {
		return nil, err
	}
	var h func() hash.Hash
	switch strings.ToUpper(c.Algo) {
	case "", "SHA1":
		h = sha1.New
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, key)
	mac.Write(challenge)
	sum := mac.Sum(nil)
	off := int(sum[len(sum)-1] & 0x0F)
	return sum[off : off+4], nil
}

// SimCode is what the client should produce for a credential at a time; the
// end-to-end suite uses it to check the code that came back off the wire.
func SimCode(secretB32 string, algo string, unix int64, period, digits int) (string, error) {
	if period <= 0 {
		period = 30
	}
	chal := make([]byte, 8)
	binary.BigEndian.PutUint64(chal, uint64(unix/int64(period)))
	trunc, err := simTruncate(SimCredential{Secret: secretB32, Algo: algo}, chal)
	if err != nil {
		return "", err
	}
	return formatTruncated(append([]byte{byte(digits)}, trunc...), digits)
}
