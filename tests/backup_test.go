package test

import (
	"strings"
	"testing"

	m "github.com/nexusriot/tpduck/internal/model"
)

const aegisJSON = `{"version":1,"header":{"slots":null,"params":null},"db":{"version":2,"entries":[
 {"type":"totp","uuid":"1","name":"alice","issuer":"GitHub","note":"work",
  "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA1","digits":6,"period":30}},
 {"type":"hotp","uuid":"2","name":"bob","issuer":"Bank",
  "info":{"secret":"JBSWY3DPEHPK3PXP","algo":"SHA256","digits":8,"counter":12}}]}}`

const andOTPJSON = `[
 {"secret":"JBSWY3DPEHPK3PXP","label":"alice","issuer":"GitHub","digits":6,"type":"TOTP","algorithm":"SHA1","period":30},
 {"secret":"JBSWY3DPEHPK3PXP","label":"Bank:bob","issuer":"","digits":6,"type":"HOTP","algorithm":"SHA1","counter":7}]`

const twofasJSON = `{"schemaVersion":4,"services":[
 {"name":"GitHub","secret":"JBSWY3DPEHPK3PXP",
  "otp":{"account":"alice","issuer":"GitHub","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP"}}]}`

func TestParseBackupAegis(t *testing.T) {
	accs, format, err := m.ParseBackup([]byte(aegisJSON))
	if err != nil {
		t.Fatal(err)
	}
	if format != "Aegis" {
		t.Errorf("format = %q", format)
	}
	if len(accs) != 2 {
		t.Fatalf("got %d accounts", len(accs))
	}
	if accs[0].Issuer != "GitHub" || accs[0].Name != "alice" || accs[0].Notes != "work" {
		t.Errorf("entry 0 = %+v", accs[0])
	}
	if accs[1].Kind() != m.TypeHOTP || accs[1].Counter != 12 || accs[1].Digits != 8 || accs[1].Algo != m.AlgoSHA256 {
		t.Errorf("entry 1 = %+v", accs[1])
	}
}

// An encrypted Aegis export must say what to do, not fail obscurely.
func TestParseBackupAegisEncrypted(t *testing.T) {
	_, _, err := m.ParseBackup([]byte(`{"version":1,"header":{"slots":[{"type":1}]},"db":"d2hvb3BzLi4u"}`))
	if err == nil || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("got %v, want a message about the export being encrypted", err)
	}
}

func TestParseBackupAndOTP(t *testing.T) {
	accs, format, err := m.ParseBackup([]byte(andOTPJSON))
	if err != nil {
		t.Fatal(err)
	}
	if format != "andOTP" || len(accs) != 2 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	// The second entry has no issuer field; it comes from the "Issuer:name" label.
	if accs[1].Issuer != "Bank" || accs[1].Name != "bob" || accs[1].Counter != 7 {
		t.Errorf("entry 1 = %+v", accs[1])
	}
}

func TestParseBackup2FAS(t *testing.T) {
	accs, format, err := m.ParseBackup([]byte(twofasJSON))
	if err != nil {
		t.Fatal(err)
	}
	if format != "2FAS" || len(accs) != 1 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	if accs[0].Issuer != "GitHub" || accs[0].Name != "alice" {
		t.Errorf("entry = %+v", accs[0])
	}
}

func TestParseBackupURIList(t *testing.T) {
	list := strings.Join([]string{
		"# exported by tpduck",
		"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
		"",
		"otpauth://hotp/Bank:bob?secret=JBSWY3DPEHPK3PXP&issuer=Bank&counter=3",
	}, "\n")
	accs, format, err := m.ParseBackup([]byte(list))
	if err != nil {
		t.Fatal(err)
	}
	if format != "otpauth URI list" || len(accs) != 2 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	if accs[1].Counter != 3 {
		t.Errorf("counter = %d", accs[1].Counter)
	}
}

func TestParseBackupKeePassCSV(t *testing.T) {
	csv := `"Group","Title","Username","Password","URL","Notes","TOTP"
"Root","GitHub","alice","hunter2","https://github.com","","otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
"Root","NoOTP","bob","hunter2","https://example.com","",""
`
	accs, format, err := m.ParseBackup([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if format != "KeePassXC CSV" {
		t.Errorf("format = %q", format)
	}
	if len(accs) != 1 || accs[0].Issuer != "GitHub" {
		t.Fatalf("got %+v", accs)
	}
}

// tpduck's own export must read back through the importer.
func TestExportBackupRoundTrip(t *testing.T) {
	want := []m.Account{
		{Issuer: "GitHub", Name: "alice", Secret: "JBSWY3DPEHPK3PXP", Digits: 6, Period: 30, Algo: m.AlgoSHA1},
		{Issuer: "Bank", Name: "bob", Secret: "JBSWY3DPEHPK3PXP", Digits: 8, Algo: m.AlgoSHA512, Type: m.TypeHOTP, Counter: 4},
	}
	accs, format, err := m.ParseBackup([]byte(m.ExportBackup(want)))
	if err != nil {
		t.Fatal(err)
	}
	if format != "otpauth URI list" || len(accs) != 2 {
		t.Fatalf("format=%q n=%d", format, len(accs))
	}
	if accs[1].Counter != 4 || accs[1].Algo != m.AlgoSHA512 || accs[1].Digits != 8 {
		t.Errorf("hotp entry lost detail: %+v", accs[1])
	}
}

func TestParseBackupRejectsJunk(t *testing.T) {
	for name, body := range map[string]string{
		"empty":        "   ",
		"random text":  "hello there\nthis is not a backup",
		"unknown json": `{"something":"else"}`,
		"empty array":  `[]`,
		"bad secret":   `[{"secret":"1111","label":"x","type":"TOTP","digits":6,"period":30}]`,
		"steam entry":  `{"db":{"entries":[{"type":"steam","name":"x","info":{"secret":"JBSWY3DPEHPK3PXP"}}]}}`,
	} {
		if accs, format, err := m.ParseBackup([]byte(body)); err == nil {
			t.Errorf("%s: accepted as %q -> %+v", name, format, accs)
		}
	}
}
