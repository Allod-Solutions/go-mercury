package mercury

import (
	"strings"
	"testing"
)

func TestFingerprintEmpty(t *testing.T) {
	if fp := Fingerprint(nil); fp != "" {
		t.Errorf("expected empty fingerprint for nil input, got %q", fp)
	}
	if fp := Fingerprint([]byte{0x17, 0x03, 0x03}); fp != "" {
		t.Errorf("expected empty fingerprint for non-handshake record, got %q", fp)
	}
}

// synthClientHello builds a minimal TLS ClientHello for testing.
func synthClientHello(recordVer, helloVer uint16, cipherSuites, exts []uint16) []byte {
	// Build cipher suite bytes
	cs := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cs = append(cs, byte(c>>8), byte(c))
	}

	// Build extension bytes (type-only, no data)
	extBytes := make([]byte, 0)
	for _, e := range exts {
		extBytes = append(extBytes, byte(e>>8), byte(e), 0x00, 0x00) // type + 0-length data
	}

	var extLenField []byte
	if len(extBytes) > 0 {
		l := len(extBytes)
		extLenField = []byte{byte(l >> 8), byte(l)}
		extLenField = append(extLenField, extBytes...)
	}

	// ClientHello body
	body := []byte{
		byte(helloVer >> 8), byte(helloVer), // legacy_version
	}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length = 0
	body = append(body,
		byte(len(cs)>>8), byte(len(cs)), // cipher suites length
	)
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // compression: 1 method, null
	body = append(body, extLenField...)

	// Handshake header: type(1) + length(3)
	hsBody := []byte{0x01, // ClientHello
		byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body)),
	}
	hsBody = append(hsBody, body...)

	// TLS record header: content_type(1) + version(2) + length(2)
	rec := []byte{
		0x16,
		byte(recordVer >> 8), byte(recordVer),
		byte(len(hsBody) >> 8), byte(len(hsBody)),
	}
	return append(rec, hsBody...)
}

func TestFingerprintFormat(t *testing.T) {
	data := synthClientHello(
		0x0303, 0x0303,
		[]uint16{0xc02b, 0xc02f, 0x002f, 0x0a0a}, // last one is GREASE
		[]uint16{0x0000, 0x000a, 0xfafa},           // last one is GREASE
	)
	fp := Fingerprint(data)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}
	// Should start with (0303)(0303)
	if !strings.HasPrefix(fp, "(0303)(0303)") {
		t.Errorf("unexpected prefix: %q", fp[:20])
	}
	// GREASE cipher 0x0a0a must be absent
	if strings.Contains(fp, "0a0a") {
		t.Errorf("GREASE value 0x0a0a should be filtered from fingerprint: %q", fp)
	}
	// GREASE extension 0xfafa must be absent
	if strings.Contains(fp, "fafa") {
		t.Errorf("GREASE extension 0xfafa should be filtered from fingerprint: %q", fp)
	}
}

func TestDBLookupMiss(t *testing.T) {
	db := NewDB()
	_, ok := db.Lookup("(0303)(0303)[][]")
	if ok {
		t.Error("expected miss on empty DB")
	}
}

func TestDBLoadAndLookup(t *testing.T) {
	const testDB = `{
		"(0303)(0303)[(c02b)(c02f)][(0000)(000a)]": {
			"process_info": [
				{"process": "testbrowser", "prevalence": 0.9,
				 "os_info": [{"os": "linux", "prevalence": 0.8}]}
			]
		}
	}`
	db := NewDB()
	if err := db.LoadReader(strings.NewReader(testDB)); err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if db.Count() != 1 {
		t.Errorf("expected 1 entry, got %d", db.Count())
	}
	pi, ok := db.Lookup("(0303)(0303)[(c02b)(c02f)][(0000)(000a)]")
	if !ok {
		t.Fatal("expected hit")
	}
	if pi.Process != "testbrowser" {
		t.Errorf("expected testbrowser, got %q", pi.Process)
	}
	if pi.OS != "linux" {
		t.Errorf("expected linux, got %q", pi.OS)
	}
}
