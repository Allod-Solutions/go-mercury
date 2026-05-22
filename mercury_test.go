package mercury

import (
	"encoding/hex"
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

// extRaw carries an extension type and its raw data bytes (may be empty).
type extRaw struct {
	typ  uint16
	data []byte
}

// synthClientHello builds a minimal TLS ClientHello for testing.
// Extensions are encoded with empty (zero-length) data.
func synthClientHello(recordVer, helloVer uint16, cipherSuites, exts []uint16) []byte {
	raw := make([]extRaw, len(exts))
	for i, e := range exts {
		raw[i] = extRaw{typ: e}
	}
	return synthClientHelloWithExts(recordVer, helloVer, cipherSuites, raw)
}

// synthClientHelloWithExts builds a TLS ClientHello with full extension data control.
func synthClientHelloWithExts(recordVer, helloVer uint16, cipherSuites []uint16, exts []extRaw) []byte {
	cs := make([]byte, 0, len(cipherSuites)*2)
	for _, c := range cipherSuites {
		cs = append(cs, byte(c>>8), byte(c))
	}

	extBytes := make([]byte, 0)
	for _, e := range exts {
		extBytes = append(extBytes, byte(e.typ>>8), byte(e.typ))
		extBytes = append(extBytes, byte(len(e.data)>>8), byte(len(e.data)))
		extBytes = append(extBytes, e.data...)
	}

	var extBlock []byte
	if len(extBytes) > 0 {
		extBlock = append([]byte{byte(len(extBytes) >> 8), byte(len(extBytes))}, extBytes...)
	}

	body := []byte{byte(helloVer >> 8), byte(helloVer)}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0x00)                // session_id length
	body = append(body, byte(len(cs)>>8), byte(len(cs)))
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // 1 compression method: null
	body = append(body, extBlock...)

	hsBody := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hsBody = append(hsBody, body...)

	rec := []byte{0x16, byte(recordVer >> 8), byte(recordVer), byte(len(hsBody) >> 8), byte(len(hsBody))}
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

func TestFingerprintExtensionData(t *testing.T) {
	// SNI (0x0000): list_len(2) + type(1=host_name) + name_len(2) + "test.com"
	sniData := []byte{
		0x00, 0x0b, // server_name_list_length = 11
		0x00,             // server_name_type: host_name
		0x00, 0x08,       // server_name_length = 8
		't', 'e', 's', 't', '.', 'c', 'o', 'm',
	}
	// supported_groups (0x000a): list_len(2) + groups
	groupsData := []byte{
		0x00, 0x04, // list length = 4
		0x00, 0x1d, // x25519
		0x00, 0x17, // secp256r1
	}
	// heartbeat (0x000f): NOT in extensionsToIncludeData — should appear as type only
	heartbeatData := []byte{0x01}

	data := synthClientHelloWithExts(0x0303, 0x0303, []uint16{0xc02b}, []extRaw{
		{typ: 0x0000, data: sniData},
		{typ: 0x000a, data: groupsData},
		{typ: 0x000f, data: heartbeatData},
	})
	fp := Fingerprint(data)
	if fp == "" {
		t.Fatal("expected non-empty fingerprint")
	}

	// SNI data must be embedded after its type code.
	sniHex := hex.EncodeToString(sniData)
	if !strings.Contains(fp, "(0000)("+sniHex+")") {
		t.Errorf("fingerprint missing SNI data; fingerprint=%q sniHex=%q", fp, sniHex)
	}

	// supported_groups data must be embedded.
	groupsHex := hex.EncodeToString(groupsData)
	if !strings.Contains(fp, "(000a)("+groupsHex+")") {
		t.Errorf("fingerprint missing supported_groups data; fingerprint=%q groupsHex=%q", fp, groupsHex)
	}

	// heartbeat extension type must appear.
	if !strings.Contains(fp, "(000f)") {
		t.Errorf("fingerprint missing heartbeat extension type: %q", fp)
	}
	// heartbeat data must NOT be included as a separate token.
	heartbeatHex := hex.EncodeToString(heartbeatData)
	if strings.Contains(fp, "(000f)("+heartbeatHex+")") {
		t.Errorf("heartbeat data should not be included in fingerprint: %q", fp)
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

func TestDBLookupPrevalence(t *testing.T) {
	// "minor" appears first in JSON but has lower prevalence — Lookup must return "dominant".
	const testDB = `{
		"(0303)(0303)[(c02b)][(0000)]": {
			"process_info": [
				{"process": "minor",    "prevalence": 0.1},
				{"process": "dominant", "prevalence": 0.9}
			]
		}
	}`
	db := NewDB()
	if err := db.LoadReader(strings.NewReader(testDB)); err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	pi, ok := db.Lookup("(0303)(0303)[(c02b)][(0000)]")
	if !ok {
		t.Fatal("expected hit")
	}
	if pi.Process != "dominant" {
		t.Errorf("Lookup should return highest-prevalence process; got %q (prevalence=%.2f)", pi.Process, pi.Prevalence)
	}
}

func TestDBLookupAll(t *testing.T) {
	const testDB = `{
		"(0303)(0303)[(c02b)][(0000)]": {
			"process_info": [
				{"process": "low",  "prevalence": 0.1},
				{"process": "high", "prevalence": 0.8},
				{"process": "mid",  "prevalence": 0.5}
			]
		}
	}`
	db := NewDB()
	if err := db.LoadReader(strings.NewReader(testDB)); err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	all := db.LookupAll("(0303)(0303)[(c02b)][(0000)]")
	if len(all) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(all))
	}
	// Must be sorted by decreasing prevalence.
	for i := 1; i < len(all); i++ {
		if all[i].Prevalence > all[i-1].Prevalence {
			t.Errorf("LookupAll not sorted by decreasing prevalence at index %d: %.2f > %.2f",
				i, all[i].Prevalence, all[i-1].Prevalence)
		}
	}
	if all[0].Process != "high" {
		t.Errorf("first entry should be 'high', got %q", all[0].Process)
	}

	// Miss returns nil, not an empty slice.
	if got := db.LookupAll("nonexistent"); got != nil {
		t.Errorf("expected nil for unknown fingerprint, got %v", got)
	}
}

func TestDBCountMultiple(t *testing.T) {
	const testDB = `{
		"fp1": {"process_info": [{"process": "a", "prevalence": 1.0}]},
		"fp2": {"process_info": [{"process": "b", "prevalence": 1.0}]},
		"fp3": {"process_info": [{"process": "c", "prevalence": 1.0}]}
	}`
	db := NewDB()
	if err := db.LoadReader(strings.NewReader(testDB)); err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if db.Count() != 3 {
		t.Errorf("expected Count()=3, got %d", db.Count())
	}
}

func TestDBLoadInvalidJSON(t *testing.T) {
	db := NewDB()
	if err := db.LoadReader(strings.NewReader(`not json`)); err == nil {
		t.Error("expected error on invalid JSON, got nil")
	}
	// Truncated value should also fail.
	if err := db.LoadReader(strings.NewReader(`{"fp": {`)); err == nil {
		t.Error("expected error on truncated JSON, got nil")
	}
}
