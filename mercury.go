// Package mercury provides a Go implementation of Cisco Mercury TLS application
// fingerprinting. It computes Network Protocol Fingerprints (NPF) from TLS
// ClientHello messages and looks them up in the Mercury fingerprint database to
// identify the sending application (e.g. "firefox", "curl", "python-requests").
//
// Fingerprint format: Based on the NPF specification by Cisco Mercury.
// Reference: https://github.com/cisco/mercury/blob/master/doc/npf.md
package mercury

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// greaseValues is the set of GREASE TLS values (RFC 8701) that must be filtered
// from cipher suites, extension types, and supported groups.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

// extensionsToNormalize lists the extension types whose data is replaced with
// a normalized representation (the raw bytes) in the fingerprint. Extensions
// not in this list appear only as their type code.
// Following Mercury's approach: include raw data for extensions that carry
// meaningful variation across implementations.
var extensionsToIncludeData = map[uint16]bool{
	0x0000: true, // server_name (include full data)
	0x000a: true, // supported_groups
	0x000b: true, // ec_point_formats
	0x000d: true, // signature_algorithms
	0x0010: true, // application_layer_protocol_negotiation (ALPN)
	0x001b: true, // compress_certificate
	0x002b: true, // supported_versions
	0x002d: true, // psk_key_exchange_modes
	0x0033: true, // key_share
	0x0012: true, // signed_certificate_timestamp
	0x0015: true, // padding (include so padding size is visible)
}

// Fingerprint computes a Mercury-style TLS fingerprint from a raw TLS record
// starting with the ContentType byte (must be 0x16 for handshake).
// Returns "" when the input is not a valid TLS ClientHello.
func Fingerprint(data []byte) string {
	ch, ok := parseClientHello(data)
	if !ok {
		return ""
	}
	return formatFingerprint(ch)
}

type clientHelloFields struct {
	recordVersion uint16
	helloVersion  uint16
	cipherSuites  []uint16
	extensions    []extension
}

type extension struct {
	typ  uint16
	data []byte
}

// parseClientHello extracts the fields needed for fingerprinting from raw
// TLS record bytes (starting at the ContentType byte).
func parseClientHello(b []byte) (clientHelloFields, bool) {
	var ch clientHelloFields

	// TLS record header: ContentType(1) + Version(2) + Length(2)
	if len(b) < 5 {
		return ch, false
	}
	if b[0] != 0x16 { // ContentType: handshake
		return ch, false
	}
	ch.recordVersion = binary.BigEndian.Uint16(b[1:3])

	// Handshake header: HandshakeType(1) + Length(3)
	hs := b[5:]
	if len(hs) < 4 {
		return ch, false
	}
	if hs[0] != 0x01 { // HandshakeType: client_hello
		return ch, false
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	hs = hs[4:]
	if len(hs) < hsLen {
		return ch, false
	}
	hs = hs[:hsLen]

	// ClientHello body: Version(2) + Random(32) + SessionID(1+N)
	if len(hs) < 2 {
		return ch, false
	}
	ch.helloVersion = binary.BigEndian.Uint16(hs[:2])
	hs = hs[2:]

	// Skip Random (32 bytes)
	if len(hs) < 32 {
		return ch, false
	}
	hs = hs[32:]

	// Skip SessionID
	if len(hs) < 1 {
		return ch, false
	}
	sidLen := int(hs[0])
	hs = hs[1:]
	if len(hs) < sidLen {
		return ch, false
	}
	hs = hs[sidLen:]

	// Cipher suites: Length(2) + CipherSuites(N*2)
	if len(hs) < 2 {
		return ch, false
	}
	csLen := int(binary.BigEndian.Uint16(hs[:2]))
	hs = hs[2:]
	if len(hs) < csLen || csLen%2 != 0 {
		return ch, false
	}
	for i := 0; i < csLen; i += 2 {
		cs := binary.BigEndian.Uint16(hs[i : i+2])
		if !greaseValues[cs] {
			ch.cipherSuites = append(ch.cipherSuites, cs)
		}
	}
	hs = hs[csLen:]

	// Skip compression methods
	if len(hs) < 1 {
		return ch, true // no extensions — still a valid fingerprint
	}
	compLen := int(hs[0])
	hs = hs[1:]
	if len(hs) < compLen {
		return ch, true
	}
	hs = hs[compLen:]

	// Extensions: ExtensionsLength(2) + extensions
	if len(hs) < 2 {
		return ch, true
	}
	extTotalLen := int(binary.BigEndian.Uint16(hs[:2]))
	hs = hs[2:]
	if len(hs) < extTotalLen {
		return ch, true
	}
	hs = hs[:extTotalLen]

	for len(hs) >= 4 {
		extType := binary.BigEndian.Uint16(hs[:2])
		extLen := int(binary.BigEndian.Uint16(hs[2:4]))
		hs = hs[4:]
		if len(hs) < extLen {
			break
		}
		extData := hs[:extLen]
		hs = hs[extLen:]

		if !greaseValues[extType] {
			ch.extensions = append(ch.extensions, extension{typ: extType, data: extData})
		}
	}

	return ch, true
}

// formatFingerprint serializes a parsed ClientHello into the Mercury NPF
// string representation for TLS.
//
// Format: (record_version)(hello_version)[(cs1)(cs2)...][(ext1)(ext2)...]
// where each element is a 4-character hex string in parentheses.
func formatFingerprint(ch clientHelloFields) string {
	var sb strings.Builder

	// Protocol version fields
	sb.WriteByte('(')
	sb.WriteString(fmt.Sprintf("%04x", ch.recordVersion))
	sb.WriteByte(')')
	sb.WriteByte('(')
	sb.WriteString(fmt.Sprintf("%04x", ch.helloVersion))
	sb.WriteByte(')')

	// Cipher suites
	sb.WriteByte('[')
	for _, cs := range ch.cipherSuites {
		sb.WriteByte('(')
		sb.WriteString(fmt.Sprintf("%04x", cs))
		sb.WriteByte(')')
	}
	sb.WriteByte(']')

	// Extensions
	sb.WriteByte('[')
	for _, ext := range ch.extensions {
		sb.WriteByte('(')
		sb.WriteString(fmt.Sprintf("%04x", ext.typ))
		sb.WriteByte(')')
		if extensionsToIncludeData[ext.typ] && len(ext.data) > 0 {
			sb.WriteByte('(')
			sb.WriteString(hex.EncodeToString(ext.data))
			sb.WriteByte(')')
		}
	}
	sb.WriteByte(']')

	return sb.String()
}
