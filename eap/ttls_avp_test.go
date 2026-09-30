package eap

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Inner PAP identity/password shared by the EAP-TTLS tests.
const (
	testUserName = "alice"
	testPassword = "s3cret"
)

// encodeVendorAVP builds one vendor-specific Diameter AVP (V flag set, with
// a 4-byte Vendor-Id ahead of data), padded to a 4-byte boundary. Unlike
// encodeAVP (Task 2's non-vendor helper), this is test-only scaffolding for
// proving ParsePapAVPs correctly skips vendor AVPs rather than misreading
// their Vendor-Id-prefixed data as a plain User-Name/User-Password value.
func encodeVendorAVP(code, vendorID uint32, data []byte) []byte {
	length := avpHeaderLen + 4 + len(data)
	out := make([]byte, avpHeaderLen)
	binary.BigEndian.PutUint32(out[0:4], code)
	out[4] = avpFlagVendor
	out[5] = byte(length >> 16 & 0xff)
	out[6] = byte(length >> 8 & 0xff)
	out[7] = byte(length & 0xff)
	vid := make([]byte, 4)
	binary.BigEndian.PutUint32(vid, vendorID)
	out = append(out, vid...)
	out = append(out, data...)
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out
}

func TestEncodeAVPPaddingAndLength(t *testing.T) {
	// User-Name = "ab" (2 bytes) → header 8 + data 2 = length 10, padded to 12.
	got := encodeAVP(avpCodeUserName, true, []byte("ab"))
	want := []byte{
		0x00, 0x00, 0x00, 0x01, // code = 1
		0x40, 0x00, 0x00, 0x0a, // flags M=0x40, length = 10
		'a', 'b', 0x00, 0x00, // data + 2 pad
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encodeAVP = %x, want %x", got, want)
	}
}

func TestParsePapAVPsRoundTrip(t *testing.T) {
	buf := append(encodeAVP(avpCodeUserName, true, []byte(testUserName)),
		encodeAVP(avpCodeUserPassword, true, []byte(testPassword))...)
	cred, err := ParsePapAVPs(buf)
	if err != nil {
		t.Fatalf("ParsePapAVPs error = %v", err)
	}
	if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
		t.Fatalf("got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}
}

// papPad replicates wpa_supplicant's RFC 5281 §11.2.2 PAP password padding:
// the User-Password is zero-padded to the next 16-octet boundary to obfuscate
// its length, and the AVP Length field counts the padding (eap_ttls.c).
func papPad(pw string) []byte {
	b := []byte(pw)
	pad := 16
	if len(b) != 0 {
		pad = (16 - (len(b) & 15)) & 15
	}
	return append(b, make([]byte, pad)...)
}

// TestParsePapAVPsStripsPasswordPadding proves a real supplicant's zero-padded
// User-Password (13-byte password -> 16-byte padded AVP value) is recovered as
// the original cleartext, not the padded bytes. Without stripping, credential
// verification against any compliant TTLS/PAP client fails.
func TestParsePapAVPsStripsPasswordPadding(t *testing.T) {
	const pw = "Twif@Test1234" // 13 bytes -> 3 NUL pad
	buf := append(encodeAVP(avpCodeUserName, true, []byte(testUserName)),
		encodeAVP(avpCodeUserPassword, true, papPad(pw))...)
	cred, err := ParsePapAVPs(buf)
	if err != nil {
		t.Fatalf("ParsePapAVPs error = %v", err)
	}
	if string(cred.UserPassword) != pw {
		t.Fatalf("UserPassword = %q, want %q (padding not stripped)", cred.UserPassword, pw)
	}
}

func TestParsePapAVPsMissingPassword(t *testing.T) {
	buf := encodeAVP(avpCodeUserName, true, []byte(testUserName))
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when User-Password AVP absent")
	}
}

// TestParsePapAVPsMissingUserName is the mirror of
// TestParsePapAVPsMissingPassword: User-Password present, User-Name absent.
func TestParsePapAVPsMissingUserName(t *testing.T) {
	buf := encodeAVP(avpCodeUserPassword, true, []byte(testPassword))
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when User-Name AVP absent")
	}
}

// TestParsePapAVPsSkipsVendorAVP proves a vendor-specific AVP (V flag set,
// with a Vendor-Id) is skipped wholesale rather than misread as a plain
// User-Name/User-Password value -- even when it reuses the User-Name AVP
// code, its Vendor-Id-prefixed data must never end up in cred.UserName.
func TestParsePapAVPsSkipsVendorAVP(t *testing.T) {
	buf := append(encodeVendorAVP(avpCodeUserName, 10415, []byte("trap")),
		append(encodeAVP(avpCodeUserName, true, []byte(testUserName)),
			encodeAVP(avpCodeUserPassword, true, []byte(testPassword))...)...)
	cred, err := ParsePapAVPs(buf)
	if err != nil {
		t.Fatalf("ParsePapAVPs error = %v", err)
	}
	if string(cred.UserName) != testUserName || string(cred.UserPassword) != testPassword {
		t.Fatalf("got name=%q pass=%q, vendor AVP was misparsed", cred.UserName, cred.UserPassword)
	}
}

// TestParsePapAVPsRejectsBadLength covers the length < avpHeaderLen and
// pos+length > len(b) guards (ttls_avp.go:56): AVP framing that is either
// self-declared shorter than the minimum header, or claims more bytes than
// the buffer actually has. Both are attacker-influenceable since this
// parses decrypted-but-untrusted inner tunnel data.
func TestParsePapAVPsRejectsBadLength(t *testing.T) {
	tests := map[string][]byte{
		"length below minimum header": {
			0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
			0x40, 0x00, 0x00, 0x04, // flags=M, length = 4 (< avpHeaderLen of 8)
		},
		"length exceeds buffer": {
			0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
			0x40, 0x00, 0x00, 0x14, // flags=M, length = 20, but buffer only has 8 bytes
		},
	}
	for name, buf := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePapAVPs(buf); err == nil {
				t.Fatal("expected error for malformed AVP length")
			}
		})
	}
}

// TestParsePapAVPsRejectsShortVendorAVP covers the dataStart > pos+length
// guard (ttls_avp.go:64): a vendor AVP (V flag set) whose declared length
// is long enough to pass the buffer-bounds check but too short to actually
// hold the 4-byte Vendor-Id the V flag promises.
func TestParsePapAVPsRejectsShortVendorAVP(t *testing.T) {
	buf := []byte{
		0x00, 0x00, 0x00, 0x01, // code = 1 (User-Name)
		0x80, 0x00, 0x00, 0x0a, // flags=V, length = 10 (header 8 + only 2 bytes, not enough for a 4-byte Vendor-Id)
		0xaa, 0xbb,
	}
	if _, err := ParsePapAVPs(buf); err == nil {
		t.Fatal("expected error when vendor AVP length can't hold its Vendor-Id")
	}
}

// encodeAVP builds one non-vendor Diameter AVP, padded to a 4-byte boundary.
// AVP Length counts the header + data but NOT the trailing padding.
func encodeAVP(code uint32, mandatory bool, data []byte) []byte {
	length := avpHeaderLen + len(data)
	out := make([]byte, avpHeaderLen)
	binary.BigEndian.PutUint32(out[0:4], code)
	if mandatory {
		out[4] = avpFlagMandatory
	}
	// 3-byte big-endian length in out[5:8].
	out[5] = byte(length >> 16 & 0xff)
	out[6] = byte(length >> 8 & 0xff)
	out[7] = byte(length & 0xff)
	out = append(out, data...)
	for len(out)%4 != 0 {
		out = append(out, 0x00)
	}
	return out
}

// TestParsePapAVPsRejectsUnsupportedMandatoryAVP: RFC 5281 Section 10.1 says an
// AVP whose M bit is set must be understood or the negotiation fails. Skipping
// it silently means the peer believes a requirement was honored when it was
// not even read.
func TestParsePapAVPsRejectsUnsupportedMandatoryAVP(t *testing.T) {
	pap := append(encodeAVP(avpCodeUserName, true, []byte(testUserName)),
		encodeAVP(avpCodeUserPassword, true, []byte(testPassword))...)

	unknownMandatory := encodeAVP(402, true, []byte("chap-challenge"))
	if _, err := ParsePapAVPs(append(unknownMandatory, pap...)); err == nil {
		t.Fatal("unsupported AVP with the M bit set was accepted")
	}

	vendorMandatory := encodeVendorAVP(avpCodeUserName, 10415, []byte("trap"))
	vendorMandatory[4] |= avpFlagMandatory
	if _, err := ParsePapAVPs(append(vendorMandatory, pap...)); err == nil {
		t.Fatal("mandatory vendor AVP was accepted")
	}

	unknownOptional := encodeAVP(402, false, []byte("chap-challenge"))
	if _, err := ParsePapAVPs(append(unknownOptional, pap...)); err != nil {
		t.Fatalf("optional unsupported AVP should be skipped, got %v", err)
	}
}

// TestParsePapAVPsRejectsDuplicateAVP: a later AVP silently overwrote an
// earlier one, so a peer could show one identity to anything that saw the
// first AVP and authenticate as the one in the last.
func TestParsePapAVPsRejectsDuplicateAVP(t *testing.T) {
	name := encodeAVP(avpCodeUserName, true, []byte(testUserName))
	pass := encodeAVP(avpCodeUserPassword, true, []byte(testPassword))

	dupName := append(append(append([]byte(nil), name...), name...), pass...)
	if _, err := ParsePapAVPs(dupName); err == nil {
		t.Fatal("duplicate User-Name was accepted")
	}

	dupPass := append(append(append([]byte(nil), name...), pass...), pass...)
	if _, err := ParsePapAVPs(dupPass); err == nil {
		t.Fatal("duplicate User-Password was accepted")
	}
}

// TestParsePapAVPsAcceptsEmptyValues: an empty value used to be
// indistinguishable from an absent AVP, because the parser marked "seen" by
// the field being non-nil and copying an empty value yields nil. A peer
// sending a User-Password of 16 zero octets (an empty password padded per
// RFC 5281 Section 11.2.2) therefore read as an incomplete stream, so the
// terminator re-prompted and failed instead of handing the caller a
// credential to reject. Whether an empty value is acceptable is the caller's
// decision, not the parser's.
func TestParsePapAVPsAcceptsEmptyValues(t *testing.T) {
	name := encodeAVP(avpCodeUserName, true, []byte(testUserName))
	pass := encodeAVP(avpCodeUserPassword, true, []byte(testPassword))

	emptyPass := encodeAVP(avpCodeUserPassword, true, make([]byte, 16))
	cred, err := ParsePapAVPs(append(append([]byte(nil), name...), emptyPass...))
	if err != nil {
		t.Fatalf("empty password: ParsePapAVPs error = %v", err)
	}
	if string(cred.UserName) != testUserName || len(cred.UserPassword) != 0 {
		t.Fatalf("empty password: got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}

	emptyName := encodeAVP(avpCodeUserName, true, nil)
	cred, err = ParsePapAVPs(append(append([]byte(nil), emptyName...), pass...))
	if err != nil {
		t.Fatalf("empty User-Name: ParsePapAVPs error = %v", err)
	}
	if len(cred.UserName) != 0 || string(cred.UserPassword) != testPassword {
		t.Fatalf("empty User-Name: got name=%q pass=%q", cred.UserName, cred.UserPassword)
	}

	// The duplicate check must see the empty AVP too, otherwise a peer can
	// hide a second identity behind an empty first one.
	shadowed := append(append(append([]byte(nil), emptyName...), name...), pass...)
	if _, err = ParsePapAVPs(shadowed); err == nil {
		t.Fatal("a User-Name after an empty User-Name was accepted")
	}
}
