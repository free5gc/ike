package eap

import (
	"bytes"
	"encoding/binary"

	"github.com/pkg/errors"
)

// Inner Diameter AVP codes carried in the EAP-TTLS tunnel (RFC 5281 §11, PAP).
const (
	avpCodeUserName     uint32 = 1
	avpCodeUserPassword uint32 = 2
)

const (
	avpFlagVendor    byte = 0x80
	avpFlagMandatory byte = 0x40
	avpHeaderLen          = 8 // no vendor id
)

// errPapAVPsIncomplete reports that the stream parsed cleanly as far as it
// goes but does not yet hold both PAP AVPs, so the caller should collect more
// tunneled bytes rather than fail the authentication.
var errPapAVPsIncomplete = errors.New("ParsePapAVPs: incomplete AVP stream")

// PapCredential holds the cleartext PAP inner identity/password.
type PapCredential struct {
	UserName     []byte
	UserPassword []byte
}

// ParsePapAVPs scans a decrypted inner AVP stream and extracts the PAP
// User-Name and User-Password AVPs. Vendor-specific AVPs are skipped.
//
// A stream that is well-formed but stops short -- a trailing partial AVP, or
// only one of the two PAP AVPs -- yields errPapAVPsIncomplete, because the
// tunnel is a byte stream and the rest may still be on its way. Only a stream
// that cannot be valid whatever follows is a hard error.
//
// An AVP that carries an empty value is present, not missing: whether an
// empty identity or password is acceptable is the caller's decision. Presence
// is therefore tracked separately from the value, which for an empty AVP is a
// zero-length slice.
func ParsePapAVPs(b []byte) (*PapCredential, error) {
	cred := &PapCredential{}
	var sawUserName, sawUserPassword bool
	pos := 0
	for pos+avpHeaderLen <= len(b) {
		code := binary.BigEndian.Uint32(b[pos : pos+4])
		flags := b[pos+4]
		length := int(b[pos+5])<<16 | int(b[pos+6])<<8 | int(b[pos+7])
		if length < avpHeaderLen {
			return nil, errors.Errorf("ParsePapAVPs: bad AVP length %d at pos %d", length, pos)
		}
		if pos+length > len(b) {
			return nil, errPapAVPsIncomplete
		}
		dataStart := pos + avpHeaderLen
		if flags&avpFlagVendor != 0 {
			// Vendor AVP has an extra 4-byte Vendor-Id; skip its data wholesale.
			dataStart += 4
		}
		if dataStart > pos+length {
			return nil, errors.Errorf("ParsePapAVPs: header overruns AVP length at pos %d", pos)
		}
		data := b[dataStart : pos+length]
		known := flags&avpFlagVendor == 0 &&
			(code == avpCodeUserName || code == avpCodeUserPassword)
		if !known {
			// RFC 5281 Section 10.1: an AVP the receiver does not understand
			// must be rejected when its M bit is set, and may be ignored
			// otherwise. A vendor AVP is never one of the two PAP AVPs, even
			// when it reuses their code.
			if flags&avpFlagMandatory != 0 {
				return nil, errors.Errorf(
					"ParsePapAVPs: unsupported mandatory AVP code %d at pos %d", code, pos)
			}
		} else {
			switch code {
			case avpCodeUserName:
				if sawUserName {
					return nil, errors.Errorf("ParsePapAVPs: duplicate User-Name AVP at pos %d", pos)
				}
				sawUserName = true
				cred.UserName = append([]byte{}, data...)
			case avpCodeUserPassword:
				if sawUserPassword {
					return nil, errors.Errorf("ParsePapAVPs: duplicate User-Password AVP at pos %d", pos)
				}
				sawUserPassword = true
				// RFC 5281 §11.2.2: the PAP password is zero-padded to a
				// 16-octet boundary to obfuscate its length, and the AVP
				// Length counts the padding. Strip trailing NULs to recover
				// the cleartext (a text password never ends in NUL).
				cred.UserPassword = append([]byte{}, bytes.TrimRight(data, "\x00")...)
			}
		}
		// Advance to next 4-byte-aligned AVP.
		pos += length
		for pos%4 != 0 {
			pos++
		}
	}
	if !sawUserName || !sawUserPassword {
		return nil, errPapAVPsIncomplete
	}
	return cred, nil
}
