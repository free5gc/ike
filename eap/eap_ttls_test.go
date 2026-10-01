package eap

import (
	"bytes"
	"testing"
)

func TestEapTtlsMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name string
		in   EapTtls
		// wire type-data bytes: [type=21][flags][optional len(4)][tls data]
		want []byte
	}{
		{
			name: "start packet, no length, no data",
			in:   EapTtls{Flags: EapTlsFlagStart},
			want: []byte{21, 0x20},
		},
		{
			name: "plain fragment, no length flag",
			in:   EapTtls{Flags: 0x00, TLSData: []byte{0xde, 0xad}},
			want: []byte{21, 0x00, 0xde, 0xad},
		},
		{
			name: "length included",
			in:   EapTtls{Flags: EapTlsFlagLengthIncluded, MessageLength: 2, TLSData: []byte{0xde, 0xad}},
			want: []byte{21, 0x80, 0x00, 0x00, 0x00, 0x02, 0xde, 0xad},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.in.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Marshal() = %x, want %x", got, tt.want)
			}
			var rt EapTtls
			if err = rt.Unmarshal(got); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			if rt.Flags != tt.in.Flags || rt.MessageLength != tt.in.MessageLength || !bytes.Equal(rt.TLSData, tt.in.TLSData) {
				t.Fatalf("roundtrip mismatch: got %+v want %+v", rt, tt.in)
			}
		})
	}
}

func TestEapTtlsUnmarshalRejectsWrongType(t *testing.T) {
	var e EapTtls
	if err := e.Unmarshal([]byte{50, 0x00}); err == nil {
		t.Fatal("expected error for non-TTLS type byte, got nil")
	}
}
