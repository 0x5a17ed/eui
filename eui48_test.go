package eui_test

import (
	"fmt"
	"net"
	"testing"

	assertpkg "github.com/stretchr/testify/assert"

	"github.com/0x5a17ed/eui"
)

func assertIsError(wantedErr error) assertpkg.ErrorAssertionFunc {
	return func(t assertpkg.TestingT, err error, msgAndArgs ...any) bool {
		return assertpkg.ErrorIs(t, err, wantedErr, msgAndArgs...)
	}
}

func assertIsAddrError(wantedErr string) assertpkg.ErrorAssertionFunc {
	return func(t assertpkg.TestingT, err error, msgAndArgs ...any) bool {
		var addrError *net.AddrError
		if !assertpkg.Error(t, err) {
			return false
		}

		if !assertpkg.ErrorAs(t, err, &addrError) {
			return false
		}

		return assertpkg.Equal(t, wantedErr, addrError.Err)
	}
}

func TestParseMAC(t *testing.T) {
	tests := []struct {
		name    string
		inp     net.HardwareAddr
		wantOut string
		wantErr assertpkg.ErrorAssertionFunc
	}{
		{"EUI-48", net.HardwareAddr{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, "12-34-51-52-67-89", assertpkg.NoError},
		{"EUI-48-in-64", net.HardwareAddr{0x02, 0x15, 0x2b, 0xff, 0xfe, 0xe4, 0x9b, 0x60}, "00-15-2b-e4-9b-60", assertpkg.NoError},
		{"EUI-64", net.HardwareAddr{0x9c, 0xfe, 0x7a, 0xec, 0x19, 0x6e, 0xa6, 0x67}, "00-00-00-00-00-00", assertIsError(eui.ErrInvalidInput)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := eui.ParseEUI48FromHWAddr(tt.inp)
			if !tt.wantErr(t, err, fmt.Sprintf("ParseEUI48FromHWAddr(%v)", tt.inp)) {
				return
			}
			assertpkg.Equalf(t, tt.wantOut, gotOut.String(), "ParseEUI48FromHWAddr(%v)", tt.inp)
		})
	}
}

func TestEUI64_Encode(t *testing.T) {
	type args struct {
		eui       eui.EUI48
		groupSize int
		delimiter byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"2.", args{eui.EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 2, '.'}, "1234.5152.6789"},
		{"1.", args{eui.EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, '.'}, "12.34.51.52.67.89"},
		{"1-", args{eui.EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, '-'}, "12-34-51-52-67-89"},
		{"1:", args{eui.EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, ':'}, "12:34:51:52:67:89"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.eui.Encode(tt.args.groupSize, tt.args.delimiter)
			assertpkg.Equalf(t, tt.want, got, "Encode(%v, %v)", tt.args.groupSize, tt.args.delimiter)
		})
	}
}

func TestEUI48_Hex(t *testing.T) {
	tests := []struct {
		name string
		i    eui.EUI48
		want string
	}{
		{"1:", eui.EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, "123451526789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertpkg.Equalf(t, tt.want, tt.i.Hex(), "Hex()")
		})
	}
}

func TestEUI48_UnmarshalText(t *testing.T) {
	tt := []struct {
		name    string
		inp     []byte
		want    eui.EUI48
		wantErr assertpkg.ErrorAssertionFunc
	}{
		{"null", nil, eui.EUI48{}, assertIsAddrError("invalid MAC address")},
		{"empty", []byte{}, eui.EUI48{}, assertIsAddrError("invalid MAC address")},

		{"ip address",
			[]byte("192.168.1.1"),
			eui.EUI48{},
			assertIsAddrError("invalid MAC address")},

		{"mac address",
			[]byte("d6:c9:8a:d8:41:45"),
			eui.EUI48{0xd6, 0xc9, 0x8a, 0xd8, 0x41, 0x45},
			assertpkg.NoError},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			var out eui.EUI48
			err := out.UnmarshalText(tc.inp)
			if !tc.wantErr(t, err, fmt.Sprintf("UnmarshalText(%v)", tc.inp)) {
				return
			}
			assertpkg.Equal(t, tc.want, out)
		})
	}
}

func TestEUI48_MarshalText(t *testing.T) {
	inp := eui.EUI48{0xd6, 0xc9, 0x8a, 0xd8, 0x41, 0x45}

	out, err := inp.MarshalText()
	if !assertpkg.NoError(t, err) {
		return
	}

	assertpkg.Equal(t, []byte(`d6-c9-8a-d8-41-45`), out)
}
