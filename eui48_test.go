package eui

import (
	"fmt"
	"net"
	"testing"

	assertpkg "github.com/stretchr/testify/assert"
)

func TestEUI64_Encode(t *testing.T) {
	type args struct {
		eui       EUI48
		groupSize int
		delimiter byte
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{"2.", args{EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 2, '.'}, "1234.5152.6789"},
		{"1.", args{EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, '.'}, "12.34.51.52.67.89"},
		{"1-", args{EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, '-'}, "12-34-51-52-67-89"},
		{"1:", args{EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, 1, ':'}, "12:34:51:52:67:89"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.eui.Encode(tt.args.groupSize, tt.args.delimiter)
			assertpkg.Equalf(t, tt.want, got, "Encode(%v, %v)", tt.args.groupSize, tt.args.delimiter)
		})
	}
}

func assertIsError(wantedErr error, msgAndArgs ...any) assertpkg.ErrorAssertionFunc {
	return func(t assertpkg.TestingT, err error, i ...interface{}) bool {
		return assertpkg.ErrorIs(t, err, wantedErr, msgAndArgs...)
	}
}

func TestParseMAC(t *testing.T) {
	tests := []struct {
		name    string
		inp     net.HardwareAddr
		wantOut string
		wantErr assertpkg.ErrorAssertionFunc
	}{
		{"EUI-48", net.HardwareAddr{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, "12:34:51:52:67:89", assertpkg.NoError},
		{"EUI-48-in-64", net.HardwareAddr{0x02, 0x15, 0x2b, 0xff, 0xfe, 0xe4, 0x9b, 0x60}, "00:15:2b:e4:9b:60", assertpkg.NoError},
		{"EUI-64", net.HardwareAddr{0x9c, 0xfe, 0x7a, 0xec, 0x19, 0x6e, 0xa6, 0x67}, "00:00:00:00:00:00", assertIsError(ErrInvalidMAC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOut, err := ParseEUI48FromMAC(tt.inp)
			if !tt.wantErr(t, err, fmt.Sprintf("ParseEUI48FromMAC(%v)", tt.inp)) {
				return
			}
			assertpkg.Equalf(t, tt.wantOut, gotOut.String(), "ParseEUI48FromMAC(%v)", tt.inp)
		})
	}
}

func TestEUI48_Hex(t *testing.T) {
	tests := []struct {
		name string
		i    EUI48
		want string
	}{
		// TODO: Add test cases.
		{"1:", EUI48{0x12, 0x34, 0x51, 0x52, 0x67, 0x89}, "123451526789"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertpkg.Equalf(t, tt.want, tt.i.Hex(), "Hex()")
		})
	}
}
