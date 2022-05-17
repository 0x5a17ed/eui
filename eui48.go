// Copyright (c) 2022 individual contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// <https://www.apache.org/licenses/LICENSE-2.0>
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package eui

import (
	"errors"
	"net"
)

var ErrInvalidMAC = errors.New("invalid hardware address")

// A EUI48 represents a 64 bit wide extended unique identifier.
type EUI48 [6]byte

func (i EUI48) Hex() string    { return encodeHex(i[:]) }
func (i EUI48) String() string { return i.Encode(1, ':') }

// Encode encodes the given EUI48 address in the specified format.
func (i EUI48) Encode(groupSize int, delimiter byte) string {
	return encodeGrouped(i[:], groupSize, delimiter)
}

// ParseEUI48FromMAC parses an EUI-48 or EUI-64 address and returns the EUI48 address.
func ParseEUI48FromMAC(mac net.HardwareAddr) (out EUI48, err error) {
	switch bits := len(mac) * 8; {
	case bits == 48: // EUI-48.
		copy(out[:], mac[:])
	case bits == 64 && mac[3] == 0xff && mac[4] == 0xfe:
		copy(out[0:3], mac[0:3])
		copy(out[3:6], mac[5:8])
		out[0] ^= 0x02

	default:
		err = ErrInvalidMAC
	}
	return
}

func MustEUI48(out EUI48, err error) EUI48 {
	if err != nil {
		panic(err.Error())
	}
	return out
}
