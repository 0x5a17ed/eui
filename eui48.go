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
	"net"
)

// A EUI48 represents a 64 bit wide extended unique identifier.
type EUI48 [6]byte

func (i *EUI48) UnmarshalText(text []byte) error {
	return i.FillFromString(string(text))
}

func (i EUI48) MarshalText() ([]byte, error) {
	return []byte(i.String()), nil
}

func (i EUI48) Hex() string {
	return encodeHex(i[:])
}

func (i EUI48) String() string {
	return i.Encode(1, '-')
}

// Encode encodes the given EUI48 address in the specified format.
func (i EUI48) Encode(groupSize int, delimiter byte) string {
	return encodeGrouped(i[:], groupSize, delimiter)
}

func (i *EUI48) FillFromString(s string) error {
	hwAddr, err := net.ParseMAC(s)
	if err != nil {
		return err
	}
	return i.FillFromHWAddr(hwAddr)
}

// FillFromHWAddr parses an EUI-48 or EUI-64 address and returns the EUI48 address.
func (i *EUI48) FillFromHWAddr(hwAddr net.HardwareAddr) error {
	switch bits := len(hwAddr) * 8; {
	case bits == 48: // EUI-48.
		copy(i[:], hwAddr[:])
	case bits == 64 && hwAddr[3] == 0xff && hwAddr[4] == 0xfe:
		copy(i[0:3], hwAddr[0:3])
		copy(i[3:6], hwAddr[5:8])
		i[0] ^= 0x02

	default:
		return ErrInvalidInput
	}
	return nil
}

func ParseEUI48FromHWAddr(hwaddr net.HardwareAddr) (out EUI48, err error) {
	err = out.FillFromHWAddr(hwaddr)
	return
}

func MustEUI48(out EUI48, err error) EUI48 {
	if err != nil {
		panic(err.Error())
	}
	return out
}
