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

const hexTable = "0123456789abcdef"

func encodeBigEndian(dst, src []byte) {
	_ = dst[len(src)*2-1] // Bounds check hint to compiler.
	for i, j := 0, 0; i < len(src); i, j = i+1, j+2 {
		dst[j], dst[j+1] = hexTable[src[i]>>4], hexTable[src[i]&0x0f]
	}
}

func encodeGrouped(eui []byte, group int, delimiter byte) string {
	var buf [40]byte

	step := group*2 + 1
	encodeBigEndian(buf[:], eui[:group])
	for i, j := group, step; i < len(eui); i, j = i+group, j+step {
		encodeBigEndian(buf[j:], eui[i:i+group])
		buf[j-1] = delimiter
	}

	return string(buf[:len(eui)*2+(len(eui)-1)/group])
}

func encodeHex(eui []byte) string {
	dst := make([]byte, len(eui)*2)
	encodeBigEndian(dst, eui[:])
	return string(dst)
}
