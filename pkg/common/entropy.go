// Copyright (C) 2024  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package common

import (
	"fmt"
	"math/bits"
)

// BitDistribution describes the probability of bit 0 and bit 1 in a byte array.
type BitDistribution struct {
	Bit0      float64
	Bit1      float64
	Bit0Count int
	Bit1Count int
}

func (bd BitDistribution) String() string {
	return fmt.Sprintf("BitDistribution{Bit0=%f, Bit1=%f, Bit0Count=%d, Bit1Count=%d}", bd.Bit0, bd.Bit1, bd.Bit0Count, bd.Bit1Count)
}

// ToBitDistribution returns the BitDistribution from a byte array.
func ToBitDistribution(arr []byte) BitDistribution {
	if len(arr) == 0 {
		return BitDistribution{
			Bit0: 0.5,
			Bit1: 0.5,
		}
	}

	// Bit1Count is the total number of set bits of arr, which
	// math/bits.OnesCount8 computes for each byte with a single machine
	// instruction. Bit0Count is the number of remaining bits.
	bit1Count := 0
	for _, b := range arr {
		bit1Count += bits.OnesCount8(b)
	}
	bit0Count := len(arr)*8 - bit1Count
	total := float64(len(arr) * 8)
	return BitDistribution{
		Bit0:      float64(bit0Count) / total,
		Bit1:      float64(bit1Count) / total,
		Bit0Count: bit0Count,
		Bit1Count: bit1Count,
	}
}
