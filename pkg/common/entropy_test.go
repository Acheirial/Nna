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
	"bytes"
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
)

func TestToBitDistribution(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected BitDistribution
	}{
		{
			name:     "empty slice",
			input:    []byte{},
			expected: BitDistribution{Bit0: 0.5, Bit1: 0.5, Bit0Count: 0, Bit1Count: 0},
		},
		{
			name:     "all zeros",
			input:    []byte{0x00, 0x00},
			expected: BitDistribution{Bit0: 1.0, Bit1: 0.0, Bit0Count: 16, Bit1Count: 0},
		},
		{
			name:     "all ones",
			input:    []byte{0xFF, 0xFF},
			expected: BitDistribution{Bit0: 0.0, Bit1: 1.0, Bit0Count: 0, Bit1Count: 16},
		},
		{
			name:     "mixed 1",
			input:    []byte{0xF0, 0x0F},
			expected: BitDistribution{Bit0: 0.5, Bit1: 0.5, Bit0Count: 8, Bit1Count: 8},
		},
		{
			name:     "mixed 2",
			input:    []byte{0xA0, 0x05},
			expected: BitDistribution{Bit0: 0.75, Bit1: 0.25, Bit0Count: 12, Bit1Count: 4},
		},
		{
			name:     "mixed 3",
			input:    []byte{0xFC, 0x3F},
			expected: BitDistribution{Bit0: 0.25, Bit1: 0.75, Bit0Count: 4, Bit1Count: 12},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToBitDistribution(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("TestToBitDistribution(%v) = %v, want %v", tt.name, result, tt.expected)
			}
		})
	}
}

// toBitDistributionSlow is the previous implementation of ToBitDistribution,
// which walks the bits of every byte one by one. It is kept in the test as the
// reference of the optimized implementation.
func toBitDistributionSlow(arr []byte) BitDistribution {
	if len(arr) == 0 {
		return BitDistribution{
			Bit0: 0.5,
			Bit1: 0.5,
		}
	}

	var bit0Count, bit1Count float64
	for _, b := range arr {
		for i := range 8 {
			if (b>>i)&1 == 0 {
				bit0Count++
			} else {
				bit1Count++
			}
		}
	}
	return BitDistribution{
		Bit0:      bit0Count / float64(len(arr)*8),
		Bit1:      bit1Count / float64(len(arr)*8),
		Bit0Count: int(bit0Count),
		Bit1Count: int(bit1Count),
	}
}

// TestToBitDistributionMatchesSlowImplementation verifies that ToBitDistribution
// returns exactly the same BitDistribution as the previous bit by bit
// implementation, including the probability arithmetic and the empty input
// special case.
func TestToBitDistributionMatchesSlowImplementation(t *testing.T) {
	testcases := []struct {
		name  string
		input []byte
	}{
		{"nil input", nil},
		{"empty input", []byte{}},
		{"single byte 0x00", []byte{0x00}},
		{"single byte 0xFF", []byte{0xFF}},
		{"single byte 0x80", []byte{0x80}},
		{"all zero bits", make([]byte, 257)},
		{"all one bits", bytes.Repeat([]byte{0xFF}, 257)},
		{"alternating bits", []byte{0xAA, 0x55, 0xAA, 0x55}},
		{"printable ASCII", []byte("shadowlemon padding data 0123456789 =~!")},
		{"one bit per byte", []byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := ToBitDistribution(tc.input)
			want := toBitDistributionSlow(tc.input)
			if got != want {
				t.Errorf("ToBitDistribution(%s) = %v, want %v", tc.name, got, want)
			}
			if got.Bit0Count+got.Bit1Count != len(tc.input)*8 {
				t.Errorf("ToBitDistribution(%s) counted %d and %d bits, want %d bits in total", tc.name, got.Bit0Count, got.Bit1Count, len(tc.input)*8)
			}
		})
	}

	// Every possible single byte must be counted the same way as well.
	for b := range 256 {
		input := []byte{byte(b)}
		if got, want := ToBitDistribution(input), toBitDistributionSlow(input); got != want {
			t.Fatalf("ToBitDistribution([%#x]) = %v, want %v", b, got, want)
		}
	}

	// Deterministic pseudo random inputs of several lengths, in particular
	// lengths around the 8 byte word boundaries.
	src := rand.New(rand.NewPCG(1, 2))
	for _, size := range []int{1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 255, 256, 257, 4096} {
		input := make([]byte, size)
		for i := range input {
			input[i] = byte(src.IntN(256))
		}
		got := ToBitDistribution(input)
		want := toBitDistributionSlow(input)
		if got != want {
			t.Fatalf("ToBitDistribution(input of %d bytes) = %v, want %v", size, got, want)
		}
		if got.Bit0Count+got.Bit1Count != size*8 {
			t.Fatalf("ToBitDistribution(input of %d bytes) counted %d bits, want %d", size, got.Bit0Count+got.Bit1Count, size*8)
		}
	}
}

// BenchmarkToBitDistribution measures the bit distribution computation, which
// runs on the plaintext of every message that is padded.
func BenchmarkToBitDistribution(b *testing.B) {
	src := rand.New(rand.NewPCG(3, 4))
	for _, size := range []int{64, 1024, 32768} {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(src.IntN(256))
		}
		b.Run(fmt.Sprintf("%d bytes", size), func(b *testing.B) {
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var dist BitDistribution
			for range b.N {
				dist = ToBitDistribution(buf)
			}
			// Make sure the loop above is not optimized away.
			if dist.Bit0+dist.Bit1 == 0 {
				b.Fatal("ToBitDistribution() returned an empty distribution")
			}
		})
	}
}
