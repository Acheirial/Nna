// Copyright (C) 2026  mieru authors
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

package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	"reflect"
	"testing"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/mathext"
)

var lowEntropyTestMasks = map[appctlpb.LowEntropyMode]uint32{
	appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32: 0x0f0f0f0f,
	appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40: 0x1f1f1f1f,
	appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48: 0x3f3f3f3f,
	appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56: 0x7f7f7f7f,
}

// lowEntropyFamilyMasks returns one half-mask per stride of the mode family,
// keyed by the number of plaintext bytes each 8 byte chunk carries. The masks
// use a byte aligned pattern, so a mask with n one-bits in every byte carries n
// plaintext bytes per chunk.
func lowEntropyFamilyMasks(t *testing.T, mode appctlpb.LowEntropyMode) map[int]uint32 {
	t.Helper()
	choices := halfMaskOnesChoices(mode)
	if len(choices) == 0 {
		t.Fatalf("halfMaskOnesChoices(%d) is empty", mode)
	}
	masks := make(map[int]uint32, len(choices))
	for _, ones := range choices {
		stride := ones / 4
		masks[stride] = uint32(0x01010101) * (uint32(1)<<stride - 1)
	}
	return masks
}

// lowEntropyStrideForTest returns the number of plaintext bytes each chunk
// carries with halfMask, exactly as the decoder derives it.
func lowEntropyStrideForTest(t *testing.T, mode appctlpb.LowEntropyMode, halfMask uint32) int {
	t.Helper()
	params, err := validateLowEntropyCodecParams(mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION)
	if err != nil {
		t.Fatalf("validateLowEntropyCodecParams(%d, %08x) failed: %v", mode, halfMask, err)
	}
	return params.sourceBytesPerChunk
}

func TestExtractLowEntropyConfig(t *testing.T) {
	tests := []struct {
		name         string
		pattern      *appctlpb.TrafficPattern
		wantMode     appctlpb.LowEntropyMode
		wantRotation appctlpb.LowEntropyMaskRotation
		wantEnabled  bool
	}{
		{
			name:         "nil pattern",
			wantMode:     appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF,
			wantRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION,
		},
		{
			name:         "nil low entropy pattern",
			pattern:      &appctlpb.TrafficPattern{},
			wantMode:     appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF,
			wantRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION,
		},
		{
			name: "explicit off",
			pattern: &appctlpb.TrafficPattern{LowEntropy: &appctlpb.LowEntropyPattern{
				Mode:         appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF.Enum(),
				MaskRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_7.Enum(),
			}},
			wantMode:     appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF,
			wantRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION,
		},
		{
			name: "enabled",
			pattern: &appctlpb.TrafficPattern{LowEntropy: &appctlpb.LowEntropyPattern{
				Mode:         appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48.Enum(),
				MaskRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3.Enum(),
			}},
			wantMode:     appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48,
			wantRotation: appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3,
			wantEnabled:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mode, rotation, enabled := extractLowEntropyConfig(test.pattern)
			if mode != test.wantMode || rotation != test.wantRotation || enabled != test.wantEnabled {
				t.Errorf("extractLowEntropyConfig() = (%v, %v, %v), want (%v, %v, %v)", mode, rotation, enabled, test.wantMode, test.wantRotation, test.wantEnabled)
			}
		})
	}
}

func TestBuildLowEntropyParams(t *testing.T) {
	tests := []struct {
		mode      appctlpb.LowEntropyMode
		sourceLen int
		maskOnes  int
		wantErr   bool
	}{
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, 0, 0, true},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, 4, 16, false},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40, 5, 20, false},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48, 6, 24, false},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, 7, 28, false},
		{appctlpb.LowEntropyMode(5), 0, 0, true},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("mode_%d", test.mode), func(t *testing.T) {
			got, err := buildLowEntropyParams(test.mode)
			if (err != nil) != test.wantErr {
				t.Fatalf("buildLowEntropyParams(%d) error = %v, wantErr %v", test.mode, err, test.wantErr)
			}
			if err == nil && (got.sourceBytesPerChunk != test.sourceLen || got.halfMaskOnes != test.maskOnes) {
				t.Errorf("buildLowEntropyParams(%d) = %+v, want source length %d and mask one-bits %d", test.mode, got, test.sourceLen, test.maskOnes)
			}
		})
	}
}

func TestLowEntropyEncodedPayloadLen(t *testing.T) {
	for mode, mask := range lowEntropyTestMasks {
		stride := lowEntropyStrideForTest(t, mode, mask)
		tests := []struct {
			extracted int
			want      uint16
			wantErr   bool
		}{
			{0, 0, true},
			{-1, 0, true},
			{1, 8, false},
			{stride, 8, false},
			{stride + 1, 16, false},
			{(math.MaxUint16 / lowEntropyChunkLen) * stride, (math.MaxUint16 / lowEntropyChunkLen) * lowEntropyChunkLen, false},
			{(math.MaxUint16/lowEntropyChunkLen)*stride + 1, 0, true},
			{math.MaxInt, 0, true},
		}
		for _, test := range tests {
			t.Run(fmt.Sprintf("mode_%d_len_%d", mode, test.extracted), func(t *testing.T) {
				got, err := lowEntropyEncodedPayloadLen(test.extracted, stride)
				if (err != nil) != test.wantErr {
					t.Fatalf("lowEntropyEncodedPayloadLen(%d, %d) error = %v, wantErr %v", test.extracted, stride, err, test.wantErr)
				}
				if got != test.want {
					t.Errorf("lowEntropyEncodedPayloadLen(%d, %d) = %d, want %d", test.extracted, stride, got, test.want)
				}
			})
		}
	}

	// Every stride of the mode family must be accepted, and the smallest stride
	// must produce the longest encoded payload: maxFragmentSize() budgets for
	// that worst case.
	for mode := range lowEntropyTestMasks {
		family := lowEntropyFamilyMasks(t, mode)
		minStride, err := lowEntropyMinStride(mode)
		if err != nil {
			t.Fatalf("lowEntropyMinStride(%d) failed: %v", mode, err)
		}
		const extracted = 4096
		minEncoded, err := lowEntropyEncodedPayloadLen(extracted, minStride)
		if err != nil {
			t.Fatalf("lowEntropyEncodedPayloadLen(%d, %d) failed: %v", extracted, minStride, err)
		}
		for stride, mask := range family {
			if got := lowEntropyStrideForTest(t, mode, mask); got != stride {
				t.Errorf("mode %d mask %08x carries %d bytes per chunk, want %d", mode, mask, got, stride)
			}
			encoded, err := lowEntropyEncodedPayloadLen(extracted, stride)
			if err != nil {
				t.Fatalf("lowEntropyEncodedPayloadLen(%d, %d) failed: %v", extracted, stride, err)
			}
			if encoded > minEncoded {
				t.Errorf("stride %d encodes %d bytes, more than the %d bytes of the smallest stride %d", stride, encoded, minEncoded, minStride)
			}
		}
	}

	for _, stride := range []int{-1, 0, lowEntropyChunkLen + 1} {
		if _, err := lowEntropyEncodedPayloadLen(1, stride); err == nil {
			t.Errorf("lowEntropyEncodedPayloadLen() accepted stride %d", stride)
		}
	}
	if _, err := lowEntropyNominalEncodedPayloadLen(1, appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF); err == nil {
		t.Error("lowEntropyNominalEncodedPayloadLen() accepted mode OFF")
	}
	nominal, err := lowEntropyNominalEncodedPayloadLen(8, appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32)
	if err != nil || nominal != 16 {
		t.Errorf("lowEntropyNominalEncodedPayloadLen(8, mode 32) = (%d, %v), want (16, nil)", nominal, err)
	}
}

func TestHalfMaskOnesChoices(t *testing.T) {
	tests := []struct {
		mode appctlpb.LowEntropyMode
		want []int
	}{
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, []int{12, 16, 20}},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40, []int{16, 20, 24}},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48, []int{20, 24, 28}},
		// 32 one-bits would leave no padding bit, so it is not offered.
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, []int{24, 28}},
	}
	for _, test := range tests {
		t.Run(test.mode.String(), func(t *testing.T) {
			got := halfMaskOnesChoices(test.mode)
			if !reflect.DeepEqual(got, test.want) {
				t.Errorf("halfMaskOnesChoices(%d) = %v, want %v", test.mode, got, test.want)
			}
			base, err := buildLowEntropyParams(test.mode)
			if err != nil {
				t.Fatal(err)
			}
			minStride, err := lowEntropyMinStride(test.mode)
			if err != nil {
				t.Fatalf("lowEntropyMinStride(%d) failed: %v", test.mode, err)
			}
			if minStride != base.sourceBytesPerChunk-1 {
				t.Errorf("lowEntropyMinStride(%d) = %d, want %d", test.mode, minStride, base.sourceBytesPerChunk-1)
			}
		})
	}
	for _, mode := range []appctlpb.LowEntropyMode{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMode(5)} {
		if got := halfMaskOnesChoices(mode); got != nil {
			t.Errorf("halfMaskOnesChoices(%d) = %v, want nil", mode, got)
		}
		if _, err := lowEntropyMinStride(mode); err == nil {
			t.Errorf("lowEntropyMinStride(%d) succeeded, want error", mode)
		}
	}
}

func TestLowEntropyRotations(t *testing.T) {
	legal := legalLowEntropyRotations()
	if len(legal) != 31 {
		t.Fatalf("legalLowEntropyRotations() returned %d values, want 31", len(legal))
	}
	for _, rotation := range legal {
		if !isValidLowEntropyRotation(rotation) {
			t.Errorf("rotation %d is rejected", rotation)
		}
	}
	for _, rotation := range []appctlpb.LowEntropyMaskRotation{-1, 17, 31, 241, 255, 256} {
		if isValidLowEntropyRotation(rotation) {
			t.Errorf("rotation %d is accepted", rotation)
		}
	}

	const initialMask = uint64(0x0f0f0f0f0f0f0f0f)
	tests := []struct {
		name       string
		rotation   appctlpb.LowEntropyMaskRotation
		chunkIndex int
		want       uint64
	}{
		{"unrotated_later_chunk", appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, 7, initialMask},
		{"right_4_first_chunk", appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_4, 0, initialMask},
		{"right_4_second_chunk", appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_4, 1, 0xf0f0f0f0f0f0f0f0},
		{"left_3_second_chunk", appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3, 1, 0x7878787878787878},
		{"left_3_third_chunk", appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3, 2, 0xc3c3c3c3c3c3c3c3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := lowEntropyChunkMask(initialMask, test.rotation, test.chunkIndex)
			if err != nil {
				t.Fatalf("lowEntropyChunkMask() failed: %v", err)
			}
			if got != test.want {
				t.Errorf("lowEntropyChunkMask() = %#016x, want %#016x", got, test.want)
			}
		})
	}
	if _, err := lowEntropyChunkMask(initialMask, appctlpb.LowEntropyMaskRotation(17), 0); err == nil {
		t.Error("lowEntropyChunkMask() accepted invalid rotation")
	}
	if _, err := lowEntropyChunkMask(initialMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, -1); err == nil {
		t.Error("lowEntropyChunkMask() accepted negative chunk index")
	}
}

func TestNewLowEntropyHalfMask(t *testing.T) {
	for mode := range lowEntropyTestMasks {
		choices := halfMaskOnesChoices(mode)
		if len(choices) == 0 {
			t.Fatalf("halfMaskOnesChoices(%d) is empty", mode)
		}
		seen := make(map[int]bool)
		for i := 0; i < 200; i++ {
			mask, err := newLowEntropyHalfMask(mode)
			if err != nil {
				t.Fatalf("newLowEntropyHalfMask(%d) failed: %v", mode, err)
			}
			ones := bits.OnesCount32(mask)
			if ones%4 != 0 {
				t.Fatalf("newLowEntropyHalfMask(%d) produced %d one-bits, want a multiple of 4", mode, ones)
			}
			if stride := lowEntropyStrideForTest(t, mode, mask); stride*4 != ones {
				t.Fatalf("newLowEntropyHalfMask(%d) produced %d one-bits and stride %d", mode, ones, stride)
			}
			found := false
			for _, choice := range choices {
				if ones == choice {
					found = true
				}
			}
			if !found {
				t.Fatalf("newLowEntropyHalfMask(%d) produced %d one-bits, want one of %v", mode, ones, choices)
			}
			seen[ones] = true
		}
		if len(seen) != len(choices) {
			t.Errorf("newLowEntropyHalfMask(%d) used %d of %d choices after 200 draws", mode, len(seen), len(choices))
		}
	}
	if _, err := newLowEntropyHalfMask(appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF); err == nil {
		t.Error("newLowEntropyHalfMask() accepted mode OFF")
	}
}

// TestEncodeLowEntropyPayloadPaddingBitIsRandom verifies that the production
// wrapper does not use a constant padding polarity.
func TestEncodeLowEntropyPayloadPaddingBitIsRandom(t *testing.T) {
	mode := appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32
	halfMask := lowEntropyTestMasks[mode]
	source := []byte{1, 2, 3, 4}
	seen := make(map[byte]bool)
	for i := 0; i < 200; i++ {
		encoded, err := encodeLowEntropyPayload(source, mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION)
		if err != nil {
			t.Fatalf("encodeLowEntropyPayload() failed: %v", err)
		}
		padding := encoded[0] &^ byte(0x0f)
		if padding != 0x00 && padding != 0xf0 {
			t.Fatalf("encoded padding bits = %#02x, want a uniform polarity", padding)
		}
		decoded, err := decodeLowEntropyPayload(encoded, len(source), mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION)
		if err != nil {
			t.Fatalf("decodeLowEntropyPayload() failed: %v", err)
		}
		if !bytes.Equal(decoded, source) {
			t.Fatal("decoded payload differs from source")
		}
		seen[padding/0xf0] = true
	}
	if len(seen) != 2 {
		t.Errorf("encodeLowEntropyPayload() used %d of 2 padding polarities after 200 draws", len(seen))
	}
}

func TestLowEntropyGoldenVector(t *testing.T) {
	source := []byte{0x12, 0x34, 0x56, 0x78}
	tests := []struct {
		paddingBit uint8
		want       []byte
	}{
		{0, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{1, []byte{0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8}},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("padding_%d", test.paddingBit), func(t *testing.T) {
			encoded, err := encodeLowEntropyPayloadWithPaddingBit(
				source,
				appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32,
				0x0f0f0f0f,
				appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION,
				test.paddingBit,
			)
			if err != nil {
				t.Fatalf("encodeLowEntropyPayloadWithPaddingBit() failed: %v", err)
			}
			if !bytes.Equal(encoded, test.want) {
				t.Fatalf("encoded bytes = % x, want % x", encoded, test.want)
			}
			decoded, err := decodeLowEntropyPayload(
				encoded,
				len(source),
				appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32,
				0x0f0f0f0f,
				appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION,
			)
			if err != nil {
				t.Fatalf("decodeLowEntropyPayload() failed: %v", err)
			}
			if !bytes.Equal(decoded, source) {
				t.Errorf("decoded bytes = % x, want % x", decoded, source)
			}
		})
	}
}

func TestLowEntropyRoundTrip(t *testing.T) {
	for mode := range lowEntropyTestMasks {
		for stride, halfMask := range lowEntropyFamilyMasks(t, mode) {
			lengths := []int{1, stride - 1, stride, stride + 1, stride*3 + 2, (math.MaxUint16 / lowEntropyChunkLen) * stride, 32764, 32768}
			for _, rotation := range legalLowEntropyRotations() {
				for _, sourceLen := range lengths {
					if _, err := lowEntropyEncodedPayloadLen(sourceLen, stride); err != nil {
						continue
					}
					source := lowEntropyTestPayload(sourceLen)
					for paddingBit := uint8(0); paddingBit <= 1; paddingBit++ {
						name := fmt.Sprintf("mode_%d_stride_%d_rotation_%d_len_%d_padding_%d", mode, stride, rotation, sourceLen, paddingBit)
						t.Run(name, func(t *testing.T) {
							encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, paddingBit)
							if err != nil {
								t.Fatalf("encodeLowEntropyPayloadWithPaddingBit() failed: %v", err)
							}
							assertLowEntropyPadding(t, encoded, sourceLen, mode, halfMask, rotation, paddingBit)
							decoded, err := decodeLowEntropyPayload(encoded, sourceLen, mode, halfMask, rotation)
							if err != nil {
								t.Fatalf("decodeLowEntropyPayload() failed: %v", err)
							}
							if !bytes.Equal(decoded, source) {
								t.Fatalf("decoded payload differs from source")
							}
						})
					}
				}
			}
		}
	}
}

// TestLowEntropyFullChunkMask covers a half-mask without a single padding bit.
// Such a message has no padding polarity to infer and no padding position to
// check, so the decoder accepts it even when the unused bits of the final
// partial chunk carry arbitrary values.
func TestLowEntropyFullChunkMask(t *testing.T) {
	mode := appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56
	halfMask := uint32(0xffffffff)
	if stride := lowEntropyStrideForTest(t, mode, halfMask); stride != lowEntropyChunkLen {
		t.Fatalf("full chunk mask carries %d bytes per chunk, want %d", stride, lowEntropyChunkLen)
	}
	for _, sourceLen := range []int{1, 7, 8, 9, 16, 32000} {
		source := lowEntropyTestPayload(sourceLen)
		t.Run(fmt.Sprintf("len_%d", sourceLen), func(t *testing.T) {
			for paddingBit := uint8(0); paddingBit <= 1; paddingBit++ {
				encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, paddingBit)
				if err != nil {
					t.Fatalf("encodeLowEntropyPayloadWithPaddingBit() failed: %v", err)
				}
				decoded, err := decodeLowEntropyPayload(encoded, sourceLen, mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION)
				if err != nil {
					t.Fatalf("decodeLowEntropyPayload() failed: %v", err)
				}
				if !bytes.Equal(decoded, source) {
					t.Fatal("decoded payload differs from source")
				}
			}
		})
	}

	// Arbitrary bits in the unused part of the final chunk must not be rejected.
	source := lowEntropyTestPayload(3)
	encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, 0)
	if err != nil {
		t.Fatalf("encodeLowEntropyPayloadWithPaddingBit() failed: %v", err)
	}
	binary.BigEndian.PutUint64(encoded, binary.BigEndian.Uint64(encoded)|^uint64(0xffffff))
	decoded, err := decodeLowEntropyPayload(encoded, len(source), mode, halfMask, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION)
	if err != nil {
		t.Fatalf("decodeLowEntropyPayload() rejected unused bits of a full chunk mask: %v", err)
	}
	if !bytes.Equal(decoded, source) {
		t.Fatal("decoded payload differs from source")
	}
}

func TestLowEntropyMalformedInputs(t *testing.T) {
	mode := appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32
	halfMask := lowEntropyTestMasks[mode]
	rotation := appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION
	source := []byte{0x12, 0x34, 0x56, 0x78, 0x9a}
	encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 0)
	if err != nil {
		t.Fatal(err)
	}

	encodeTests := []struct {
		name       string
		source     []byte
		mode       appctlpb.LowEntropyMode
		halfMask   uint32
		rotation   appctlpb.LowEntropyMaskRotation
		paddingBit uint8
	}{
		{"empty_source", nil, mode, halfMask, rotation, 0},
		{"mode_off", source, appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, halfMask, rotation, 0},
		{"wrong_mask_popcount", source, mode, halfMask ^ 1, rotation, 0},
		{"zero_mask", source, mode, 0, rotation, 0},
		{"mask_ones_not_a_multiple_of_4", source, mode, halfMask ^ 3, rotation, 0},
		{"stride_above_family", source, mode, 0x3f3f3f3f, rotation, 0},
		{"stride_below_family", source, appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, 0x07070707, rotation, 0},
		{"invalid_rotation", source, mode, halfMask, appctlpb.LowEntropyMaskRotation(17), 0},
		{"invalid_padding_bit", source, mode, halfMask, rotation, 2},
		{"encoded_length_overflow", make([]byte, 32765), mode, halfMask, rotation, 0},
	}
	for _, test := range encodeTests {
		t.Run("encode_"+test.name, func(t *testing.T) {
			if _, err := encodeLowEntropyPayloadWithPaddingBit(test.source, test.mode, test.halfMask, test.rotation, test.paddingBit); err == nil {
				t.Error("encodeLowEntropyPayloadWithPaddingBit() succeeded, want error")
			}
		})
	}

	decodeTests := []struct {
		name         string
		encoded      []byte
		extractedLen int
		mode         appctlpb.LowEntropyMode
		halfMask     uint32
		rotation     appctlpb.LowEntropyMaskRotation
	}{
		{"empty_extracted", encoded, 0, mode, halfMask, rotation},
		{"mode_off", encoded, len(source), appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, halfMask, rotation},
		{"wrong_mask_popcount", encoded, len(source), mode, halfMask ^ 1, rotation},
		{"zero_mask", encoded, len(source), mode, 0, rotation},
		{"mask_ones_not_a_multiple_of_4", encoded, len(source), mode, halfMask ^ 3, rotation},
		{"stride_above_family", encoded, len(source), mode, 0x3f3f3f3f, rotation},
		{"stride_below_family", encoded, len(source), appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, 0x07070707, rotation},
		{"invalid_rotation", encoded, len(source), mode, halfMask, appctlpb.LowEntropyMaskRotation(17)},
		{"short_encoded_body", encoded[:len(encoded)-1], len(source), mode, halfMask, rotation},
		{"long_encoded_body", append(append([]byte{}, encoded...), make([]byte, lowEntropyChunkLen)...), len(source), mode, halfMask, rotation},
	}
	for _, test := range decodeTests {
		t.Run("decode_"+test.name, func(t *testing.T) {
			if _, err := decodeLowEntropyPayload(test.encoded, test.extractedLen, test.mode, test.halfMask, test.rotation); err == nil {
				t.Error("decodeLowEntropyPayload() succeeded, want error")
			}
		})
	}
}

func TestLowEntropyRejectsNonCanonicalPadding(t *testing.T) {
	mode := appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32
	halfMask := lowEntropyTestMasks[mode]
	rotation := appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION
	initialMask := mathext.RepeatUint32(halfMask)

	t.Run("mixed_first_chunk_padding", func(t *testing.T) {
		source := []byte{1, 2, 3, 4}
		encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 0)
		if err != nil {
			t.Fatal(err)
		}
		chunk := binary.BigEndian.Uint64(encoded)
		paddingMask := ^initialMask
		chunk |= paddingMask & -paddingMask
		binary.BigEndian.PutUint64(encoded, chunk)
		if _, err := decodeLowEntropyPayload(encoded, len(source), mode, halfMask, rotation); err == nil {
			t.Error("decodeLowEntropyPayload() accepted mixed first-chunk padding")
		}
	})

	t.Run("polarity_changes_between_chunks", func(t *testing.T) {
		source := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 0)
		if err != nil {
			t.Fatal(err)
		}
		secondChunk := binary.BigEndian.Uint64(encoded[lowEntropyChunkLen:])
		secondChunk |= ^initialMask
		binary.BigEndian.PutUint64(encoded[lowEntropyChunkLen:], secondChunk)
		if _, err := decodeLowEntropyPayload(encoded, len(source), mode, halfMask, rotation); err == nil {
			t.Error("decodeLowEntropyPayload() accepted a padding polarity change")
		}
	})

	t.Run("unused_selected_positions_in_partial_chunk", func(t *testing.T) {
		source := []byte{0x5a}
		encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 0)
		if err != nil {
			t.Fatal(err)
		}
		dataMask := mathext.PDEP(lowBits(8), initialMask)
		unusedSelectedMask := initialMask &^ dataMask
		if unusedSelectedMask == 0 {
			t.Fatal("test requires an unused selected position")
		}
		chunk := binary.BigEndian.Uint64(encoded)
		chunk |= unusedSelectedMask & -unusedSelectedMask
		binary.BigEndian.PutUint64(encoded, chunk)
		if _, err := decodeLowEntropyPayload(encoded, len(source), mode, halfMask, rotation); err == nil {
			t.Error("decodeLowEntropyPayload() accepted inconsistent padding in an unused selected position")
		}
	})
}

func FuzzLowEntropyRoundTrip(f *testing.F) {
	f.Add([]byte{0x12, 0x34, 0x56, 0x78}, byte(0), byte(0), uint32(0), false)
	f.Add([]byte("partial final chunk"), byte(3), byte(30), uint32(17), true)
	f.Fuzz(func(t *testing.T, data []byte, modeSeed, rotationSeed byte, maskSeed uint32, paddingOne bool) {
		if len(data) == 0 {
			return
		}
		if len(data) > 4096 {
			data = data[:4096]
		}
		mode := appctlpb.LowEntropyMode(int32(modeSeed%4) + 1)
		rotations := legalLowEntropyRotations()
		rotation := rotations[int(rotationSeed)%len(rotations)]
		halfMask := bits.RotateLeft32(lowEntropyTestMasks[mode], int(maskSeed%32))
		paddingBit := uint8(0)
		if paddingOne {
			paddingBit = 1
		}
		encoded, err := encodeLowEntropyPayloadWithPaddingBit(data, mode, halfMask, rotation, paddingBit)
		if err != nil {
			t.Fatalf("encodeLowEntropyPayloadWithPaddingBit() failed: %v", err)
		}
		decoded, err := decodeLowEntropyPayload(encoded, len(data), mode, halfMask, rotation)
		if err != nil {
			t.Fatalf("decodeLowEntropyPayload() failed: %v", err)
		}
		if !bytes.Equal(decoded, data) {
			t.Fatal("round-trip payload mismatch")
		}
	})
}

func FuzzDecodeLowEntropyPayload(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, uint16(4), byte(1), uint32(0x0f0f0f0f), byte(0))
	f.Add([]byte{0xff}, uint16(1), byte(5), uint32(0), byte(17))
	f.Fuzz(func(t *testing.T, encoded []byte, extractedLen uint16, modeByte byte, halfMask uint32, rotationByte byte) {
		_, _ = decodeLowEntropyPayload(
			encoded,
			int(extractedLen),
			appctlpb.LowEntropyMode(modeByte),
			halfMask,
			appctlpb.LowEntropyMaskRotation(rotationByte),
		)
	})
}

func BenchmarkLowEntropyCodec(b *testing.B) {
	for mode, halfMask := range lowEntropyTestMasks {
		sourceLen := 32768
		if mode == appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32 {
			sourceLen = 32764
		}
		source := lowEntropyTestPayload(sourceLen)
		rotation := appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_7
		encoded, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 1)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(fmt.Sprintf("encode_mode_%d_%d_bytes", mode, sourceLen), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sourceLen))
			for i := 0; i < b.N; i++ {
				if _, err := encodeLowEntropyPayloadWithPaddingBit(source, mode, halfMask, rotation, 1); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("decode_mode_%d_%d_bytes", mode, sourceLen), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(sourceLen))
			for i := 0; i < b.N; i++ {
				if _, err := decodeLowEntropyPayload(encoded, sourceLen, mode, halfMask, rotation); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func assertLowEntropyPadding(t *testing.T, encoded []byte, extractedLen int, mode appctlpb.LowEntropyMode, halfMask uint32, rotation appctlpb.LowEntropyMaskRotation, paddingBit uint8) {
	t.Helper()
	params, err := validateLowEntropyCodecParams(mode, halfMask, rotation)
	if err != nil {
		t.Fatal(err)
	}
	stride := params.sourceBytesPerChunk
	initialMask := mathext.RepeatUint32(halfMask)
	for chunkIndex, sourceOffset := 0, 0; sourceOffset < extractedLen; chunkIndex, sourceOffset = chunkIndex+1, sourceOffset+stride {
		sourceLen := stride
		if remaining := extractedLen - sourceOffset; remaining < sourceLen {
			sourceLen = remaining
		}
		chunk := binary.BigEndian.Uint64(encoded[chunkIndex*lowEntropyChunkLen:])
		chunkMask := rotateLowEntropyMask(initialMask, rotation, chunkIndex)
		dataMask := mathext.PDEP(lowBits(sourceLen*8), chunkMask)
		paddingMask := ^dataMask
		got := chunk & paddingMask
		if (paddingBit == 0 && got != 0) || (paddingBit == 1 && got != paddingMask) {
			t.Fatalf("chunk %d padding = %#016x with mask %#016x and padding bit %d", chunkIndex, got, paddingMask, paddingBit)
		}
	}
}

func legalLowEntropyRotations() []appctlpb.LowEntropyMaskRotation {
	rotations := []appctlpb.LowEntropyMaskRotation{appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION}
	for i := int32(1); i <= 15; i++ {
		rotations = append(rotations, appctlpb.LowEntropyMaskRotation(i))
	}
	for i := int32(1); i <= 15; i++ {
		rotations = append(rotations, appctlpb.LowEntropyMaskRotation(i*16))
	}
	return rotations
}

func lowEntropyTestPayload(n int) []byte {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i*31 + 7)
	}
	return payload
}
