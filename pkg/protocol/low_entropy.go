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
	"encoding/binary"
	"fmt"
	"math"
	"math/bits"
	mrand "math/rand"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
	"github.com/Acheirial/shadowlemon/v3/pkg/rng"
)

// lowEntropyChunkLen is the number of bytes of each low entropy chunk.
const lowEntropyChunkLen = 8

// lowEntropyMaxHalfMaskOnes is the largest number of one-bits a half-mask may
// have when this implementation encodes a message. A half-mask with 32 one-bits
// repeats to a chunk mask without a single padding bit, which is not a low
// entropy chunk anymore, so the encoder never generates one. The decoder still
// accepts such a half-mask, because it can only trust what the sender of the
// message put on the wire.
const lowEntropyMaxHalfMaskOnes = 28

// lowEntropyModeParams describes the low entropy parameters of one message.
//
// buildLowEntropyParams returns the nominal parameters of a mode: the number of
// plaintext bytes each 8 byte chunk carries and the number of one-bits of the
// half-mask. Neither is fixed by the mode in a message: the sender picks the
// number of one-bits from a family of three values, and the receiver derives
// the effective parameters from the half-mask it received, see
// validateLowEntropyCodecParams.
type lowEntropyModeParams struct {
	sourceBytesPerChunk int
	halfMaskOnes        int
}

// extractLowEntropyConfig returns the effective low entropy configuration.
// A missing traffic pattern, a missing low entropy pattern, or mode OFF all
// disable low entropy transmission.
func extractLowEntropyConfig(pattern *appctlpb.TrafficPattern) (appctlpb.LowEntropyMode, appctlpb.LowEntropyMaskRotation, bool) {
	if pattern == nil || pattern.LowEntropy == nil {
		return appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	mode := pattern.LowEntropy.GetMode()
	if mode == appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF {
		return mode, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	return mode, pattern.LowEntropy.GetMaskRotation(), true
}

func buildLowEntropyParams(mode appctlpb.LowEntropyMode) (lowEntropyModeParams, error) {
	switch mode {
	case appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32:
		return lowEntropyModeParams{sourceBytesPerChunk: 4, halfMaskOnes: 16}, nil
	case appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40:
		return lowEntropyModeParams{sourceBytesPerChunk: 5, halfMaskOnes: 20}, nil
	case appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48:
		return lowEntropyModeParams{sourceBytesPerChunk: 6, halfMaskOnes: 24}, nil
	case appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56:
		return lowEntropyModeParams{sourceBytesPerChunk: 7, halfMaskOnes: 28}, nil
	default:
		return lowEntropyModeParams{}, fmt.Errorf("invalid low entropy mode %d", mode)
	}
}

// halfMaskOnesChoices returns the number of one-bits a half-mask of mode may
// have. The count is drawn per message, so the number of padding bits in each
// 8 byte chunk is not a constant of the mode that a passive observer could
// count. The family is {K0-4, K0, K0+4} truncated at lowEntropyMaxHalfMaskOnes.
// The returned slice is nil for a mode that has no codec.
func halfMaskOnesChoices(mode appctlpb.LowEntropyMode) []int {
	params, err := buildLowEntropyParams(mode)
	if err != nil {
		return nil
	}
	choices := make([]int, 0, 3)
	for _, ones := range []int{params.halfMaskOnes - 4, params.halfMaskOnes, params.halfMaskOnes + 4} {
		if ones > 0 && ones <= lowEntropyMaxHalfMaskOnes {
			choices = append(choices, ones)
		}
	}
	return choices
}

// lowEntropyMinStride returns the smallest number of plaintext bytes per chunk
// of the mode family, in other words the stride that produces the longest
// encoded payload. Callers that must size a fragment before the half-mask of
// the message exists use it as the worst case.
func lowEntropyMinStride(mode appctlpb.LowEntropyMode) (int, error) {
	choices := halfMaskOnesChoices(mode)
	if len(choices) == 0 {
		return 0, fmt.Errorf("invalid low entropy mode %d", mode)
	}
	minOnes := choices[0]
	for _, ones := range choices[1:] {
		if ones < minOnes {
			minOnes = ones
		}
	}
	// The half-mask is repeated to fill an 8 byte chunk, so the chunk mask has
	// twice as many one-bits and carries 2*ones/8 = ones/4 plaintext bytes.
	return minOnes / 4, nil
}

// lowEntropyEncodedPayloadLen returns the encoded body length of a payload
// encoded with stride, the number of plaintext bytes each 8 byte chunk carries.
// The stride of a message is derived from its half-mask, see
// validateLowEntropyCodecParams. It also checks that the result is
// representable by the uint16 metadata field.
func lowEntropyEncodedPayloadLen(extractedPayloadLen, stride int) (uint16, error) {
	if stride <= 0 || stride > lowEntropyChunkLen {
		return 0, fmt.Errorf("invalid low entropy stride %d", stride)
	}
	if extractedPayloadLen <= 0 {
		return 0, fmt.Errorf("invalid extracted payload length %d", extractedPayloadLen)
	}

	chunkCount := extractedPayloadLen / stride
	if extractedPayloadLen%stride != 0 {
		chunkCount++
	}
	if chunkCount > math.MaxUint16/lowEntropyChunkLen {
		return 0, fmt.Errorf("encoded payload length for %d bytes exceeds %d", extractedPayloadLen, uint16(math.MaxUint16))
	}
	return uint16(chunkCount * lowEntropyChunkLen), nil
}

// lowEntropyNominalEncodedPayloadLen returns the encoded body length that mode
// implies for extractedPayloadLen. The exact length of a message depends on its
// half-mask, which is generated when the message is put on the wire, so a
// sender that has to fill a length before the mask exists uses the nominal
// value and replaces it once the mask is known.
func lowEntropyNominalEncodedPayloadLen(extractedPayloadLen int, mode appctlpb.LowEntropyMode) (uint16, error) {
	params, err := buildLowEntropyParams(mode)
	if err != nil {
		return 0, err
	}
	return lowEntropyEncodedPayloadLen(extractedPayloadLen, params.sourceBytesPerChunk)
}

func isValidLowEntropyRotation(rotation appctlpb.LowEntropyMaskRotation) bool {
	return rotation == appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION ||
		(rotation >= appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_1 &&
			rotation <= appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_15) ||
		(rotation >= appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_1 &&
			rotation <= appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_15 &&
			rotation%16 == 0)
}

// lowEntropyChunkMask returns the mask for chunkIndex. The first chunk is
// unrotated. Right-rotation values occupy the low nibble; left-rotation values
// occupy the high nibble and encode the shift after division by 16.
func lowEntropyChunkMask(initialMask uint64, rotation appctlpb.LowEntropyMaskRotation, chunkIndex int) (uint64, error) {
	if !isValidLowEntropyRotation(rotation) {
		return 0, fmt.Errorf("invalid low entropy mask rotation %d", rotation)
	}
	if chunkIndex < 0 {
		return 0, fmt.Errorf("invalid low entropy chunk index %d", chunkIndex)
	}
	return rotateLowEntropyMask(initialMask, rotation, chunkIndex), nil
}

func rotateLowEntropyMask(initialMask uint64, rotation appctlpb.LowEntropyMaskRotation, chunkIndex int) uint64 {
	if rotation == appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION || chunkIndex == 0 {
		return initialMask
	}
	if rotation <= appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_15 {
		return bits.RotateLeft64(initialMask, -((chunkIndex % 64) * int(rotation)))
	}
	return bits.RotateLeft64(initialMask, (chunkIndex%64)*int(rotation/16))
}

// newLowEntropyHalfMask returns a fresh 32-bit half-mask for one message. The
// number of one-bits is drawn from the mode family, so two messages of the same
// mode carry a different number of padding bits per chunk.
func newLowEntropyHalfMask(mode appctlpb.LowEntropyMode) (uint32, error) {
	choices := halfMaskOnesChoices(mode)
	if len(choices) == 0 {
		return 0, fmt.Errorf("invalid low entropy mode %d", mode)
	}
	return rng.Uint32WithBits(choices[mrand.Intn(len(choices))]), nil
}

// encodeLowEntropyPayload is the production codec wrapper. The padding polarity
// is drawn per message, so the padding bits of a host are not a constant that a
// passive observer could learn. Tests use
// encodeLowEntropyPayloadWithPaddingBit directly to cover both polarities.
func encodeLowEntropyPayload(src []byte, mode appctlpb.LowEntropyMode, halfMask uint32, rotation appctlpb.LowEntropyMaskRotation) ([]byte, error) {
	return encodeLowEntropyPayloadWithPaddingBit(src, mode, halfMask, rotation, uint8(mrand.Intn(2)))
}

func encodeLowEntropyPayloadWithPaddingBit(src []byte, mode appctlpb.LowEntropyMode, halfMask uint32, rotation appctlpb.LowEntropyMaskRotation, paddingBit uint8) ([]byte, error) {
	params, err := validateLowEntropyCodecParams(mode, halfMask, rotation)
	if err != nil {
		return nil, err
	}
	if paddingBit > 1 {
		return nil, fmt.Errorf("invalid low entropy padding bit %d", paddingBit)
	}
	// The stride is derived from the half-mask, so a message carries as many
	// plaintext bytes per chunk as its mask has room for.
	stride := params.sourceBytesPerChunk
	encodedLen, err := lowEntropyEncodedPayloadLen(len(src), stride)
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, int(encodedLen))
	initialMask := mathext.RepeatUint32(halfMask)
	for chunkIndex, srcOffset := 0, 0; srcOffset < len(src); chunkIndex, srcOffset = chunkIndex+1, srcOffset+stride {
		sourceLen := stride
		if remaining := len(src) - srcOffset; remaining < sourceLen {
			sourceLen = remaining
		}

		var scratch [lowEntropyChunkLen]byte
		copy(scratch[lowEntropyChunkLen-sourceLen:], src[srcOffset:srcOffset+sourceLen])
		source := binary.BigEndian.Uint64(scratch[:])
		chunkMask := rotateLowEntropyMask(initialMask, rotation, chunkIndex)
		dataMask := mathext.PDEP(lowBits(sourceLen*8), chunkMask)
		chunk := mathext.PDEP(source, chunkMask)
		if paddingBit == 1 {
			chunk |= ^dataMask
		}
		binary.BigEndian.PutUint64(encoded[chunkIndex*lowEntropyChunkLen:], chunk)
	}
	return encoded, nil
}

// decodeLowEntropyPayload validates canonical uniform padding while extracting
// the original ciphertext body. The stride of the message is derived from the
// half-mask. The padding polarity is inferred from the first chunk and must
// remain the same in every non-data position. A half-mask without a padding bit
// has no polarity to infer and no padding position to check.
func decodeLowEntropyPayload(encoded []byte, extractedPayloadLen int, mode appctlpb.LowEntropyMode, halfMask uint32, rotation appctlpb.LowEntropyMaskRotation) ([]byte, error) {
	params, err := validateLowEntropyCodecParams(mode, halfMask, rotation)
	if err != nil {
		return nil, err
	}
	stride := params.sourceBytesPerChunk
	expectedEncodedLen, err := lowEntropyEncodedPayloadLen(extractedPayloadLen, stride)
	if err != nil {
		return nil, err
	}
	if len(encoded) != int(expectedEncodedLen) {
		return nil, fmt.Errorf("encoded payload length is %d, want %d", len(encoded), expectedEncodedLen)
	}

	decoded := make([]byte, extractedPayloadLen)
	initialMask := mathext.RepeatUint32(halfMask)
	hasPadding := bits.OnesCount64(initialMask) != lowEntropyChunkLen*8
	var paddingBit uint8
	for chunkIndex, dstOffset := 0, 0; dstOffset < extractedPayloadLen; chunkIndex, dstOffset = chunkIndex+1, dstOffset+stride {
		sourceLen := stride
		if remaining := extractedPayloadLen - dstOffset; remaining < sourceLen {
			sourceLen = remaining
		}

		chunk := binary.BigEndian.Uint64(encoded[chunkIndex*lowEntropyChunkLen:])
		chunkMask := rotateLowEntropyMask(initialMask, rotation, chunkIndex)
		dataMask := mathext.PDEP(lowBits(sourceLen*8), chunkMask)
		if hasPadding {
			paddingMask := ^dataMask
			padding := chunk & paddingMask
			if chunkIndex == 0 {
				switch padding {
				case 0:
					paddingBit = 0
				case paddingMask:
					paddingBit = 1
				default:
					return nil, fmt.Errorf("low entropy chunk %d has mixed padding bits", chunkIndex)
				}
			} else if (paddingBit == 0 && padding != 0) || (paddingBit == 1 && padding != paddingMask) {
				return nil, fmt.Errorf("low entropy chunk %d has non-uniform padding bits", chunkIndex)
			}
		}

		source := mathext.PEXT(chunk, chunkMask)
		var scratch [lowEntropyChunkLen]byte
		binary.BigEndian.PutUint64(scratch[:], source)
		copy(decoded[dstOffset:dstOffset+sourceLen], scratch[lowEntropyChunkLen-sourceLen:])
	}
	return decoded, nil
}

// validateLowEntropyCodecParams checks the half-mask and the rotation of one
// message and returns the effective parameters they imply. The number of
// one-bits of the half-mask is not fixed by the mode: the sender draws it from
// the mode family, so the receiver derives the number of plaintext bytes per
// chunk from the mask it received and only checks that this stride belongs to
// the family of the mode. This is a change of the protocol semantics, both
// peers must be upgraded together. It does not change the wire format lengths
// and does not change the protocol version.
func validateLowEntropyCodecParams(mode appctlpb.LowEntropyMode, halfMask uint32, rotation appctlpb.LowEntropyMaskRotation) (lowEntropyModeParams, error) {
	base, err := buildLowEntropyParams(mode)
	if err != nil {
		return lowEntropyModeParams{}, err
	}
	// The half-mask is repeated to fill an 8 byte chunk, so a chunk mask has
	// twice as many one-bits and carries chunk ones / 8 plaintext bytes.
	chunkOnes := 2 * bits.OnesCount32(halfMask)
	if chunkOnes%lowEntropyChunkLen != 0 {
		return lowEntropyModeParams{}, fmt.Errorf("low entropy mask has %d one-bits in a chunk, want a multiple of %d", chunkOnes, lowEntropyChunkLen)
	}
	stride := chunkOnes / lowEntropyChunkLen
	if stride < base.sourceBytesPerChunk-1 || stride > base.sourceBytesPerChunk+1 {
		return lowEntropyModeParams{}, fmt.Errorf("low entropy mask carries %d bytes per chunk, want %d, %d or %d", stride, base.sourceBytesPerChunk-1, base.sourceBytesPerChunk, base.sourceBytesPerChunk+1)
	}
	if !isValidLowEntropyRotation(rotation) {
		return lowEntropyModeParams{}, fmt.Errorf("invalid low entropy mask rotation %d", rotation)
	}
	return lowEntropyModeParams{sourceBytesPerChunk: stride, halfMaskOnes: chunkOnes / 2}, nil
}

func lowBits(n int) uint64 {
	if n >= 64 {
		return math.MaxUint64
	}
	return uint64(1)<<n - 1
}
