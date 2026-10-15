// Copyright (C) 2023  mieru authors
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>

package protocol

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/rng"
)

var (
	recommendedConsecutiveASCIILen = 24 + rng.FixedIntVH(17)
	recommendedTargetProbability   = 0.325
)

type paddingPosition int

const (
	middlePadding paddingPosition = iota
	endPadding
)

type paddingOpts struct {
	// The maxinum length of padding.
	maxLen int

	ascii *asciiPaddingOpts

	entropy *entropyPaddingOpts
}

type asciiPaddingOpts struct {
	// The mininum length of consecutive ASCII characters.
	// This implies the mininum length of padding.
	minConsecutiveASCIILen int
}

type entropyPaddingOpts struct {
	// The existing data that the padding will be attached to.
	//
	// It must be the real content to protect instead of a random buffer,
	// otherwise the padding degenerates into a constant block.
	existingData []byte

	// The target probability of bit 0 or bit 1, whichever is lower,
	// in the existing data + padding.
	// This value should be in the range of (0.0, 0.5].
	//
	// We will try best effort to meet the target with the given
	// maximum padding length.
	targetProbability float64
}

// maxPaddingSizeWithTrafficPattern returns the maximum padding size.
func maxPaddingSizeWithTrafficPattern(mtu int, transport common.TransportProtocol, fragmentSize int, existingPaddingSize int, trafficPattern *appctlpb.TrafficPattern, position paddingPosition) int {
	maxPaddingSize := maxPaddingSize(mtu, transport, fragmentSize, existingPaddingSize)
	if trafficPattern == nil || trafficPattern.Padding == nil {
		return maxPaddingSize
	}

	var configured *int32
	switch position {
	case middlePadding:
		configured = trafficPattern.Padding.MaxMiddlePaddingLen
	case endPadding:
		configured = trafficPattern.Padding.MaxEndPaddingLen
	default:
		return maxPaddingSize
	}
	if configured == nil {
		return maxPaddingSize
	}
	if *configured < 0 {
		return 0
	}
	return mathext.Min(maxPaddingSize, int(*configured))
}

// maxPaddingSize returns the maximum padding size without considering traffic pattern.
func maxPaddingSize(mtu int, transport common.TransportProtocol, fragmentSize int, existingPaddingSize int) int {
	if transport == common.StreamTransport {
		// No limit.
		return 255
	}

	res := mtu - fragmentSize - packetOverhead
	if res <= int(existingPaddingSize) {
		return 0
	}
	return mathext.Min(res-int(existingPaddingSize), 255)
}

func buildRecommendedPaddingOpts(maxLen int, existingData []byte, strategySource string) paddingOpts {
	asciiOpts := paddingOpts{
		maxLen: maxLen,
		ascii: &asciiPaddingOpts{
			minConsecutiveASCIILen: mathext.Min(maxLen, recommendedConsecutiveASCIILen),
		},
	}

	// strategySource decides the padding strategy.
	if rng.FixedIntV(2, strategySource) == 0 {
		// Use ASCII.
		return asciiOpts
	}

	// Use entropy. The bit distribution of existingData decides how many
	// bits in the padding are set to the less frequent bit value.
	if _, _, minPaddingBytes := entropyPaddingParams(existingData, recommendedTargetProbability); minPaddingBytes < maxLen {
		return paddingOpts{
			maxLen: maxLen,
			entropy: &entropyPaddingOpts{
				existingData:      existingData,
				targetProbability: recommendedTargetProbability,
			},
		}
	}

	// The target probability can't be reached with maxLen bytes of padding.
	// In this case the entropy padding is a constant block of the more
	// frequent bit value, which is easy to locate, so use the ASCII strategy
	// instead.
	return asciiOpts
}

// entropyPaddingParams returns the bit value with the lower probability in
// data, the number of such bits in data, and the shortest padding length in
// bytes that is needed to lower the probability of that bit in data plus
// padding to targetProbability.
func entropyPaddingParams(data []byte, targetProbability float64) (lowerBit byte, lowerBitCount, minPaddingBytes int) {
	dist := common.ToBitDistribution(data)
	lowerBitCount = dist.Bit0Count
	if dist.Bit1 < dist.Bit0 {
		lowerBit = byte(1)
		lowerBitCount = dist.Bit1Count
	}

	// Let x = lowerBitCount, t = targetProbability, e = data bits, p = padding bits.
	// We need to find p that satisfy x = t * (e + p).
	// Solve the equation gives p = x / t - e.
	minPaddingBits := int(float64(lowerBitCount)/targetProbability - float64(len(data)*8))
	minPaddingBits = mathext.Max(minPaddingBits, 0)
	minPaddingBytes = (minPaddingBits + 7) / 8
	return
}

func newPadding(opts paddingOpts) []byte {
	if opts.ascii != nil {
		if opts.maxLen < opts.ascii.minConsecutiveASCIILen {
			panic(fmt.Sprintf("Invalid padding options: maxLen %d is smaller than minConsecutiveASCIILen %d", opts.maxLen, opts.ascii.minConsecutiveASCIILen))
		}

		// Pick the length uniformly from [lower, maxLen]. The lower bound is
		// at least 1 so that a zero length padding, which reveals the exact
		// payload length, is not generated.
		lower := mathext.Max(opts.ascii.minConsecutiveASCIILen, 1)
		lower = mathext.Min(lower, opts.maxLen)
		length := lower + mrand.Intn(opts.maxLen-lower+1)
		p := make([]byte, length)
		for {
			if _, err := crand.Read(p); err == nil {
				break
			}
		}
		beginIdx := 0
		if length > opts.ascii.minConsecutiveASCIILen {
			beginIdx = mrand.Intn(length - opts.ascii.minConsecutiveASCIILen)
		}
		common.ToPrintableChar(p, beginIdx, beginIdx+opts.ascii.minConsecutiveASCIILen)
		return p
	} else if opts.entropy != nil {
		if opts.entropy.targetProbability <= 0.0 || opts.entropy.targetProbability > 0.5 {
			panic(fmt.Sprintf("Invalid padding options: targetProbability %f is out of range (0.0, 0.5]", opts.entropy.targetProbability))
		}

		lowerBit, lowerBitCount, minPaddingBytes := entropyPaddingParams(opts.entropy.existingData, opts.entropy.targetProbability)

		// Pick the padding length uniformly from [lower, maxLen]. The lower
		// bound is at least 1 so that a zero length padding, which reveals
		// the exact payload length, is not generated. It is also at least
		// minPaddingBytes+1, otherwise the padding contains no bit with the
		// lower probability and degenerates into a constant block.
		lower := mathext.Max(minPaddingBytes+1, 1)
		lower = mathext.Min(lower, opts.maxLen)
		length := lower + mrand.Intn(opts.maxLen-lower+1)
		p := make([]byte, length)

		// Determine the number of bits in the padding that use the bit value
		// with the lower probability in the existing data.
		flip := mathext.Max(int(float64(len(opts.entropy.existingData)+length)*8*opts.entropy.targetProbability)-lowerBitCount, 0)
		flip = mathext.Min(flip, length*8)

		// Fill the padding with random bytes and then adjust the number of
		// lower probability bits to exactly flip. Different from filling
		// every bit with the higher probability value, the padding bytes have
		// no constant block texture as long as the target probability is
		// reachable within maxLen, i.e. flip is not 0. When maxLen is too
		// small to dilute the lower probability bit, the padding is the best
		// effort fill of the higher probability bit.
		for {
			if _, err := crand.Read(p); err == nil {
				break
			}
		}
		setBitCount(p, lowerBit, flip)
		return p
	}
	panic("Detailed padding options are not provided")
}

// setBitCount rewrites p, so that exactly want bits are equal to bit and the
// remaining bits are equal to the other bit value. want is clamped to
// [0, len(p)*8]. The rewritten positions are selected in a random order, thus
// the byte distribution of p stays close to uniform.
func setBitCount(p []byte, bit byte, want int) {
	if bit != 0 && bit != 1 {
		panic(fmt.Sprintf("Invalid bit value %d", bit))
	}
	maxWant := len(p) * 8
	if want < 0 {
		want = 0
	}
	if want > maxWant {
		want = maxWant
	}
	dist := common.ToBitDistribution(p)
	count := dist.Bit0Count
	if bit == 1 {
		count = dist.Bit1Count
	}
	if count == want {
		return
	}

	// The bits equal to src are rewritten to the other bit value. The
	// distance between count and want is the number of bits to rewrite.
	delta := count - want
	src := bit
	if delta < 0 {
		delta = -delta
		src = 1 - bit
	}
	start := mrand.Intn(maxWant)
	for i := 0; i < maxWant && delta > 0; i++ {
		j := (start + i) % maxWant
		byteIndex := j / 8
		bitIndex := uint(j % 8)
		if (p[byteIndex]>>bitIndex)&1 != src {
			continue
		}
		p[byteIndex] ^= 1 << bitIndex
		delta--
	}
}
