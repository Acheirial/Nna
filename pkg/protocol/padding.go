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

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
)

var (
	// recommendedConsecutiveASCIILen is the minimum length of consecutive
	// printable ASCII characters in the ASCII padding strategy. It is drawn
	// once per process so that the padding byte distribution is not a stable
	// fingerprint of the host name and shadowlemon version.
	recommendedConsecutiveASCIILen = 24 + mrand.Intn(17)
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

func buildRecommendedPaddingOpts(maxLen int, existingData []byte) paddingOpts {
	asciiOpts := paddingOpts{
		maxLen: maxLen,
		ascii: &asciiPaddingOpts{
			minConsecutiveASCIILen: mathext.Min(maxLen, recommendedConsecutiveASCIILen),
		},
	}

	// The padding strategy is chosen randomly for every message so that it is
	// not a stable property of the sender's account. The padding bytes are not
	// authenticated and are discarded by the receiver, so this has no effect
	// on the wire format.
	if mrand.Intn(2) == 0 {
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

// newPaddingInto generates padding that satisfies opts and appends it to dst.
//
// When dst has enough spare capacity, the returned slice aliases dst and the
// padding is written into that buffer, so the call itself allocates nothing.
// A caller should therefore keep one scratch buffer and pass it as dst for all
// the messages it sends. When dst is nil, a fresh buffer is allocated instead,
// so the returned padding is never a nil slice. The generated padding never
// aliases the existingData of opts.
//
// Invalid options are reported with an error instead of a panic, and the bytes
// of dst are left untouched when opts is invalid.
//
// Invariants of the generated padding:
//   - it is never longer than opts.maxLen;
//   - it has length 0 only when opts.maxLen is 0. A padding of length 0
//     reveals the exact payload length, so it is only generated when the
//     caller explicitly forbids padding;
//   - when opts.maxLen is at least 2, the length is drawn uniformly from at
//     least 2 distinct values. A padding length that is always opts.maxLen
//     would be a fingerprint of the padding strategy, which is what happens
//     when the minimum length required by the strategy is also opts.maxLen;
//   - with the ASCII strategy, the padding contains at least 1 printable
//     ASCII byte whenever it is not empty, and up to minConsecutiveASCIILen
//     consecutive printable ASCII bytes;
//   - with the entropy strategy, the padding lowers the probability of the
//     less frequent bit value of opts.entropy.existingData to at most
//     targetProbability whenever opts.maxLen makes that reachable, and is a
//     fill of the more frequent bit value otherwise.
func newPaddingInto(dst []byte, opts paddingOpts) ([]byte, error) {
	if opts.ascii != nil {
		// Both the ASCII and the entropy options may be set; the ASCII
		// strategy keeps precedence, as it always did.
		if opts.maxLen < opts.ascii.minConsecutiveASCIILen {
			return nil, fmt.Errorf("Invalid padding options: maxLen %d is smaller than minConsecutiveASCIILen %d", opts.maxLen, opts.ascii.minConsecutiveASCIILen)
		}

		// The padding must contain at least 1 printable ASCII byte, and it
		// should contain minConsecutiveASCIILen consecutive printable ASCII
		// bytes. When minConsecutiveASCIILen does not fit under maxLen-1,
		// honoring it would make the length always maxLen, so the consecutive
		// printable content is shortened to the padding length (never below 1
		// byte) to keep the length variable.
		minPrintableLen := mathext.Min(opts.ascii.minConsecutiveASCIILen, opts.maxLen-1)
		length := choosePaddingLength(mathext.Max(minPrintableLen, 1), opts.maxLen)
		out, padding := growPadding(dst, length)
		if length == 0 {
			// Only reachable when opts.maxLen is 0.
			return out, nil
		}
		if _, err := crand.Read(padding); err != nil {
			return nil, fmt.Errorf("crypto/rand Read() failed: %w", err)
		}
		printableLen := mathext.Max(mathext.Min(opts.ascii.minConsecutiveASCIILen, length), 1)
		beginIdx := 0
		if length > printableLen {
			beginIdx = mrand.Intn(length - printableLen)
		}
		common.ToPrintableChar(padding, beginIdx, beginIdx+printableLen)
		return out, nil
	} else if opts.entropy != nil {
		if opts.entropy.targetProbability <= 0.0 || opts.entropy.targetProbability > 0.5 {
			return nil, fmt.Errorf("Invalid padding options: targetProbability %f is out of range (0.0, 0.5]", opts.entropy.targetProbability)
		}

		lowerBit, lowerBitCount, minPaddingBytes := entropyPaddingParams(opts.entropy.existingData, opts.entropy.targetProbability)

		// The lower bound is at least 1, and at least minPaddingBytes+1,
		// otherwise the padding contains no bit with the lower probability and
		// degenerates into a constant block. Keeping the length variable takes
		// priority over the latter rule: when only maxLen can hold a bit with
		// the lower probability, the shorter length is still used, and the
		// padding falls back to the best effort fill of the higher probability
		// bit, exactly like when maxLen itself is too small.
		lower := mathext.Max(minPaddingBytes+1, 1)
		length := choosePaddingLength(lower, opts.maxLen)
		out, padding := growPadding(dst, length)

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
		if _, err := crand.Read(padding); err != nil {
			return nil, fmt.Errorf("crypto/rand Read() failed: %w", err)
		}
		setBitCount(padding, lowerBit, flip)
		return out, nil
	}
	return nil, fmt.Errorf("Detailed padding options are not provided")
}

// choosePaddingLength returns a padding length drawn uniformly at random from
// the inclusive range that starts at minLen when minLen fits, and documents the
// invariants of the value it returns:
//   - the length is in [0, maxLen];
//   - the length is 0 only when maxLen is 0, so that the padding of a
//     non-empty message never reveals the exact payload length;
//   - when maxLen is at least 2, at least 2 distinct lengths are possible and
//     they are equally likely. When the caller allows at least 2 bytes but the
//     minimum length required by the strategy is maxLen, the returned length
//     may be maxLen-1, i.e. below that minimum, because a padding length that
//     is always maxLen fingerprints the padding strategy.
func choosePaddingLength(minLen, maxLen int) int {
	if maxLen <= 0 {
		return 0
	}
	lower := mathext.Max(minLen, 1)
	lower = mathext.Min(lower, maxLen)
	if lower == maxLen && maxLen >= 2 {
		lower = maxLen - 1
	}
	return lower + mrand.Intn(maxLen-lower+1)
}

// growPadding appends length reserved bytes to dst and returns the extended
// slice together with the reserved region. The content of dst is preserved and
// the reserved bytes are uninitialized. dst is reallocated when it is nil or
// when it does not have enough spare capacity, so a scratch buffer of
// sufficient capacity makes the operation allocation free.
func growPadding(dst []byte, length int) (out, padding []byte) {
	prefixLen := len(dst)
	if dst == nil || cap(dst)-prefixLen < length {
		// A nil dst is always replaced by a fresh buffer, even for a zero
		// length padding, so that the padding generated without a caller
		// buffer is never a nil slice.
		grown := make([]byte, prefixLen, prefixLen+length)
		copy(grown, dst)
		dst = grown
	}
	out = dst[:prefixLen+length]
	padding = out[prefixLen:]
	return out, padding
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
