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
// along with this program.  If not, see <https://www.gnu.org/licenses/>

package protocol

import (
	crand "crypto/rand"
	"fmt"
	"maps"
	mrand "math/rand"
	"slices"
	"testing"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/rng"
	"google.golang.org/protobuf/proto"
)

func TestMaxPaddingSizeWithTrafficPattern(t *testing.T) {
	testcases := []struct {
		name                string
		mtu                 int
		transport           common.TransportProtocol
		fragmentSize        int
		existingPaddingSize int
		trafficPattern      *appctlpb.TrafficPattern
		position            paddingPosition
		want                int
	}{
		{
			name:           "nil_traffic_pattern",
			mtu:            1400,
			transport:      common.StreamTransport,
			fragmentSize:   128,
			trafficPattern: nil,
			position:       middlePadding,
			want:           maxPaddingSize(1400, common.StreamTransport, 128, 0),
		},
		{
			name:           "nil_padding_pattern",
			mtu:            1400,
			transport:      common.StreamTransport,
			fragmentSize:   128,
			trafficPattern: &appctlpb.TrafficPattern{},
			position:       endPadding,
			want:           maxPaddingSize(1400, common.StreamTransport, 128, 0),
		},
		{
			name:         "nil_selected_field",
			mtu:          1400,
			transport:    common.StreamTransport,
			fragmentSize: 128,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxEndPaddingLen: proto.Int32(12),
				},
			},
			position: middlePadding,
			want:     maxPaddingSize(1400, common.StreamTransport, 128, 0),
		},
		{
			name:         "configured_zero",
			mtu:          1400,
			transport:    common.StreamTransport,
			fragmentSize: 128,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxMiddlePaddingLen: proto.Int32(0),
				},
			},
			position: middlePadding,
			want:     0,
		},
		{
			name:         "configured_small_cap",
			mtu:          1400,
			transport:    common.StreamTransport,
			fragmentSize: 128,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxEndPaddingLen: proto.Int32(7),
				},
			},
			position: endPadding,
			want:     7,
		},
		{
			name:         "negative_configured_value",
			mtu:          1400,
			transport:    common.StreamTransport,
			fragmentSize: 128,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxMiddlePaddingLen: proto.Int32(-1),
				},
			},
			position: middlePadding,
			want:     0,
		},
		{
			name:         "udp_mtu_caps_configured_value",
			mtu:          1400,
			transport:    common.PacketTransport,
			fragmentSize: 1400 - packetOverhead - 5,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxEndPaddingLen: proto.Int32(255),
				},
			},
			position: endPadding,
			want:     5,
		},
		{
			name:                "udp_existing_padding_caps_configured_value",
			mtu:                 1400,
			transport:           common.PacketTransport,
			fragmentSize:        1400 - packetOverhead - 5,
			existingPaddingSize: 3,
			trafficPattern: &appctlpb.TrafficPattern{
				Padding: &appctlpb.PaddingPattern{
					MaxEndPaddingLen: proto.Int32(255),
				},
			},
			position: endPadding,
			want:     2,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := maxPaddingSizeWithTrafficPattern(tc.mtu, tc.transport, tc.fragmentSize, tc.existingPaddingSize, tc.trafficPattern, tc.position)
			if got != tc.want {
				t.Errorf("maxPaddingSizeWithTrafficPattern() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestMaxPaddingSize(t *testing.T) {
	testcases := []struct {
		mtu                 int
		transport           common.TransportProtocol
		fragmentSize        int
		existingPaddingSize int
		want                int
	}{
		{
			1400,
			common.StreamTransport,
			maxPDU,
			255,
			255,
		},
		{
			1400,
			common.PacketTransport,
			1400 - packetOverhead - 16,
			12,
			4,
		},
		{
			1400,
			common.UnknownTransport,
			0,
			255,
			255,
		},
	}
	for _, tc := range testcases {
		got := maxPaddingSize(tc.mtu, tc.transport, tc.fragmentSize, tc.existingPaddingSize)
		if got != tc.want {
			t.Errorf("MaxPaddingSize() = %d, want %d", got, tc.want)
		}
	}
}

// TestNewASCIIPadding verifies the invariants of the ASCII padding: the length
// is in [0, maxLen] and is 0 only when maxLen is 0, the padding contains at
// least 1 printable ASCII byte when it is not empty, and it contains up to
// minConsecutiveASCIILen consecutive printable ASCII bytes.
func TestNewASCIIPadding(t *testing.T) {
	testcases := []struct {
		name                   string
		maxPaddingLen          int
		minConsecutiveASCIILen int
	}{
		{"maxLen 0", 0, 0},
		{"maxLen 1", 1, 1},
		{"maxLen 2", 2, 2},
		{"minConsecutiveASCIILen equals maxLen", 16, 16},
		{"minConsecutiveASCIILen below maxLen", 16, 4},
		{"minConsecutiveASCIILen 0", 8, 0},
		{"maxLen 255", 255, 24},
		{"maxLen 255 without consecutive ASCII", 255, 0},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			opts := paddingOpts{
				maxLen: tc.maxPaddingLen,
				ascii: &asciiPaddingOpts{
					minConsecutiveASCIILen: tc.minConsecutiveASCIILen,
				},
			}
			for range 100 {
				padding, err := newPaddingInto(nil, opts)
				if err != nil {
					t.Fatalf("newPaddingInto() error = %v", err)
				}

				if len(padding) > tc.maxPaddingLen {
					t.Errorf("Padding length %d is bigger than the maximum length %d", len(padding), tc.maxPaddingLen)
				}
				if tc.maxPaddingLen == 0 {
					if len(padding) != 0 {
						t.Errorf("Padding length %d is not 0 although the maximum length is 0", len(padding))
					}
					continue
				}
				if len(padding) < 1 {
					t.Errorf("Padding length %d is smaller than 1 although the maximum length is %d", len(padding), tc.maxPaddingLen)
				}
				consecutive := common.MaxConsecutivePrintableLength(padding)
				if consecutive < 1 {
					t.Errorf("Padding's consecutive printable length is %d, want at least 1", consecutive)
				}
				if want := mathext.Min(tc.minConsecutiveASCIILen, len(padding)); consecutive < want {
					t.Errorf("Padding's consecutive printable length %d is smaller than the required minimum consecutive ASCII length %d", consecutive, want)
				}
			}
		})
	}

	t.Run("random options", func(t *testing.T) {
		for range 200 {
			maxPaddingLen := rng.Intn(256)
			minConsecutiveASCIILen := rng.IntRange(0, maxPaddingLen+1)
			opts := paddingOpts{
				maxLen: maxPaddingLen,
				ascii: &asciiPaddingOpts{
					minConsecutiveASCIILen: minConsecutiveASCIILen,
				},
			}
			padding, err := newPaddingInto(nil, opts)
			if err != nil {
				t.Fatalf("newPaddingInto() error = %v", err)
			}

			if len(padding) > maxPaddingLen {
				t.Errorf("Padding length %d is bigger than the maximum length %d", len(padding), maxPaddingLen)
			}
			if maxPaddingLen == 0 && len(padding) != 0 {
				t.Errorf("Padding length %d is not 0 although the maximum length is 0", len(padding))
			}
			if maxPaddingLen > 0 && len(padding) < 1 {
				t.Errorf("Padding length %d is smaller than 1 although the maximum length is %d", len(padding), maxPaddingLen)
			}
			consecutive := common.MaxConsecutivePrintableLength(padding)
			if len(padding) > 0 && consecutive < 1 {
				t.Errorf("Padding's consecutive printable length is %d, want at least 1", consecutive)
			}
			if want := mathext.Min(minConsecutiveASCIILen, len(padding)); consecutive < want {
				t.Errorf("Padding's consecutive printable length %d is smaller than the required minimum consecutive ASCII length %d", consecutive, want)
			}
		}
	})
}

// TestNewEntropyPadding verifies that generated padding meets the target bit
// distribution or falls back to uniform bits when the length cap prevents it.
func TestNewEntropyPadding(t *testing.T) {
	var meet, miss int
	for i := 0; i < 1000; i++ {
		existingDataLen := rng.IntRange(0, 1024)
		existingData := make([]byte, existingDataLen)
		if _, err := crand.Read(existingData); err != nil {
			t.Fatalf("Failed to generate random data: %v", err)
		}
		maxPaddingLen := rng.Intn(256)
		targetPercentage := mrand.Intn(50) + 1
		targetProbability := float64(targetPercentage) / 100.0
		padding, err := newPaddingInto(nil, paddingOpts{
			maxLen: maxPaddingLen,
			entropy: &entropyPaddingOpts{
				targetProbability: targetProbability,
				existingData:      existingData,
			},
		})
		if err != nil {
			t.Fatalf("newPaddingInto() error = %v", err)
		}

		if len(padding) > maxPaddingLen {
			t.Errorf("Padding length %d is bigger than the maximum length %d", len(padding), maxPaddingLen)
		}
		combined := append(existingData, padding...)
		bitDistribution := common.ToBitDistribution(combined)
		if bitDistribution.Bit0 > targetProbability && bitDistribution.Bit1 > targetProbability {
			// Doesn't meet the target.
			// In this case, the padding bits are either all 0 or all 1.
			if !common.IsBitsAllZero(padding) && !common.IsBitsAllOne(padding) {
				t.Errorf("Can't meet target probability %f, but padding %v is not pure 0 bit or 1 bit", targetProbability, padding)
			} else {
				miss++
			}
		} else {
			meet++
		}
	}
	t.Logf("%d paddings meet the target probability; %d paddings miss", meet, miss)
}

// entropyTestData has 21 bits set to 1 and 19 bits set to 0. Together with
// targetProbability 0.325 it yields minPaddingBytes == 3, so the lower bound of
// the entropy padding length used to be 4 bytes, although a padding of 3 bytes
// already contains a bit with the less frequent value.
var entropyTestData = []byte{0x0F, 0xFF, 0x0F, 0x0F, 0x01}

// oldNewPadding is the padding generator before the buffer reuse and the
// padding length variability changes. It is kept in the test as the reference
// of the current implementation, which reads the same package level math/rand
// source.
func oldNewPadding(opts paddingOpts) []byte {
	if opts.ascii != nil {
		if opts.maxLen < opts.ascii.minConsecutiveASCIILen {
			panic(fmt.Sprintf("Invalid padding options: maxLen %d is smaller than minConsecutiveASCIILen %d", opts.maxLen, opts.ascii.minConsecutiveASCIILen))
		}

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
		lower := mathext.Max(minPaddingBytes+1, 1)
		lower = mathext.Min(lower, opts.maxLen)
		length := lower + mrand.Intn(opts.maxLen-lower+1)
		p := make([]byte, length)
		flip := mathext.Max(int(float64(len(opts.entropy.existingData)+length)*8*opts.entropy.targetProbability)-lowerBitCount, 0)
		flip = mathext.Min(flip, length*8)
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

// TestNewPaddingMatchesOldPaddingLength compares the padding length
// distribution of the current implementation with the previous implementation.
// Both of them read the same package level math/rand source, but the padding
// bytes come from crypto/rand, so two calls can't be compared one by one.
// Their length distributions are compared instead: they must be the same,
// except when the previous implementation always generated maxLen, which is the
// constant length the current implementation fixes.
func TestNewPaddingMatchesOldPaddingLength(t *testing.T) {
	const trials = 1000
	testcases := []struct {
		name string
		opts paddingOpts
		// The inclusive range of the padding length the current
		// implementation may generate.
		minLen, maxLen int
		// Whether the previous implementation always generated maxLen, which
		// means the current implementation must generate more than one length.
		oldAlwaysMaxLen bool
		// Whether the padding opts use the entropy strategy, in which case the
		// target probability of the combined data is checked as well.
		checkEntropy bool
	}{
		{
			name:            "ascii maxLen 0",
			opts:            paddingOpts{maxLen: 0, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 0}},
			minLen:          0,
			maxLen:          0,
			oldAlwaysMaxLen: true,
		},
		{
			name:            "ascii maxLen 1",
			opts:            paddingOpts{maxLen: 1, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 1}},
			minLen:          1,
			maxLen:          1,
			oldAlwaysMaxLen: true,
		},
		{
			name:            "ascii maxLen 2",
			opts:            paddingOpts{maxLen: 2, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 2}},
			minLen:          1,
			maxLen:          2,
			oldAlwaysMaxLen: true,
		},
		{
			name:            "ascii minConsecutiveASCIILen equals maxLen",
			opts:            paddingOpts{maxLen: 24, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 24}},
			minLen:          23,
			maxLen:          24,
			oldAlwaysMaxLen: true,
		},
		{
			name:   "ascii minConsecutiveASCIILen below maxLen",
			opts:   paddingOpts{maxLen: 24, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 5}},
			minLen: 5,
			maxLen: 24,
		},
		{
			name:            "entropy only maxLen holds the less frequent bit",
			opts:            paddingOpts{maxLen: 4, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.325}},
			minLen:          3,
			maxLen:          4,
			oldAlwaysMaxLen: true,
			checkEntropy:    true,
		},
		{
			name:         "entropy target reachable within maxLen",
			opts:         paddingOpts{maxLen: 32, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.325}},
			minLen:       4,
			maxLen:       32,
			checkEntropy: true,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			newLengths := map[int]int{}
			oldLengths := map[int]int{}
			for range trials {
				got, err := newPaddingInto(nil, tc.opts)
				if err != nil {
					t.Fatalf("newPaddingInto() error = %v", err)
				}
				want := oldNewPadding(tc.opts)

				if len(got) < tc.minLen || len(got) > tc.maxLen {
					t.Fatalf("newPaddingInto() padding length = %d, want in [%d, %d]", len(got), tc.minLen, tc.maxLen)
				}
				if len(want) < tc.minLen || len(want) > tc.maxLen {
					t.Fatalf("oldNewPadding() padding length = %d, want in [%d, %d]", len(want), tc.minLen, tc.maxLen)
				}
				if tc.oldAlwaysMaxLen && len(want) != tc.maxLen {
					t.Fatalf("oldNewPadding() padding length = %d, want %d", len(want), tc.maxLen)
				}
				if tc.checkEntropy {
					// The padding must still lower the probability of the less
					// frequent bit, or be a pure bit block when the target
					// probability can't be reached.
					combined := append(append([]byte{}, tc.opts.entropy.existingData...), got...)
					dist := common.ToBitDistribution(combined)
					if dist.Bit0 > tc.opts.entropy.targetProbability && dist.Bit1 > tc.opts.entropy.targetProbability {
						if !common.IsBitsAllZero(got) && !common.IsBitsAllOne(got) {
							t.Fatalf("newPaddingInto() can't meet target probability %f, but padding %v is not pure 0 bit or 1 bit", tc.opts.entropy.targetProbability, got)
						}
					}
				}
				newLengths[len(got)]++
				oldLengths[len(want)]++
			}

			newSeen := slices.Sorted(maps.Keys(newLengths))
			oldSeen := slices.Sorted(maps.Keys(oldLengths))
			if tc.minLen < tc.maxLen {
				if len(newSeen) < 2 {
					t.Errorf("newPaddingInto() generated the padding lengths %v, want at least 2 distinct lengths", newSeen)
				}
				// Both the shortest and the longest allowed length must be
				// generated.
				if newSeen[0] != tc.minLen || newSeen[len(newSeen)-1] != tc.maxLen {
					t.Errorf("newPaddingInto() generated the padding lengths %v, want the range [%d, %d]", newSeen, tc.minLen, tc.maxLen)
				}
				if !tc.oldAlwaysMaxLen && !slices.Equal(newSeen, oldSeen) {
					t.Errorf("newPaddingInto() generated the padding lengths %v, oldNewPadding() generated %v", newSeen, oldSeen)
				}
			} else {
				if len(newSeen) != 1 || newSeen[0] != tc.maxLen {
					t.Errorf("newPaddingInto() generated the padding lengths %v, want only %d", newSeen, tc.maxLen)
				}
			}
			if tc.oldAlwaysMaxLen && !slices.Equal(oldSeen, []int{tc.maxLen}) {
				t.Errorf("oldNewPadding() generated the padding lengths %v, want only %d", oldSeen, tc.maxLen)
			}
		})
	}
}

// TestPaddingLengthDistribution verifies the padding length invariants for the
// option shapes buildRecommendedPaddingOpts creates, i.e. the ASCII strategy
// with minConsecutiveASCIILen equal to the smaller of maxLen and
// recommendedConsecutiveASCIILen, and the entropy strategy.
func TestPaddingLengthDistribution(t *testing.T) {
	const trials = 1000
	seenLengths := func(opts paddingOpts) []int {
		seen := map[int]int{}
		for range trials {
			padding, err := newPaddingInto(nil, opts)
			if err != nil {
				t.Fatalf("newPaddingInto() error = %v", err)
			}
			seen[len(padding)]++
		}
		return slices.Sorted(maps.Keys(seen))
	}

	// The ASCII strategy, with the option shapes of buildRecommendedPaddingOpts.
	for maxLen := range recommendedConsecutiveASCIILen + 2 {
		minConsecutiveASCIILen := mathext.Min(maxLen, recommendedConsecutiveASCIILen)
		lengths := seenLengths(paddingOpts{
			maxLen: maxLen,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: minConsecutiveASCIILen,
			},
		})

		if maxLen == 0 {
			if !slices.Equal(lengths, []int{0}) {
				t.Errorf("ASCII padding with maxLen 0 generated the lengths %v, want [0]", lengths)
			}
			continue
		}
		if lengths[0] < 1 {
			t.Errorf("ASCII padding with maxLen %d generated the length %d, want at least 1", maxLen, lengths[0])
		}
		if lengths[len(lengths)-1] != maxLen {
			t.Errorf("ASCII padding with maxLen %d generated the lengths %v, want the longest length %d", maxLen, lengths, maxLen)
		}
		if maxLen == 1 {
			if len(lengths) != 1 {
				t.Errorf("ASCII padding with maxLen 1 generated the lengths %v, want a single length", lengths)
			}
			continue
		}
		if len(lengths) < 2 {
			t.Errorf("ASCII padding with maxLen %d generated the lengths %v, want at least 2 distinct lengths", maxLen, lengths)
		}
		if maxLen <= recommendedConsecutiveASCIILen && lengths[0] != maxLen-1 {
			t.Errorf("ASCII padding with maxLen %d generated the lengths %v, want the shortest length %d", maxLen, lengths, maxLen-1)
		}
	}

	// The entropy strategy.
	for maxLen := range 9 {
		lengths := seenLengths(paddingOpts{
			maxLen: maxLen,
			entropy: &entropyPaddingOpts{
				existingData:      entropyTestData,
				targetProbability: 0.325,
			},
		})

		if maxLen == 0 {
			if !slices.Equal(lengths, []int{0}) {
				t.Errorf("entropy padding with maxLen 0 generated the lengths %v, want [0]", lengths)
			}
			continue
		}
		if lengths[0] < 1 {
			t.Errorf("entropy padding with maxLen %d generated the length %d, want at least 1", maxLen, lengths[0])
		}
		if lengths[len(lengths)-1] != maxLen {
			t.Errorf("entropy padding with maxLen %d generated the lengths %v, want the longest length %d", maxLen, lengths, maxLen)
		}
		if maxLen == 1 {
			if len(lengths) != 1 {
				t.Errorf("entropy padding with maxLen 1 generated the lengths %v, want a single length", lengths)
			}
			continue
		}
		if len(lengths) < 2 {
			t.Errorf("entropy padding with maxLen %d generated the lengths %v, want at least 2 distinct lengths", maxLen, lengths)
		}
	}
}

// TestNewPaddingIntoReusesDst verifies that newPaddingInto writes the padding
// into the buffer of the caller, so that generating the padding of every
// message doesn't allocate a buffer per message.
func TestNewPaddingIntoReusesDst(t *testing.T) {
	prefix := []byte("prefix")
	testcases := []struct {
		name           string
		opts           paddingOpts
		minLen, maxLen int
	}{
		{
			name:   "ascii",
			opts:   paddingOpts{maxLen: 32, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 8}},
			minLen: 8,
			maxLen: 32,
		},
		{
			name:   "ascii maxLen 0",
			opts:   paddingOpts{maxLen: 0, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 0}},
			minLen: 0,
			maxLen: 0,
		},
		{
			name:   "entropy",
			opts:   paddingOpts{maxLen: 16, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.325}},
			minLen: 4,
			maxLen: 16,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			scratch := make([]byte, len(prefix), len(prefix)+tc.opts.maxLen)
			copy(scratch, prefix)
			firstByte := &scratch[0]

			out, err := newPaddingInto(scratch, tc.opts)
			if err != nil {
				t.Fatalf("newPaddingInto() error = %v", err)
			}
			if len(out) == 0 || &out[0] != firstByte {
				t.Errorf("newPaddingInto() didn't write the padding into dst")
			}
			padding := out[len(prefix):]
			if len(out) != len(prefix)+len(padding) {
				t.Errorf("newPaddingInto() returned %d bytes, want %d", len(out), len(prefix)+len(padding))
			}
			if cap(out) != cap(scratch) {
				t.Errorf("newPaddingInto() returned a buffer of capacity %d, want %d", cap(out), cap(scratch))
			}
			if string(out[:len(prefix)]) != string(prefix) {
				t.Errorf("newPaddingInto() overwrote the existing dst content with %q", out[:len(prefix)])
			}
			if len(padding) < tc.minLen || len(padding) > tc.maxLen {
				t.Errorf("newPaddingInto() padding length = %d, want in [%d, %d]", len(padding), tc.minLen, tc.maxLen)
			}
			if len(padding) > 0 && tc.opts.ascii != nil {
				if printable := common.MaxConsecutivePrintableLength(padding); printable < 1 {
					t.Errorf("newPaddingInto() padding %v contains no printable ASCII byte", padding)
				}
			}

			// The padding can also be generated without a caller buffer, and
			// the length bounds stay the same.
			standalone, err := newPaddingInto(nil, tc.opts)
			if err != nil {
				t.Fatalf("newPaddingInto() error = %v", err)
			}
			if len(standalone) < tc.minLen || len(standalone) > tc.maxLen {
				t.Errorf("newPaddingInto() padding length = %d, want in [%d, %d]", len(standalone), tc.minLen, tc.maxLen)
			}
		})
	}
}

// TestNewPaddingIntoAllocations verifies that newPaddingInto allocates nothing
// when the caller provides a scratch buffer of enough capacity, while the
// previous implementation, which always allocated its own buffer, allocates
// exactly one buffer per call.
func TestNewPaddingIntoAllocations(t *testing.T) {
	const runs = 100
	testcases := []struct {
		name string
		opts paddingOpts
		// The number of buffers oldNewPadding is expected to allocate, which
		// is also the number of allocations newPaddingInto saves.
		wantSavedAllocs float64
	}{
		{
			name:            "ascii",
			opts:            paddingOpts{maxLen: 255, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 24}},
			wantSavedAllocs: 1,
		},
		{
			name:            "entropy",
			opts:            paddingOpts{maxLen: 255, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.325}},
			wantSavedAllocs: 1,
		},
		{
			name:            "ascii maxLen 0",
			opts:            paddingOpts{maxLen: 0, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 0}},
			wantSavedAllocs: 0,
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			scratch := make([]byte, 0, tc.opts.maxLen)
			var out []byte
			var err error
			allocsInto := testing.AllocsPerRun(runs, func() {
				out, err = newPaddingInto(scratch, tc.opts)
			})
			if err != nil {
				t.Fatalf("newPaddingInto() error = %v", err)
			}
			if len(out) > tc.opts.maxLen {
				t.Fatalf("newPaddingInto() padding length = %d, want at most %d", len(out), tc.opts.maxLen)
			}
			if allocsInto != 0 {
				t.Errorf("newPaddingInto() with a reusable buffer allocated %v buffers per call, want 0", allocsInto)
			}

			var padding []byte
			allocsOld := testing.AllocsPerRun(runs, func() {
				padding = oldNewPadding(tc.opts)
			})
			if len(padding) > tc.opts.maxLen {
				t.Fatalf("oldNewPadding() padding length = %d, want at most %d", len(padding), tc.opts.maxLen)
			}
			if saved := allocsOld - allocsInto; saved != tc.wantSavedAllocs {
				t.Errorf("oldNewPadding() allocated %v buffers per call and newPaddingInto() allocated %v, want a difference of %v", allocsOld, allocsInto, tc.wantSavedAllocs)
			}
		})
	}
}

// TestNewPaddingIntoError verifies that invalid padding options are reported
// with an error, that a nil padding is returned, and that the buffer of the
// caller is not modified.
func TestNewPaddingIntoError(t *testing.T) {
	testcases := []struct {
		name string
		opts paddingOpts
	}{
		{
			name: "ASCII maxLen smaller than minConsecutiveASCIILen",
			opts: paddingOpts{maxLen: 3, ascii: &asciiPaddingOpts{minConsecutiveASCIILen: 4}},
		},
		{
			name: "entropy targetProbability too big",
			opts: paddingOpts{maxLen: 8, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.75}},
		},
		{
			name: "entropy targetProbability zero",
			opts: paddingOpts{maxLen: 8, entropy: &entropyPaddingOpts{existingData: entropyTestData, targetProbability: 0.0}},
		},
		{
			name: "no padding options",
			opts: paddingOpts{maxLen: 8},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dst := []byte("dst content")
			out, err := newPaddingInto(dst, tc.opts)
			if err == nil {
				t.Fatalf("newPaddingInto() error = nil, want non-nil")
			}
			if out != nil {
				t.Errorf("newPaddingInto() = %v, want nil", out)
			}
			if string(dst) != "dst content" {
				t.Errorf("newPaddingInto() modified dst to %q", dst)
			}

			// The padding generated without a caller buffer is rejected the
			// same way.
			out, err = newPaddingInto(nil, tc.opts)
			if err == nil {
				t.Fatalf("newPaddingInto() error = nil, want non-nil")
			}
			if out != nil {
				t.Errorf("newPaddingInto() = %v, want nil", out)
			}
		})
	}
}
