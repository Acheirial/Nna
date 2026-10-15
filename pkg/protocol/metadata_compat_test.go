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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package protocol

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// stampTimestamp overwrites bytes 2-5 with the current minute.
//
// Both sessionStruct.Unmarshal and dataAckStruct.Unmarshal reject a metadata
// buffer whose timestamp is not within one minute of the local clock
// (see mathext.WithinRange with margin 1). A byte-exact golden vector can
// therefore not carry a hard-coded literal timestamp, so the template keeps
// bytes 2-5 as zeros and this helper stamps "now" into them.
func stampTimestamp(t *testing.T, template []byte) []byte {
	t.Helper()
	if len(template) != MetadataLength {
		t.Fatalf("template length = %d, want %d", len(template), MetadataLength)
	}
	b := append([]byte(nil), template...)
	binary.BigEndian.PutUint32(b[2:], uint32(time.Now().Unix()/60))
	return b
}

// newMetadataForProtocol picks the concrete metadata implementation that
// Unmarshal must be called on, based on the protocol byte at offset 0.
func newMetadataForProtocol(b []byte) metadata {
	if isSessionProtocol(protocolType(b[0])) {
		return &sessionStruct{}
	}
	return &dataAckStruct{}
}

func TestMetadataWireFormatGolden(t *testing.T) {
	tests := []struct {
		name     string
		hexBytes string
		verify   func(t *testing.T, m metadata)
	}{
		{
			// 00:      protocol = openSessionRequest (2)
			// 01:      type-specific / reserved = 0
			// 02-05:   timestamp, stamped at run time
			// 06-09:   sessionID = 0x11223344
			// 10-13:   seq = 0x55667788
			// 14:      statusCode = statusOK (0)
			// 15-16:   payloadLen = 0x0100 = 256
			// 17:      suffixLen = 0x7f
			// 18-31:   reserved = 0
			name:     "session_open_session_request",
			hexBytes: "02000000000011223344556677880001007f0000000000000000000000000000",
			verify: func(t *testing.T, m metadata) {
				ss, ok := toSessionStruct(m)
				if !ok {
					t.Fatalf("toSessionStruct() returned false for %v", m.Protocol())
				}
				if got := ss.Protocol(); got != openSessionRequest {
					t.Errorf("protocol = %v, want %v", got, openSessionRequest)
				}
				if got := ss.sessionID; got != 0x11223344 {
					t.Errorf("sessionID = %#x, want 0x11223344", got)
				}
				if got := ss.seq; got != 0x55667788 {
					t.Errorf("seq = %#x, want 0x55667788", got)
				}
				if got := statusCode(ss.statusCode); got != statusOK {
					t.Errorf("statusCode = %v, want %v", got, statusOK)
				}
				if got := ss.payloadLen; got != 256 {
					t.Errorf("payloadLen = %d, want 256", got)
				}
				if got := ss.suffixLen; got != 0x7f {
					t.Errorf("suffixLen = %#x, want 0x7f", got)
				}
			},
		},
		{
			// 00:      protocol = dataServerToClient (7)
			// 01:      reserved (not read for non-low-entropy data) = 0
			// 02-05:   timestamp, stamped at run time
			// 06-09:   sessionID = 0xa1a2a3a4
			// 10-13:   seq = 0xb1b2b3b4
			// 14-17:   unAckSeq = 0xc1c2c3c4
			// 18-19:   windowSize = 0x0100 = 256
			// 20:      fragment = 0
			// 21:      prefixLen = 0
			// 22-23:   payloadLen = 0x1234 = 4660
			// 24:      suffixLen = 0x7f
			// 25-31:   reserved (low entropy fields, not written for this protocol) = 0
			name:     "data_server_to_client",
			hexBytes: "070000000000a1a2a3a4b1b2b3b4c1c2c3c40100000012347f00000000000000",
			verify: func(t *testing.T, m metadata) {
				das, ok := toDataAckStruct(m)
				if !ok {
					t.Fatalf("toDataAckStruct() returned false for %v", m.Protocol())
				}
				if got := das.Protocol(); got != dataServerToClient {
					t.Errorf("protocol = %v, want %v", got, dataServerToClient)
				}
				if got := das.sessionID; got != 0xa1a2a3a4 {
					t.Errorf("sessionID = %#x, want 0xa1a2a3a4", got)
				}
				if got := das.seq; got != 0xb1b2b3b4 {
					t.Errorf("seq = %#x, want 0xb1b2b3b4", got)
				}
				if got := das.unAckSeq; got != 0xc1c2c3c4 {
					t.Errorf("unAckSeq = %#x, want 0xc1c2c3c4", got)
				}
				if got := das.windowSize; got != 256 {
					t.Errorf("windowSize = %d, want 256", got)
				}
				if got := das.fragment; got != 0 {
					t.Errorf("fragment = %d, want 0", got)
				}
				if got := das.prefixLen; got != 0 {
					t.Errorf("prefixLen = %d, want 0", got)
				}
				if got := das.payloadLen; got != 0x1234 {
					t.Errorf("payloadLen = %#x, want 0x1234", got)
				}
				if got := das.suffixLen; got != 0x7f {
					t.Errorf("suffixLen = %#x, want 0x7f", got)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			template, err := hex.DecodeString(test.hexBytes)
			if err != nil {
				t.Fatalf("hex.DecodeString() failed: %v", err)
			}
			want := stampTimestamp(t, template)

			got := newMetadataForProtocol(want)
			if err := got.Unmarshal(want); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			test.verify(t, got)

			// Marshal() rewrites the timestamp bytes to the current minute
			// (metadata.go: sessionStruct.Marshal b[2:], dataAckStruct.Marshal
			// b[2:]). Everything else must round-trip byte for byte, so bytes
			// 2-5 are excluded from the comparison to stay robust across a
			// minute boundary.
			gotBytes := got.Marshal()
			if len(gotBytes) != MetadataLength {
				t.Fatalf("Marshal() length = %d, want %d", len(gotBytes), MetadataLength)
			}
			for i := range want {
				if i >= 2 && i < 6 {
					continue
				}
				if gotBytes[i] != want[i] {
					t.Errorf("Marshal() byte %d = %#x, want %#x", i, gotBytes[i], want[i])
				}
			}
		})
	}
}

func TestMetadataLegacyBytesCompatibility(t *testing.T) {
	// assertReservedIgnored checks that the reserved tail of a non-low-entropy
	// dataAck metadata (byte 1 and bytes 25-31) is parsed but never rejected.
	assertReservedIgnored := func(t *testing.T, das *dataAckStruct) {
		t.Helper()
		if das.lowEntropyMode != 0 {
			t.Errorf("lowEntropyMode = %d, want 0 (reserved byte 1 must be ignored)", das.lowEntropyMode)
		}
		if das.lowEntropyMask != 0 {
			t.Errorf("lowEntropyMask = %#x, want 0 (bytes 25-28 must be ignored)", das.lowEntropyMask)
		}
		if das.extractedPayloadLen != 0 {
			t.Errorf("extractedPayloadLen = %d, want 0 (bytes 29-30 must be ignored)", das.extractedPayloadLen)
		}
		if das.lowEntropyMaskRotation != 0 {
			t.Errorf("lowEntropyMaskRotation = %d, want 0 (byte 31 must be ignored)", das.lowEntropyMaskRotation)
		}
	}

	tests := []struct {
		name     string
		template []byte
		verify   func(t *testing.T, m metadata)
	}{
		{
			// A legacy non-low-entropy data segment: empty payload, maximal
			// suffix padding, in-flight fragment, prefix padding, and garbage
			// in the reserved byte 1 / bytes 25-31 that a future-looking or
			// older implementation may have left non-zero.
			name: "legacy_data_zero_payload_nonzero_reserved",
			template: []byte{
				byte(dataClientToServer), 0xff, // 0-1: protocol, reserved
				0x00, 0x00, 0x00, 0x00, // 2-5: timestamp (stamped later)
				0x01, 0x02, 0x03, 0x04, // 6-9: sessionID
				0x05, 0x06, 0x07, 0x08, // 10-13: seq
				0x09, 0x0a, 0x0b, 0x0c, // 14-17: unAckSeq
				0x02, 0x00, // 18-19: windowSize
				0x05,       // 20: fragment
				0x09,       // 21: prefixLen
				0x00, 0x00, // 22-23: payloadLen
				0xff,                   // 24: suffixLen
				0xde, 0xad, 0xbe, 0xef, // 25-28: reserved
				0xca, 0xfe, // 29-30: reserved
				0xba, // 31: reserved
			},
			verify: func(t *testing.T, m metadata) {
				das, ok := toDataAckStruct(m)
				if !ok {
					t.Fatalf("toDataAckStruct() returned false for %v", m.Protocol())
				}
				if das.sessionID != 0x01020304 || das.seq != 0x05060708 || das.unAckSeq != 0x090a0b0c {
					t.Errorf("IDs parsed wrong: sessionID=%#x seq=%#x unAckSeq=%#x", das.sessionID, das.seq, das.unAckSeq)
				}
				if das.windowSize != 0x0200 {
					t.Errorf("windowSize = %#x, want 0x0200", das.windowSize)
				}
				if das.fragment != 0x05 {
					t.Errorf("fragment = %#x, want 0x05", das.fragment)
				}
				if das.prefixLen != 0x09 {
					t.Errorf("prefixLen = %#x, want 0x09", das.prefixLen)
				}
				if das.payloadLen != 0 {
					t.Errorf("payloadLen = %d, want 0", das.payloadLen)
				}
				if das.suffixLen != 0xff {
					t.Errorf("suffixLen = %#x, want 0xff", das.suffixLen)
				}
				assertReservedIgnored(t, das)
			},
		},
		{
			// A legacy ACK segment with garbage in the reserved byte 1 and
			// bytes 25-31.
			name: "legacy_ack_nonzero_reserved",
			template: []byte{
				byte(ackClientToServer), 0xee, // 0-1: protocol, reserved
				0x00, 0x00, 0x00, 0x00, // 2-5: timestamp (stamped later)
				0x10, 0x20, 0x30, 0x40, // 6-9: sessionID
				0x50, 0x60, 0x70, 0x80, // 10-13: ack number
				0x90, 0xa0, 0xb0, 0xc0, // 14-17: unAckSeq
				0x04, 0x00, // 18-19: windowSize
				0x00,       // 20: fragment
				0x00,       // 21: prefixLen
				0x00, 0x00, // 22-23: payloadLen
				0xff,                   // 24: suffixLen
				0x11, 0x22, 0x33, 0x44, // 25-28: reserved
				0x55, 0x66, // 29-30: reserved
				0x77, // 31: reserved
			},
			verify: func(t *testing.T, m metadata) {
				das, ok := toDataAckStruct(m)
				if !ok {
					t.Fatalf("toDataAckStruct() returned false for %v", m.Protocol())
				}
				if das.seq != 0x50607080 {
					t.Errorf("seq = %#x, want 0x50607080", das.seq)
				}
				if das.payloadLen != 0 {
					t.Errorf("payloadLen = %d, want 0", das.payloadLen)
				}
				if das.suffixLen != 0xff {
					t.Errorf("suffixLen = %#x, want 0xff", das.suffixLen)
				}
				assertReservedIgnored(t, das)
			},
		},
		{
			// A legacy session segment with garbage in the reserved byte 1 and
			// bytes 18-31; Unmarshal only reads bytes 0-17 for sessions.
			name: "legacy_session_nonzero_reserved",
			template: []byte{
				byte(openSessionResponse), 0xcc, // 0-1: protocol, reserved
				0x00, 0x00, 0x00, 0x00, // 2-5: timestamp (stamped later)
				0x11, 0x22, 0x33, 0x44, // 6-9: sessionID
				0x55, 0x66, 0x77, 0x88, // 10-13: seq
				0x00,       // 14: statusCode
				0x00, 0x00, // 15-16: payloadLen
				0xff,                                           // 17: suffixLen
				0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // 18-25: reserved
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // 26-31: reserved
			},
			verify: func(t *testing.T, m metadata) {
				ss, ok := toSessionStruct(m)
				if !ok {
					t.Fatalf("toSessionStruct() returned false for %v", m.Protocol())
				}
				if ss.sessionID != 0x11223344 {
					t.Errorf("sessionID = %#x, want 0x11223344", ss.sessionID)
				}
				if ss.seq != 0x55667788 {
					t.Errorf("seq = %#x, want 0x55667788", ss.seq)
				}
				if ss.payloadLen != 0 {
					t.Errorf("payloadLen = %d, want 0", ss.payloadLen)
				}
				if ss.suffixLen != 0xff {
					t.Errorf("suffixLen = %#x, want 0xff", ss.suffixLen)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b := stampTimestamp(t, test.template)
			got := newMetadataForProtocol(b)
			if err := got.Unmarshal(b); err != nil {
				t.Fatalf("Unmarshal() failed: %v", err)
			}
			test.verify(t, got)
		})
	}
}

func TestMetadataPayloadLenBoundary(t *testing.T) {
	// The upper boundary maxPDU+1 for a non-low-entropy data segment is
	// already covered by TestDataAckStruct/payload_len_exceeds_max_pdu; only
	// the inclusive lower-side boundary maxPDU is asserted here.
	t.Run("payload_len_equals_max_pdu", func(t *testing.T) {
		s := &dataAckStruct{
			baseStruct: baseStruct{protocol: uint8(dataServerToClient)},
			payloadLen: maxPDU,
		}
		got := &dataAckStruct{}
		if err := got.Unmarshal(s.Marshal()); err != nil {
			t.Fatalf("Unmarshal() failed: %v", err)
		}
		if got.payloadLen != maxPDU {
			t.Errorf("payloadLen = %d, want %d", got.payloadLen, maxPDU)
		}
	})
}
