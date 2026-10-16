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

package appctlcommon

import (
	"slices"
	"strings"
	"testing"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"google.golang.org/protobuf/proto"
)

func TestValidateCipherSuiteList(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		suites  []pb.CipherSuite
		want    []cipher.Suite
		wantErr string
	}{
		{
			name:   "unset list",
			field:  "client profile cipherSuites",
			suites: nil,
			want:   []cipher.Suite{},
		},
		{
			name:   "empty list",
			field:  "client profile cipherSuites",
			suites: []pb.CipherSuite{},
			want:   []cipher.Suite{},
		},
		{
			name:   "xchacha20 poly1305",
			field:  "client profile cipherSuites",
			suites: []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305},
			want:   []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
		},
		{
			name:   "aes 256 gcm",
			field:  "server config cipherSuites",
			suites: []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_AES_256_GCM},
			want:   []cipher.Suite{cipher.SuiteAES256GCM},
		},
		{
			name:   "aes 128 gcm",
			field:  "server config cipherSuites",
			suites: []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_AES_128_GCM},
			want:   []cipher.Suite{cipher.SuiteAES128GCM},
		},
		{
			name:  "preference order is preserved",
			field: "client profile cipherSuites",
			suites: []pb.CipherSuite{
				pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
				pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305,
				pb.CipherSuite_CIPHER_SUITE_AES_128_GCM,
			},
			want: []cipher.Suite{
				cipher.SuiteAES256GCM,
				cipher.SuiteXChaCha20Poly1305,
				cipher.SuiteAES128GCM,
			},
		},
		{
			name:  "duplicated suites are removed",
			field: "client profile cipherSuites",
			suites: []pb.CipherSuite{
				pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
				pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
				pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305,
			},
			want: []cipher.Suite{
				cipher.SuiteAES256GCM,
				cipher.SuiteXChaCha20Poly1305,
			},
		},
		{
			name:    "unspecified is rejected at index 0",
			field:   "client profile cipherSuites",
			suites:  []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED},
			wantErr: "client profile cipherSuites[0] is CIPHER_SUITE_UNSPECIFIED",
		},
		{
			name:  "unspecified is rejected at a later index",
			field: "server config cipherSuites",
			suites: []pb.CipherSuite{
				pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
				pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED,
			},
			wantErr: "server config cipherSuites[1] is CIPHER_SUITE_UNSPECIFIED",
		},
		{
			name:    "unknown value is rejected",
			field:   "server config cipherSuites",
			suites:  []pb.CipherSuite{pb.CipherSuite(9)},
			wantErr: "server config cipherSuites[0] is not a supported cipher suite, got value 9",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateCipherSuiteList(tc.field, tc.suites)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("ValidateCipherSuiteList() succeeded, want error %q", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("ValidateCipherSuiteList() error = %q, want %q", err.Error(), tc.wantErr)
				}
				if got != nil {
					t.Fatalf("ValidateCipherSuiteList() result = %v, want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateCipherSuiteList() failed: %v", err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("ValidateCipherSuiteList() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCipherSuiteToProtoCipherSuite(t *testing.T) {
	for _, test := range []struct {
		suite cipher.Suite
		want  pb.CipherSuite
	}{
		{cipher.SuiteXChaCha20Poly1305, pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305},
		{cipher.SuiteAES256GCM, pb.CipherSuite_CIPHER_SUITE_AES_256_GCM},
		{cipher.SuiteAES128GCM, pb.CipherSuite_CIPHER_SUITE_AES_128_GCM},
	} {
		t.Run(test.suite.String(), func(t *testing.T) {
			got, found := CipherSuiteToProtoCipherSuite(test.suite)
			if !found {
				t.Fatalf("CipherSuiteToProtoCipherSuite(%d) is not found", test.suite)
			}
			if got != test.want {
				t.Fatalf("CipherSuiteToProtoCipherSuite(%d) = %v, want %v", test.suite, got, test.want)
			}
			// Converting back must return the original suite.
			roundTrip, err := ValidateCipherSuiteList("test cipherSuites", []pb.CipherSuite{got})
			if err != nil {
				t.Fatalf("ValidateCipherSuiteList() failed: %v", err)
			}
			if len(roundTrip) != 1 || roundTrip[0] != test.suite {
				t.Fatalf("round trip of suite %d = %v, want %d", test.suite, roundTrip, test.suite)
			}
		})
	}
	if _, found := CipherSuiteToProtoCipherSuite(cipher.Suite(42)); found {
		t.Fatal("CipherSuiteToProtoCipherSuite(42) is found, want not found")
	}
}

func TestClientProfileCipherSuitesValidation(t *testing.T) {
	profile := newValidClientProfile()
	if err := ValidateClientConfigSingleProfile(profile); err != nil {
		t.Fatalf("ValidateClientConfigSingleProfile() failed without cipher suites: %v", err)
	}

	profile.CipherSuites = []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED}
	err := ValidateClientConfigSingleProfile(profile)
	if err == nil {
		t.Fatal("profile with CIPHER_SUITE_UNSPECIFIED is accepted")
	}
	if want := "client profile cipherSuites[0] is CIPHER_SUITE_UNSPECIFIED"; err.Error() != want {
		t.Fatalf("ValidateClientConfigSingleProfile() error = %q, want %q", err.Error(), want)
	}

	profile.CipherSuites = []pb.CipherSuite{pb.CipherSuite(7)}
	if err := ValidateClientConfigSingleProfile(profile); err == nil {
		t.Fatal("profile with an unknown cipher suite is accepted")
	}

	// A duplicated suite is not an error.
	profile.CipherSuites = []pb.CipherSuite{
		pb.CipherSuite_CIPHER_SUITE_AES_128_GCM,
		pb.CipherSuite_CIPHER_SUITE_AES_128_GCM,
	}
	if err := ValidateClientConfigSingleProfile(profile); err != nil {
		t.Fatalf("profile with a duplicated cipher suite is rejected: %v", err)
	}
}

func TestClientProfileCipherSuitesJSON(t *testing.T) {
	profile := newValidClientProfile()
	profile.CipherSuites = []pb.CipherSuite{
		pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
		pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305,
	}

	b, err := common.MarshalJSON(profile)
	if err != nil {
		t.Fatalf("common.MarshalJSON() failed: %v", err)
	}
	for _, want := range []string{
		`"cipherSuites"`,
		`"CIPHER_SUITE_AES_256_GCM"`,
		`"CIPHER_SUITE_XCHACHA20_POLY1305"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("marshaled JSON %s doesn't contain %s", string(b), want)
		}
	}

	decoded := &pb.ClientProfile{}
	if err := common.UnmarshalJSON(b, decoded); err != nil {
		t.Fatalf("common.UnmarshalJSON() failed: %v", err)
	}
	if !proto.Equal(decoded, profile) {
		t.Fatalf("JSON round trip produced %v, want %v", decoded, profile)
	}
}

func newValidClientProfile() *pb.ClientProfile {
	return &pb.ClientProfile{
		ProfileName: proto.String("default"),
		User: &pb.User{
			Name:     proto.String("user1"),
			Password: proto.String("password1"),
		},
		Servers: []*pb.ServerEndpoint{
			{
				IpAddress: proto.String("12.34.56.78"),
				PortBindings: []*pb.PortBinding{
					{
						PortRange: proto.String("2012-2022"),
						Protocol:  pb.TransportProtocol_TCP.Enum(),
					},
				},
			},
		},
	}
}
