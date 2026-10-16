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

package appctl

import (
	"slices"
	"strings"
	"testing"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"google.golang.org/protobuf/proto"
)

func newClientProfileWithCipherSuites() *pb.ClientProfile {
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
		CipherSuites: []pb.CipherSuite{
			pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
			pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305,
		},
	}
}

// TestClientConfigCipherSuitesURL verifies that the mieru:// sharing link,
// which carries the whole client config as protobuf, round trips cipher suites.
func TestClientConfigCipherSuitesURL(t *testing.T) {
	config := &pb.ClientConfig{
		Profiles:      []*pb.ClientProfile{newClientProfileWithCipherSuites()},
		ActiveProfile: proto.String("default"),
		Socks5Port:    proto.Int32(1080),
	}
	u, err := ClientConfigToURL(config)
	if err != nil {
		t.Fatalf("ClientConfigToURL() failed: %v", err)
	}
	got, err := URLToClientConfig(u)
	if err != nil {
		t.Fatalf("URLToClientConfig() failed: %v", err)
	}
	if !proto.Equal(got, config) {
		t.Fatalf("URL round trip produced %v, want %v", got, config)
	}
}

// TestClientProfileCipherSuitesSimpleURL verifies that the mierus:// sharing
// link, which encodes each field by hand, round trips cipher suites too.
func TestClientProfileCipherSuitesSimpleURL(t *testing.T) {
	profile := newClientProfileWithCipherSuites()
	urls, err := ClientProfileToMultiURLs(profile)
	if err != nil {
		t.Fatalf("ClientProfileToMultiURLs() failed: %v", err)
	}
	if len(urls) != 1 {
		t.Fatalf("ClientProfileToMultiURLs() returned %d URLs, want 1", len(urls))
	}
	if !strings.Contains(urls[0], "cipher-suites=") {
		t.Fatalf("URL %q doesn't contain cipher suites", urls[0])
	}
	got, err := URLToClientProfile(urls[0])
	if err != nil {
		t.Fatalf("URLToClientProfile() failed: %v", err)
	}
	if !slices.Equal(got.GetCipherSuites(), profile.GetCipherSuites()) {
		t.Fatalf("URL round trip produced cipher suites %v, want %v", got.GetCipherSuites(), profile.GetCipherSuites())
	}

	// A cipher suite that doesn't exist is rejected instead of being
	// silently replaced by the default suite.
	badURL := strings.Replace(urls[0], "CIPHER_SUITE_AES_256_GCM", "CIPHER_SUITE_UNKNOWN", 1)
	if _, err := URLToClientProfile(badURL); err == nil {
		t.Fatal("URL with an unknown cipher suite is accepted")
	}
}

// TestClientConfigCipherSuitesJSON verifies that cipher suites survive a JSON
// round trip through the encoding used by "mieru apply/replace/describe config".
func TestClientConfigCipherSuitesJSON(t *testing.T) {
	config := &pb.ClientConfig{
		Profiles:      []*pb.ClientProfile{newClientProfileWithCipherSuites()},
		ActiveProfile: proto.String("default"),
		Socks5Port:    proto.Int32(1080),
	}
	b, err := common.MarshalJSON(config)
	if err != nil {
		t.Fatalf("common.MarshalJSON() failed: %v", err)
	}
	for _, want := range []string{`"cipherSuites"`, `"CIPHER_SUITE_AES_256_GCM"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("marshaled JSON %s doesn't contain %s", string(b), want)
		}
	}
	decoded := &pb.ClientConfig{}
	if err := common.UnmarshalJSON(b, decoded); err != nil {
		t.Fatalf("common.UnmarshalJSON() failed: %v", err)
	}
	if err := ValidateFullClientConfig(decoded); err != nil {
		t.Fatalf("ValidateFullClientConfig() failed: %v", err)
	}
	if !proto.Equal(decoded, config) {
		t.Fatalf("JSON round trip produced %v, want %v", decoded, config)
	}

	// An unspecified cipher suite in JSON is rejected by validation.
	badJSON := strings.Replace(string(b), "CIPHER_SUITE_AES_256_GCM", "CIPHER_SUITE_UNSPECIFIED", 1)
	bad := &pb.ClientConfig{}
	if err := common.UnmarshalJSON([]byte(badJSON), bad); err != nil {
		t.Fatalf("common.UnmarshalJSON() failed: %v", err)
	}
	err = ValidateFullClientConfig(bad)
	if err == nil {
		t.Fatal("config with CIPHER_SUITE_UNSPECIFIED is accepted")
	}
	if want := "client profile cipherSuites[0] is CIPHER_SUITE_UNSPECIFIED"; !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateFullClientConfig() error = %q, want it to contain %q", err.Error(), want)
	}
}

func TestServerConfigCipherSuites(t *testing.T) {
	// The server allows every supported cipher suite when the list is empty.
	config := &pb.ServerConfig{
		PortBindings: []*pb.PortBinding{
			{
				Port:     proto.Int32(8964),
				Protocol: pb.TransportProtocol_TCP.Enum(),
			},
		},
		CipherSuites: []pb.CipherSuite{
			pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
			pb.CipherSuite_CIPHER_SUITE_AES_128_GCM,
		},
	}
	if err := ValidateServerConfigPatch(config); err != nil {
		t.Fatalf("ValidateServerConfigPatch() failed: %v", err)
	}

	bad := &pb.ServerConfig{
		PortBindings: config.GetPortBindings(),
		CipherSuites: []pb.CipherSuite{
			pb.CipherSuite_CIPHER_SUITE_AES_256_GCM,
			pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED,
		},
	}
	err := ValidateServerConfigPatch(bad)
	if err == nil {
		t.Fatal("server config with CIPHER_SUITE_UNSPECIFIED is accepted")
	}
	if want := "server config cipherSuites[1] is CIPHER_SUITE_UNSPECIFIED"; err.Error() != want {
		t.Fatalf("ValidateServerConfigPatch() error = %q, want %q", err.Error(), want)
	}

	// A patch that doesn't set cipher suites preserves the stored value.
	stored := &pb.ServerConfig{
		PortBindings: config.GetPortBindings(),
		CipherSuites: []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305},
	}
	patch := &pb.ServerConfig{
		Users: []*pb.User{
			{
				Name:     proto.String("user1"),
				Password: proto.String("password1"),
			},
		},
	}
	if err := MergeServerConfig(stored, patch); err != nil {
		t.Fatalf("MergeServerConfig() failed: %v", err)
	}
	want := []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305}
	if !slices.Equal(stored.GetCipherSuites(), want) {
		t.Fatalf("merged cipher suites = %v, want %v", stored.GetCipherSuites(), want)
	}

	// A patch that sets cipher suites replaces the stored value.
	stored.CipherSuites = want
	patch.CipherSuites = []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_AES_128_GCM}
	if err := MergeServerConfig(stored, patch); err != nil {
		t.Fatalf("MergeServerConfig() failed: %v", err)
	}
	want = []pb.CipherSuite{pb.CipherSuite_CIPHER_SUITE_AES_128_GCM}
	if !slices.Equal(stored.GetCipherSuites(), want) {
		t.Fatalf("merged cipher suites = %v, want %v", stored.GetCipherSuites(), want)
	}
}
