// Copyright (C) 2021  mieru authors
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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
	"google.golang.org/protobuf/proto"
)

const (
	EnvMieruConfigFile     = "MIERU_CONFIG_FILE"
	EnvMieruConfigJSONFile = "MIERU_CONFIG_JSON_FILE"
)

var (
	// clientIOLock is required to load client config and store client config.
	clientIOLock sync.Mutex

	// cachedClientConfigDir is the absolute path of client config directory.
	//
	// In Linux, it is typically /home/<user>/.config/mieru
	//
	// In Mac OS, it is typically /Users/<user>/Library/Application Support/mieru
	//
	// In Windows, it is typically C:\Users\<user>\AppData\Roaming\mieru
	cachedClientConfigDir string

	// cachedClientConfigFilePath is the absolute path of client config file.
	cachedClientConfigFilePath string
)

// GetJSONClientConfig returns the client config as JSON.
func GetJSONClientConfig() (string, error) {
	config, err := LoadClientConfig()
	if err != nil {
		return "", fmt.Errorf("LoadClientConfig() failed: %w", err)
	}
	b, err := common.MarshalJSON(config)
	if err != nil {
		return "", fmt.Errorf("common.MarshalJSON() failed: %w", err)
	}
	return string(b), nil
}

// GetURLClientConfig returns the client config as a URL.
func GetURLClientConfig() (string, error) {
	config, err := LoadClientConfig()
	if err != nil {
		return "", fmt.Errorf("LoadClientConfig() failed: %w", err)
	}
	u, err := ClientConfigToURL(config)
	if err != nil {
		return "", fmt.Errorf("ClientConfigToURL() failed: %w", err)
	}
	return u, nil
}

// LoadClientConfig reads client config from disk.
func LoadClientConfig() (*pb.ClientConfig, error) {
	clientIOLock.Lock()
	defer clientIOLock.Unlock()

	fileName, fileType, err := clientConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("clientConfigFilePath() failed: %w", err)
	}
	if err := prepareClientConfigDir(); err != nil {
		return nil, fmt.Errorf("prepareClientConfigDir() failed: %w", err)
	}

	log.Debugf("loading client config from %q", fileName)
	f, err := os.Open(fileName)
	if err != nil && os.IsNotExist(err) {
		return nil, stderror.ErrFileNotExist
	} else if err != nil {
		return nil, fmt.Errorf("os.Open() failed: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll() failed: %w", err)
	}

	c := &pb.ClientConfig{}
	switch fileType {
	case PROTOBUF_CONFIG_FILE_TYPE:
		if err := proto.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("proto.Unmarshal() failed: %w", err)
		}
	case JSON_CONFIG_FILE_TYPE:
		if err := common.UnmarshalJSON(b, c); err != nil {
			return nil, fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("config file type is invalid")
	}

	return c, nil
}

// StoreClientConfig writes client config to disk.
func StoreClientConfig(config *pb.ClientConfig) error {
	clientIOLock.Lock()
	defer clientIOLock.Unlock()

	fileName, fileType, err := clientConfigFilePath()
	if err != nil {
		return fmt.Errorf("clientConfigFilePath() failed: %w", err)
	}
	if err := prepareClientConfigDir(); err != nil {
		return fmt.Errorf("prepareClientConfigDir() failed: %w", err)
	}

	for _, profile := range config.GetProfiles() {
		user, err := appctlcommon.HashUserPassword(profile.GetUser(), true)
		if err != nil {
			return err
		}
		profile.User = user
	}

	var b []byte
	switch fileType {
	case PROTOBUF_CONFIG_FILE_TYPE:
		if b, err = proto.Marshal(config); err != nil {
			return fmt.Errorf("proto.Marshal() failed: %w", err)
		}
	case JSON_CONFIG_FILE_TYPE:
		if b, err = common.MarshalJSON(config); err != nil {
			return fmt.Errorf("common.MarshalJSON() failed: %w", err)
		}
	default:
		return fmt.Errorf("config file type is invalid")
	}

	err = os.WriteFile(fileName, b, 0660)
	if err != nil {
		return fmt.Errorf("os.WriteFile(%q) failed: %w", fileName, err)
	}

	return nil
}

// ApplyJSONClientConfig applies user provided JSON client config from the given file.
func ApplyJSONClientConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	c := &pb.ClientConfig{}
	if err = common.UnmarshalJSON(b, c); err != nil {
		return fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
	}
	return applyClientConfig(c)
}

// ReplaceJSONClientConfig replaces the saved client config with a complete JSON config.
func ReplaceJSONClientConfig(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	config := &pb.ClientConfig{}
	if err = common.UnmarshalJSON(b, config); err != nil {
		return fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
	}
	if err = ValidateFullClientConfig(config); err != nil {
		return fmt.Errorf("ValidateFullClientConfig() failed: %w", err)
	}
	if err = StoreClientConfig(config); err != nil {
		return fmt.Errorf("StoreClientConfig() failed: %w", err)
	}
	return nil
}

// ParseURLClientConfig parses a client config URL and returns the config
// without applying it.
func ParseURLClientConfig(u string) (*pb.ClientConfig, error) {
	if strings.HasPrefix(u, "mieru://") {
		c, err := URLToClientConfig(u)
		if err != nil {
			return nil, fmt.Errorf("URLToClientConfig() failed: %w", err)
		}
		return c, nil
	} else if strings.HasPrefix(u, "mierus://") {
		p, err := URLToClientProfile(u)
		if err != nil {
			return nil, fmt.Errorf("URLToClientProfile() failed: %w", err)
		}
		return &pb.ClientConfig{
			Profiles: []*pb.ClientProfile{p},
		}, nil
	} else {
		return nil, fmt.Errorf("unrecognized URL scheme. URL must begin with mieru:// or mierus://")
	}
}

// ApplyURLClientConfig applies user provided client config URL.
func ApplyURLClientConfig(u string) error {
	c, err := ParseURLClientConfig(u)
	if err != nil {
		return err
	}
	return applyClientConfig(c)
}

// DeleteClientConfigProfile deletes a profile stored in client config.
// The profile to delete can't be the active profile.
func DeleteClientConfigProfile(profileName string) error {
	config, err := LoadClientConfig()
	if err != nil {
		return fmt.Errorf("LoadClientConfig() failed: %w", err)
	}
	if config.GetActiveProfile() == profileName {
		return fmt.Errorf("activeProfile %q can't be deleted", profileName)
	}
	profiles := config.GetProfiles()
	updated := make([]*pb.ClientProfile, 0)
	for _, profile := range profiles {
		if profile.GetProfileName() == profileName {
			continue
		}
		updated = append(updated, profile)
	}
	config.Profiles = updated
	if err = StoreClientConfig(config); err != nil {
		return fmt.Errorf("StoreClientConfig() failed: %w", err)
	}
	return nil
}

// ValidateClientConfigPatch validates a patch of client config.
//
// A client config patch must satisfy:
// 1. it has 0 or more profile
// 2. profile names are unique, and each profile is valid
// 3. for each socks5 authentication, the user and password are not empty
func ValidateClientConfigPatch(patch *pb.ClientConfig) error {
	usedProfileNames := map[string]bool{}
	for _, profile := range patch.GetProfiles() {
		if err := appctlcommon.ValidateClientConfigSingleProfile(profile); err != nil {
			return err
		}
		if _, found := usedProfileNames[profile.GetProfileName()]; found {
			return fmt.Errorf("found duplicate profile name %q", profile.GetProfileName())
		}
		usedProfileNames[profile.GetProfileName()] = true
	}
	for _, auth := range patch.GetSocks5Authentication() {
		if auth.GetUser() == "" {
			return fmt.Errorf("socks5 authentication user is not set")
		}
		if auth.GetPassword() == "" {
			return fmt.Errorf("socks5 authentication password is not set")
		}
	}
	return nil
}

// ValidateFullClientConfig validates the full client config.
//
// In addition to ValidateClientConfigPatch, it also validates:
// 1. there is at least 1 profile
// 2. the active profile is available
// 3. socks5 port is valid
func ValidateFullClientConfig(config *pb.ClientConfig) error {
	if err := ValidateClientConfigPatch(config); err != nil {
		return err
	}

	if len(config.GetProfiles()) == 0 {
		return fmt.Errorf("profiles are not set")
	}
	if config.GetActiveProfile() == "" {
		return fmt.Errorf("active profile is not set")
	}
	foundActiveProfile := false
	for _, profile := range config.GetProfiles() {
		if profile.GetProfileName() == config.GetActiveProfile() {
			foundActiveProfile = true
			break
		}
	}
	if !foundActiveProfile {
		return fmt.Errorf("active profile is not found in the profile list")
	}
	if config.GetSocks5Port() < 1 || config.GetSocks5Port() > 65535 {
		return fmt.Errorf("socks5 port number %d is invalid", config.GetSocks5Port())
	}
	return nil
}

// GetActiveProfileFromConfig returns the active client profile from client config.
func GetActiveProfileFromConfig(config *pb.ClientConfig, name string) (*pb.ClientProfile, error) {
	if config == nil {
		return nil, fmt.Errorf("client config is nil")
	}
	for _, profile := range config.GetProfiles() {
		if profile.GetProfileName() == name {
			return profile, nil
		}
	}
	return nil, fmt.Errorf("profile %q is not found", name)
}

// prepareClientConfigDir creates the client config directory if needed.
func prepareClientConfigDir() error {
	if cachedClientConfigDir != "" {
		return os.MkdirAll(cachedClientConfigDir, 0755)
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	cachedClientConfigDir = configDir + string(os.PathSeparator) + "mieru"
	return os.MkdirAll(cachedClientConfigDir, 0755)
}

// clientConfigFilePath returns the client config file path and file type.
// If environment variable MIERU_CONFIG_FILE or MIERU_CONFIG_JSON_FILE is specified,
// those values are returned.
func clientConfigFilePath() (string, ConfigFileType, error) {
	if v, found := os.LookupEnv(EnvMieruConfigFile); found {
		cachedClientConfigFilePath = v
		cachedClientConfigDir = filepath.Dir(v)
		return cachedClientConfigFilePath, PROTOBUF_CONFIG_FILE_TYPE, nil
	}
	if v, found := os.LookupEnv(EnvMieruConfigJSONFile); found {
		cachedClientConfigFilePath = v
		cachedClientConfigDir = filepath.Dir(v)
		return cachedClientConfigFilePath, JSON_CONFIG_FILE_TYPE, nil
	}

	if cachedClientConfigFilePath != "" {
		return cachedClientConfigFilePath, FindConfigFileType(cachedClientConfigFilePath), nil
	}

	if err := prepareClientConfigDir(); err != nil {
		return "", INVALID_CONFIG_FILE_TYPE, fmt.Errorf("prepareClientConfigDir() failed: %w", err)
	}
	cachedClientConfigFilePath = cachedClientConfigDir + string(os.PathSeparator) + "client.conf.pb"
	return cachedClientConfigFilePath, FindConfigFileType(cachedClientConfigFilePath), nil
}

func applyClientConfig(c *pb.ClientConfig) error {
	if err := ValidateClientConfigPatch(c); err != nil {
		return fmt.Errorf("ValidateClientConfigPatch() failed: %w", err)
	}
	config, err := LoadClientConfig()
	if err != nil {
		return fmt.Errorf("LoadClientConfig() failed: %w", err)
	}
	mergeClientConfigByProfile(config, c)
	if err = ValidateFullClientConfig(config); err != nil {
		return fmt.Errorf("ValidateFullClientConfig() failed: %w", err)
	}
	if err = StoreClientConfig(config); err != nil {
		return fmt.Errorf("StoreClientConfig() failed: %w", err)
	}
	return nil
}

// mergeClientConfigByProfile merges the source client config into destination.
// If a profile is specified in source, it is added to destination,
// or replacing existing profile in destination.
func mergeClientConfigByProfile(dst, src *pb.ClientConfig) {
	// Merge src profiles into dst profiles.
	dstMapping := map[string]*pb.ClientProfile{}
	srcMapping := map[string]*pb.ClientProfile{}
	for _, profile := range dst.GetProfiles() {
		dstMapping[profile.GetProfileName()] = profile
	}
	for _, profile := range src.GetProfiles() {
		srcMapping[profile.GetProfileName()] = profile
	}
	mergedProfileMapping := map[string]*pb.ClientProfile{}
	for name, profile := range dstMapping {
		mergedProfileMapping[name] = profile
	}
	for name, profile := range srcMapping {
		mergedProfileMapping[name] = profile
	}
	names := make([]string, 0, len(mergedProfileMapping))
	for name := range mergedProfileMapping {
		names = append(names, name)
	}
	sort.Strings(names)
	mergedProfiles := make([]*pb.ClientProfile, 0, len(mergedProfileMapping))
	for _, name := range names {
		mergedProfiles = append(mergedProfiles, mergedProfileMapping[name])
	}

	// Required fields.
	var activeProfile string
	if src.ActiveProfile != nil {
		activeProfile = src.GetActiveProfile()
	} else {
		activeProfile = dst.GetActiveProfile()
	}
	var sock5Port int32
	if src.Socks5Port != nil {
		sock5Port = src.GetSocks5Port()
	} else {
		sock5Port = dst.GetSocks5Port()
	}
	var loggingLevel pb.LoggingLevel
	if src.LoggingLevel != nil {
		loggingLevel = src.GetLoggingLevel()
	} else {
		loggingLevel = dst.GetLoggingLevel()
	}

	// Optional fields.
	var socks5ListenLAN *bool = dst.Socks5ListenLAN
	if src.Socks5ListenLAN != nil {
		socks5ListenLAN = src.Socks5ListenLAN
	}
	var socks5Authentication []*pb.Auth = dst.Socks5Authentication
	if src.Socks5Authentication != nil {
		socks5Authentication = src.Socks5Authentication
	}

	proto.Reset(dst)

	dst.ActiveProfile = proto.String(activeProfile)
	dst.Profiles = mergedProfiles
	dst.Socks5Port = proto.Int32(sock5Port)
	dst.LoggingLevel = &loggingLevel

	dst.Socks5ListenLAN = socks5ListenLAN
	dst.Socks5Authentication = socks5Authentication
}

// deleteClientConfigFile deletes the client config file.
func deleteClientConfigFile() error {
	path, _, err := clientConfigFilePath()
	if err != nil {
		return fmt.Errorf("clientConfigFilePath() failed: %w", err)
	}
	err = os.Remove(path)
	if err != nil && os.IsNotExist(err) {
		return nil
	}
	return err
}
