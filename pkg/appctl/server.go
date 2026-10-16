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

package appctl

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/protocol"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"github.com/enfein/mieru/v3/pkg/stderror"
	"google.golang.org/protobuf/proto"
)

var (
	cachedServerConfigDir      string = "/etc/mita"
	cachedServerConfigFilePath string = "/etc/mita/server.conf.pb"

	// serverIOLock is required to load server config and store server config.
	serverIOLock sync.Mutex

	// socks5ServerGroup holds a pointer to server socks5 server.
	socks5ServerRef atomic.Pointer[socks5.Server]

	// serverMuxRef holds a pointer to server multiplexier.
	serverMuxRef atomic.Pointer[protocol.Mux]
)

func SetSocks5Server(server *socks5.Server) {
	socks5ServerRef.Store(server)
}

func SetServerMuxRef(mux *protocol.Mux) {
	serverMuxRef.Store(mux)
}

// serverProxy is an object that bundles server mux and associated socks5 server.
type serverProxy struct {
	mux          *protocol.Mux
	socks5Server *socks5.Server
}

func newServerProxy(config *pb.ServerConfig) (*serverProxy, error) {
	trafficPattern, err := trafficpattern.NewConfig(config.TrafficPattern)
	if err != nil {
		return nil, err
	}
	allowedCipherSuites, err := appctlcommon.ValidateCipherSuiteList("server config cipherSuites", config.GetCipherSuites())
	if err != nil {
		return nil, err
	}
	mux := protocol.NewMux(false).
		SetTrafficPattern(trafficPattern).
		SetServerUsers(appctlcommon.UserListToMap(config.GetUsers())).
		SetServerUserHintIsMandatory(config.GetAdvancedSettings().GetUserHintIsMandatory())
	mux.SetAllowedCipherSuites(allowedCipherSuites)
	mtu := common.DefaultMTU
	if config.GetMtu() != 0 {
		mtu = int(config.GetMtu())
	}
	endpoints, err := appctlcommon.AddrPortToUnderlayProperties(config.GetListenIPAddress(), config.GetPortBindings(), mtu)
	if err != nil {
		mux.Close()
		return nil, err
	}
	mux.SetEndpoints(endpoints)

	dnsHosts, err := appctlcommon.TransformDNSHosts(config.GetDns())
	if err != nil {
		mux.Close()
		return nil, err
	}

	// Create the egress socks5 server.
	socks5Config := &socks5.Config{
		AuthOpts: socks5.Auth{
			ClientSideAuthentication: true,
		},
		DualStackPreference: common.DualStackPreference(config.GetDns().GetDualStack()),
		Egress:              config.GetEgress(),
		HandshakeTimeout:    10 * time.Second,
		Resolver:            apicommon.HostMapResolver{Resolver: &net.Resolver{}, Hosts: dnsHosts},
		Users:               appctlcommon.UserListToMap(config.GetUsers()),
	}
	socks5Server, err := socks5.New(socks5Config)
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf(stderror.CreateSocks5ServerFailedErr, err)
	}
	return &serverProxy{mux: mux, socks5Server: socks5Server}, nil
}

func cleanupFailedServerProxy(proxy *serverProxy) {
	if proxy != nil {
		if proxy.socks5Server != nil && socks5ServerRef.Load() == proxy.socks5Server {
			SetSocks5Server(nil)
			if err := proxy.socks5Server.Close(); err != nil {
				log.Errorf("socks5 server Close() failed: %v", err)
			}
		}
		if proxy.mux != nil && serverMuxRef.Load() == proxy.mux {
			SetServerMuxRef(nil)
			if err := proxy.mux.Close(); err != nil {
				log.Errorf("server mux Close() failed: %v", err)
			}
		}
	}
}

// StartServerProxy starts the mita proxy service.
func StartServerProxy(config *pb.ServerConfig) error {
	if socks5ServerRef.Load() != nil {
		log.Infof("socks5 server already exist")
		return nil
	}

	proxy, err := newServerProxy(config)
	if err != nil {
		return err
	}

	startErr := make(chan error, 1)
	go func() {
		if err := proxy.mux.Start(); err != nil {
			log.Errorf("server mux listening failed: %v", err)
			startErr <- err
			return
		}
		SetServerMuxRef(proxy.mux)
		SetSocks5Server(proxy.socks5Server)
		startErr <- nil

		log.Infof("mita server daemon socks5 server is running")
		if err := proxy.socks5Server.Serve(proxy.mux); err != nil {
			log.Errorf("Run socks5 server failed: %v", err)
			cleanupFailedServerProxy(proxy)
			return
		}
		log.Infof("mita server daemon socks5 server is stopped")
	}()

	if err := <-startErr; err != nil {
		cleanupFailedServerProxy(proxy)
		return err
	}

	return nil
}

// StopServerProxy stops the mita proxy service.
func StopServerProxy() error {
	if socks5ServerRef.Load() != nil {
		log.Infof("stopping socks5 server")
		if err := socks5ServerRef.Load().Close(); err != nil {
			log.Infof("socks5 server Close() failed: %v", err)
		}
		SetSocks5Server(nil)
	} else {
		log.Infof("active socks5 servers not found")
	}
	if mux := serverMuxRef.Load(); mux != nil {
		if err := mux.Close(); err != nil {
			log.Infof("server mux Close() failed: %v", err)
		}
	}
	SetServerMuxRef(nil)
	return nil
}

// LoadServerConfig reads server config from disk.
func LoadServerConfig() (*pb.ServerConfig, error) {
	serverIOLock.Lock()
	defer serverIOLock.Unlock()

	fileName, fileType, err := serverConfigFilePath()
	if err != nil {
		return nil, fmt.Errorf("serverConfigFilePath() failed: %w", err)
	}
	if err := checkServerConfigDir(); err != nil {
		return nil, fmt.Errorf("checkServerConfigDir() failed: %w", err)
	}

	log.Debugf("loading server config from %q", fileName)
	f, err := os.Open(fileName)
	if err != nil && os.IsNotExist(err) {
		return nil, stderror.ErrFileNotExist
	} else if err != nil {
		return nil, fmt.Errorf("os.Open() failed: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll(%q) failed: %w", fileName, err)
	}

	s := &pb.ServerConfig{}
	switch fileType {
	case PROTOBUF_CONFIG_FILE_TYPE:
		if err := proto.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("proto.Unmarshal() failed: %w", err)
		}
	case JSON_CONFIG_FILE_TYPE:
		if err := common.UnmarshalJSON(b, s); err != nil {
			return nil, fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("config file type is invalid")
	}

	return s, nil
}

// StoreServerConfig writes server config to disk.
func StoreServerConfig(config *pb.ServerConfig) error {
	serverIOLock.Lock()
	defer serverIOLock.Unlock()

	if config == nil {
		return fmt.Errorf("ServerConfig is nil")
	}
	users, err := appctlcommon.HashUserPasswords(config.GetUsers(), false)
	if err != nil {
		return err
	}
	config.Users = users

	fileName, fileType, err := serverConfigFilePath()
	if err != nil {
		return fmt.Errorf("serverConfigFilePath() failed: %w", err)
	}
	if err := checkServerConfigDir(); err != nil {
		return fmt.Errorf("checkServerConfigDir() failed: %w", err)
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

// MergeServerConfig merges the source server config into destination.
// Source users are added or replace destination users with the same name.
// Users omitted from source are preserved. Other supplied fields replace their
// destination values. The caller must validate the patch and merged config.
func MergeServerConfig(dst, src *pb.ServerConfig) error {
	listenIPAddress := dst.ListenIPAddress
	if src.ListenIPAddress != nil {
		listenIPAddress = src.ListenIPAddress
	}

	// Port bindings: if src is set, replace dst with src.
	var portBindings []*pb.PortBinding
	if src.PortBindings != nil {
		portBindings = src.GetPortBindings()
	} else {
		portBindings = dst.GetPortBindings()
	}

	// Users: merge src into dst.
	mergedUserMapping := map[string]*pb.User{}
	for _, user := range dst.GetUsers() {
		mergedUserMapping[user.GetName()] = user
	}
	for _, user := range src.GetUsers() {
		mergedUserMapping[user.GetName()] = user
	}
	names := make([]string, 0, len(mergedUserMapping))
	for name := range mergedUserMapping {
		names = append(names, name)
	}
	sort.Strings(names)
	mergedUsers := make([]*pb.User, 0, len(mergedUserMapping))
	for _, name := range names {
		mergedUsers = append(mergedUsers, mergedUserMapping[name])
	}

	var advancedSettings *pb.ServerAdvancedSettings
	if src.AdvancedSettings != nil {
		advancedSettings = src.GetAdvancedSettings()
	} else {
		advancedSettings = dst.GetAdvancedSettings()
	}
	var loggingLevel pb.LoggingLevel
	if src.LoggingLevel != nil {
		loggingLevel = src.GetLoggingLevel()
	} else {
		loggingLevel = dst.GetLoggingLevel()
	}
	var mtu int32
	if src.Mtu != nil {
		mtu = src.GetMtu()
	} else {
		mtu = dst.GetMtu()
	}
	var egress *pb.Egress
	if src.Egress != nil {
		egress = src.GetEgress()
	} else {
		egress = dst.GetEgress()
	}
	var dns *pb.DNS
	if src.Dns != nil {
		dns = src.GetDns()
	} else {
		dns = dst.GetDns()
	}
	var trafficPattern *pb.TrafficPattern
	if src.TrafficPattern != nil {
		trafficPattern = src.GetTrafficPattern()
	} else {
		trafficPattern = dst.GetTrafficPattern()
	}
	var cipherSuites []pb.CipherSuite
	if src.CipherSuites != nil {
		cipherSuites = src.GetCipherSuites()
	} else {
		cipherSuites = dst.GetCipherSuites()
	}

	proto.Reset(dst)
	dst.ListenIPAddress = listenIPAddress
	dst.PortBindings = portBindings
	dst.Users = mergedUsers
	dst.AdvancedSettings = advancedSettings
	dst.LoggingLevel = &loggingLevel
	dst.Mtu = proto.Int32(mtu)
	dst.Egress = egress
	dst.Dns = dns
	dst.TrafficPattern = trafficPattern
	dst.CipherSuites = cipherSuites
	return nil
}

// ValidateServerConfigPatch validates a patch of server config.
//
// A server config patch must satisfy:
// 1. listen IP address is valid
// 2. port bindings are valid
// 3. user names are unique, and users are valid
// 4. if set, MTU is valid
// 5. for each egress proxy
// 5.1. name is not empty
// 5.2. name is unique
// 5.3. protocol is valid
// 5.4. host is not empty
// 5.5. port is valid
// 5.6. if socks5 authentication is used, the user and password are not empty
// 6. for each egress rule
// 6.1. each IP range is either "*" or a valid IP CIDR
// 6.2. each domain name is not empty, and does not begin or end with a dot
// 6.3. if the action is "PROXY", the proxy is defined
// 7. DNS configuration is valid
// 8. if set, traffic pattern is valid
// 9. if set, cipher suites are valid
func ValidateServerConfigPatch(patch *pb.ServerConfig) error {
	if err := appctlcommon.ValidateServerListenIPAddress(patch.GetListenIPAddress()); err != nil {
		return err
	}
	if _, err := appctlcommon.FlatPortBindings(patch.GetPortBindings()); err != nil {
		return err
	}
	usedUserNames := map[string]bool{}
	for _, user := range patch.GetUsers() {
		if err := appctlcommon.ValidateServerConfigSingleUser(user); err != nil {
			return err
		}
		if _, found := usedUserNames[user.GetName()]; found {
			return fmt.Errorf("found duplicate user name %q", user.GetName())
		}
		usedUserNames[user.GetName()] = true
	}
	if patch.GetMtu() != 0 && (patch.GetMtu() < 1280 || patch.GetMtu() > 1500) {
		return fmt.Errorf("MTU value %d is out of range, valid range is [1280, 1500]", patch.GetMtu())
	}
	usedProxyNames := map[string]bool{}
	for _, proxy := range patch.GetEgress().GetProxies() {
		if proxy.GetName() == "" {
			return fmt.Errorf("egress proxy name is empty")
		}
		if _, found := usedProxyNames[proxy.GetName()]; found {
			return fmt.Errorf("found duplicate egress proxy name %q", proxy.GetName())
		}
		usedProxyNames[proxy.GetName()] = true
		if proxy.GetProtocol() == pb.ProxyProtocol_UNKNOWN_PROXY_PROTOCOL {
			return fmt.Errorf("egress proxy protocol is not set")
		}
		if proxy.GetHost() == "" {
			return fmt.Errorf("egress proxy host is not set")
		}
		if proxy.GetPort() < 1 || proxy.GetPort() > 65535 {
			return fmt.Errorf("egress proxy port number %d is invalid", proxy.GetPort())
		}
		hasSocks5AuthenticationUser := proxy.GetSocks5Authentication().GetUser() != ""
		hasSocks5AuthenticationPassword := proxy.GetSocks5Authentication().GetPassword() != ""
		if !hasSocks5AuthenticationUser && hasSocks5AuthenticationPassword {
			return fmt.Errorf("egress proxy socks5 authentication user is not set")
		}
		if hasSocks5AuthenticationUser && !hasSocks5AuthenticationPassword {
			return fmt.Errorf("egress proxy socks5 authentication password is not set")
		}
	}
	for _, rule := range patch.GetEgress().GetRules() {
		for _, ipRange := range rule.GetIpRanges() {
			if ipRange != "*" {
				if _, _, err := net.ParseCIDR(ipRange); err != nil {
					return fmt.Errorf("egress rule: invalid IP CIDR: %s", ipRange)
				}
			}
		}
		for _, domain := range rule.GetDomainNames() {
			if domain == "" {
				return fmt.Errorf("egress rule: domain name is empty")
			}
			if domain[0] == '.' {
				return fmt.Errorf("egress rule: domain name %q must not begin with a dot", domain)
			}
			if domain[len(domain)-1] == '.' {
				return fmt.Errorf("egress rule: domain name %q must not end with a dot", domain)
			}
		}
		if rule.GetAction() == pb.EgressAction_PROXY {
			if len(rule.GetProxyNames()) == 0 {
				return fmt.Errorf("egress rule: proxy name list is empty for PROXY action")
			}
			for _, proxyName := range rule.GetProxyNames() {
				if _, found := usedProxyNames[proxyName]; !found {
					return fmt.Errorf("egress rule: proxy %q is referenced but not defined", proxyName)
				}
			}
		} else {
			if len(rule.GetProxyNames()) > 0 {
				return fmt.Errorf("egress rule: proxy name list is not empty for non-PROXY action")
			}
		}
	}
	if _, err := appctlcommon.TransformDNSHosts(patch.GetDns()); err != nil {
		return fmt.Errorf("invalid DNS configuration: %w", err)
	}
	if err := common.ValidateDualStackPreference(common.DualStackPreference(patch.GetDns().GetDualStack())); err != nil {
		return fmt.Errorf("invalid DNS configuration: %w", err)
	}
	if err := trafficpattern.Validate(patch.GetTrafficPattern()); err != nil {
		return fmt.Errorf("invalid traffic pattern: %w", err)
	}
	if _, err := appctlcommon.ValidateCipherSuiteList("server config cipherSuites", patch.GetCipherSuites()); err != nil {
		return err
	}
	return nil
}

// ValidateFullServerConfig validates the full server config.
//
// In addition to ValidateServerConfigPatch, it also validates:
// 1. there is at least 1 port binding
//
// It is not an error if no user is configured. However mita won't be functional.
func ValidateFullServerConfig(config *pb.ServerConfig) error {
	if err := ValidateServerConfigPatch(config); err != nil {
		return err
	}

	if proto.Equal(config, &pb.ServerConfig{}) {
		return fmt.Errorf("server config is empty")
	}
	if len(config.GetPortBindings()) == 0 {
		return fmt.Errorf("server port binding is not set")
	}
	return nil
}

// checkServerConfigDir validates if server config directory exists.
func checkServerConfigDir() error {
	_, err := os.Stat(cachedServerConfigDir)
	return err
}

// serverConfigFilePath returns the server config file path.
// If environment variable MITA_CONFIG_FILE or MITA_CONFIG_JSON_FILE is specified,
// those values are returned.
func serverConfigFilePath() (string, ConfigFileType, error) {
	if v, found := os.LookupEnv("MITA_CONFIG_FILE"); found {
		cachedServerConfigFilePath = v
		cachedServerConfigDir = filepath.Dir(v)
		return cachedServerConfigFilePath, PROTOBUF_CONFIG_FILE_TYPE, nil
	}
	if v, found := os.LookupEnv("MITA_CONFIG_JSON_FILE"); found {
		cachedServerConfigFilePath = v
		cachedServerConfigDir = filepath.Dir(v)
		return cachedServerConfigFilePath, JSON_CONFIG_FILE_TYPE, nil
	}
	if cachedServerConfigFilePath != "" {
		return cachedServerConfigFilePath, FindConfigFileType(cachedServerConfigFilePath), nil
	}
	return "", INVALID_CONFIG_FILE_TYPE, fmt.Errorf("server config file path is empty")
}
