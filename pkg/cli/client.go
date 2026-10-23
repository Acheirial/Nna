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

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlcommon"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/sockopts"
	"github.com/Acheirial/shadowlemon/v3/pkg/socks5"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

// RegisterClientCommands registers all the client side CLI commands.
func RegisterClientCommands() {
	RegisterCallback(
		[]string{"", "client", "help"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientHelpFunc,
	)
	RegisterCallback(
		[]string{"", "client", "start"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientStartFunc,
	)
	RegisterCallback(
		[]string{"", "client", "run"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientRunFunc,
	)
	RegisterCallback(
		[]string{"", "client", "stop"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientStopFunc,
	)
	RegisterCallback(
		[]string{"", "client", "status"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientStatusFunc,
	)
	RegisterCallback(
		[]string{"", "client", "apply", "config"},
		func(s []string) error {
			if len(s) < 5 {
				return fmt.Errorf("usage: shadowlemon client apply config <FILE>. No config file is provided")
			} else if len(s) > 5 {
				return fmt.Errorf("usage: shadowlemon client apply config <FILE>. More than 1 config file is provided")
			}
			return nil
		},
		clientApplyConfigFunc,
	)
	RegisterCallback(
		[]string{"", "client", "replace", "config"},
		func(s []string) error {
			if len(s) < 5 {
				return fmt.Errorf("usage: shadowlemon client replace config <FILE>. No config file is provided")
			} else if len(s) > 5 {
				return fmt.Errorf("usage: shadowlemon client replace config <FILE>. More than 1 config file is provided")
			}
			return nil
		},
		clientReplaceConfigFunc,
	)
	RegisterCallback(
		[]string{"", "client", "describe", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 4)
		},
		clientDescribeConfigFunc,
	)
	RegisterCallback(
		[]string{"", "client", "import", "config"},
		func(s []string) error {
			if len(s) < 5 {
				return fmt.Errorf("usage: shadowlemon client import config <URL>. No URL is provided")
			} else if len(s) > 5 {
				return fmt.Errorf("usage: shadowlemon client import config <URL>. More than 1 URL is provided")
			}
			return nil
		},
		clientImportConfigFunc,
	)
	RegisterCallback(
		[]string{"", "client", "export", "config", "simple"},
		func(s []string) error {
			return unexpectedArgsError(s, 5)
		},
		clientExportConfigSimpleFunc,
	)
	RegisterCallback(
		[]string{"", "client", "export", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 4)
		},
		clientExportConfigFunc,
	)
	RegisterCallback(
		[]string{"", "client", "version"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		versionFunc,
	)
}

var clientHelpFunc = func(s []string) error {
	helpFmt := helpFormatter{
		appName: "shadowlemon client",
		entries: []helpCmdEntry{
			{
				cmd:  "client help",
				help: []string{"Show shadowlemon client help."},
			},
			{
				cmd:  "client start",
				help: []string{"Start shadowlemon client in background."},
			},
			{
				cmd:  "client stop",
				help: []string{"Stop shadowlemon client."},
			},
			{
				cmd:  "client status",
				help: []string{"Check shadowlemon client status."},
			},
			{
				cmd: "client apply config <JSON_FILE>",
				help: []string{
					"Apply client configuration patch from a file.",
					"It merges the patch with existing client configuration.",
				},
			},
			{
				cmd: "client replace config <JSON_FILE>",
				help: []string{
					"Replace saved client configuration with a complete JSON file.",
					"Omitted settings and profiles are removed.",
				},
			},
			{
				cmd:  "client describe config",
				help: []string{"Show current client configuration."},
			},
			{
				cmd: "client import config <URL>",
				help: []string{
					"Import client configuration from a URL.",
					"The URL can be standard format shadowlemon:// or simple format shadowlemons://.",
					"Please use quotation marks to wrap the URL, so it can be parsed correctly.",
				},
			},
			{
				cmd:  "client export config simple",
				help: []string{"Export client configuration as URLs in simple format."},
			},
			{
				cmd:  "client export config",
				help: []string{"Export client configuration as a URL."},
			},
			{
				cmd:  "client version",
				help: []string{"Show shadowlemon client version."},
			},
		},
		advanced: []helpCmdEntry{
			{
				cmd: "client run",
				help: []string{
					"Run shadowlemon client in foreground.",
					"Use environment variable SHADOWLEMON_CLIENT_CONFIG_JSON_FILE to load configuration.",
				},
			},
		},
	}
	helpFmt.print()
	return nil
}

var clientStartFunc = func(s []string) error {
	// Load and verify client config.
	config, err := appctl.LoadClientConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ClientConfigNotExist)
		}
		return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
	}
	if err = appctl.ValidateFullClientConfig(config); err != nil {
		return fmt.Errorf(stderror.ValidateFullClientConfigFailedErr, err)
	}

	pidFilePath, err := appctl.ClientPidFilePath()
	if err != nil {
		return fmt.Errorf(stderror.GetClientPidFilePathFailedErr, err)
	}
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("shadowlemon client is running, listening to socks5://%s", clientSocks5Address(config))
		return nil
	}

	if err := appctl.StartAppDaemon(s[0], pidFilePath, "client"); err != nil {
		return fmt.Errorf(stderror.StartClientFailedErr, err)
	}
	log.Infof("shadowlemon client is started, listening to socks5://%s", clientSocks5Address(config))
	return nil
}

var clientRunFunc = func(s []string) error {
	log.SetFormatter(&log.DaemonFormatter{})

	if _, found := os.LookupEnv(appctl.EnvClientConfigFile); found {
		log.Debugf("log to stdout because environment variable %s is set", appctl.EnvClientConfigFile)
	} else if _, found := os.LookupEnv(appctl.EnvClientConfigJSONFile); found {
		log.Debugf("log to stdout because environment variable %s is set", appctl.EnvClientConfigJSONFile)
	} else {
		logFile, err := log.NewClientLogFile()
		if err == nil {
			log.SetOutput(logFile)
			if err = log.RemoveOldClientLogFiles(); err != nil {
				log.Errorf("remove old client log files failed: %v", err)
			}
		} else {
			log.Infof("log to stdout because: %v", err)
		}
	}

	// Load and verify client config.
	config, err := appctl.LoadClientConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ClientConfigNotExist)
		}
		return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
	}
	if err = appctl.ValidateFullClientConfig(config); err != nil {
		return fmt.Errorf(stderror.ValidateFullClientConfigFailedErr, err)
	}

	// Write the pid file, so that the start, stop and status commands
	// can control this process.
	pidFilePath, err := appctl.ClientPidFilePath()
	if err != nil {
		return fmt.Errorf(stderror.GetClientPidFilePathFailedErr, err)
	}
	if err = appctl.AcquirePidFile(pidFilePath); err != nil {
		return fmt.Errorf(stderror.WriteClientPidFileFailedErr, err)
	}
	defer appctl.RemoveOwnPidFile(pidFilePath)

	// Set logging level based on client config.
	loggingLevel := config.GetLoggingLevel().String()
	if loggingLevel != appctlpb.LoggingLevel_DEFAULT.String() {
		log.SetLevel(loggingLevel)
	}

	resolver := &net.Resolver{}

	// Create the client multiplexer.
	activeProfile, err := appctl.GetActiveProfileFromConfig(config, config.GetActiveProfile())
	if err != nil {
		return fmt.Errorf(stderror.ClientGetActiveProfileFailedErr, err)
	}
	mux, err := appctlcommon.NewClientMuxFromProfile(activeProfile, nil, nil, resolver, nil)
	if err != nil {
		return err
	}

	// Create the local socks5 server.
	var socks5IngressCredentials []socks5.Credential
	for _, auth := range config.GetSocks5Authentication() {
		socks5IngressCredentials = append(socks5IngressCredentials, socks5.Credential{
			User:     auth.GetUser(),
			Password: auth.GetPassword(),
		})
	}
	socks5Config := &socks5.Config{
		UseProxy: true,
		AuthOpts: socks5.Auth{
			ClientSideAuthentication: true,
			IngressCredentials:       socks5IngressCredentials,
		},
		ProxyDialer:      mux,
		Resolver:         resolver,
		HandshakeTimeout: 10 * time.Second,
	}
	// HANDSHAKE_DEFAULT and HANDSHAKE_STANDARD are equivalent: both use the
	// standard handshake that waits for the server. An unknown mode is rejected
	// instead of silently falling back to the standard handshake.
	switch activeProfile.GetHandshakeMode() {
	case appctlpb.HandshakeMode_HANDSHAKE_DEFAULT, appctlpb.HandshakeMode_HANDSHAKE_STANDARD:
		// Use the default handshake behavior.
	case appctlpb.HandshakeMode_HANDSHAKE_NO_WAIT:
		socks5Config.HandshakeNoWait = true
	default:
		return fmt.Errorf("invalid handshake mode %d in profile %q", activeProfile.GetHandshakeMode(), activeProfile.GetProfileName())
	}
	socks5Server, err := socks5.New(socks5Config)
	if err != nil {
		return fmt.Errorf(stderror.CreateSocks5ServerFailedErr, err)
	}

	// Run the local socks5 server in the background.
	socks5Addr := clientSocks5Address(config)
	started := make(chan struct{})
	serveErr := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func(socks5Addr string) {
		defer wg.Done()
		socks5TCPAddr, err := apicommon.ResolveTCPAddr(context.Background(), resolver, "tcp", socks5Addr)
		if err != nil {
			serveErr <- fmt.Errorf("resolve socks5 address %q failed: %w", socks5Addr, err)
			return
		}
		socks5Listener, err := net.ListenTCP("tcp", socks5TCPAddr)
		if err != nil {
			serveErr <- fmt.Errorf("listen on socks5 address %q failed: %w", socks5Addr, err)
			return
		}
		if err := sockopts.ApplyTCPControl(socks5Listener, sockopts.DefaultListenerControl()); err != nil {
			serveErr <- fmt.Errorf("ApplyTCPControl() failed: %w", err)
			return
		}
		close(started)
		log.Infof("shadowlemon client socks5 server is running, listening to socks5://%s", socks5Addr)
		serveErr <- socks5Server.Serve(socks5Listener)
	}(socks5Addr)

	// Wait until the socks5 server is started, or fails to start.
	select {
	case <-started:
	case err := <-serveErr:
		return fmt.Errorf(stderror.CreateSocks5ServerFailedErr, err)
	}
	log.Debugf("Started proxy after %v", appctl.Elapsed())

	// Wait until a stop signal is received.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	var serveFailed error
	select {
	case sig := <-stopChan:
		log.Infof("received signal %v, stop shadowlemon client", sig)
	case err := <-serveErr:
		// Don't call log.Fatalf here, which exits the process without running
		// the deferred pid file removal, and leaves a stale pid file.
		serveFailed = err
		log.Errorf("run socks5 server failed: %v", err)
	}

	if err := socks5Server.Close(); err != nil {
		log.Errorf("socks5 server Close() failed: %v", err)
	}
	if err := mux.Close(); err != nil {
		log.Errorf("client mux Close() failed: %v", err)
	}
	wg.Wait()
	log.Infof("shadowlemon client socks5 server is stopped")

	log.Infof("shadowlemon client exit now")
	if serveFailed != nil {
		return fmt.Errorf(stderror.RunSocks5ServerFailedErr, serveFailed)
	}
	return nil
}

var clientStopFunc = func(s []string) error {
	pidFilePath, err := appctl.ClientPidFilePath()
	if err != nil {
		return fmt.Errorf(stderror.GetClientPidFilePathFailedErr, err)
	}
	running, err := appctl.StopAppDaemon(pidFilePath)
	if err != nil {
		return fmt.Errorf(stderror.StopClientFailedErr, err)
	}
	if !running {
		log.Infof(stderror.ClientNotRunning)
		return nil
	}
	log.Infof("shadowlemon client is stopped")
	return nil
}

var clientStatusFunc = func(s []string) error {
	pidFilePath, err := appctl.ClientPidFilePath()
	if err != nil {
		return fmt.Errorf(stderror.GetClientPidFilePathFailedErr, err)
	}
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("shadowlemon client status is %q", "RUNNING")
	} else {
		log.Infof("shadowlemon client status is %q", "STOPPED")
	}
	return nil
}

var clientApplyConfigFunc = func(s []string) error {
	if _, err := appctl.LoadClientConfig(); err == stderror.ErrFileNotExist {
		if err = appctl.StoreClientConfig(&appctlpb.ClientConfig{}); err != nil {
			return fmt.Errorf(stderror.StoreClientConfigFailedErr, err)
		}
	}
	return appctl.ApplyJSONClientConfig(s[4])
}

var clientReplaceConfigFunc = func(s []string) error {
	return appctl.ReplaceJSONClientConfig(s[4])
}

var clientDescribeConfigFunc = func(s []string) error {
	if _, err := appctl.LoadClientConfig(); err == stderror.ErrFileNotExist {
		if err = appctl.StoreClientConfig(&appctlpb.ClientConfig{}); err != nil {
			return fmt.Errorf(stderror.StoreClientConfigFailedErr, err)
		}
	}
	out, err := appctl.GetJSONClientConfig()
	if err != nil {
		return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
	}
	log.Infof("%s", out)
	return nil
}

var clientImportConfigFunc = func(s []string) error {
	if _, err := appctl.LoadClientConfig(); err == stderror.ErrFileNotExist {
		if err = appctl.StoreClientConfig(&appctlpb.ClientConfig{}); err != nil {
			return fmt.Errorf(stderror.StoreClientConfigFailedErr, err)
		}
	}
	return appctl.ApplyURLClientConfig(s[4])
}

var clientExportConfigSimpleFunc = func(s []string) error {
	config, err := appctl.LoadClientConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ClientConfigNotExist)
		} else {
			return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
		}
	}
	for _, profile := range config.GetProfiles() {
		urls, err := appctl.ClientProfileToMultiURLs(profile)
		if err != nil {
			log.Errorf("%v", err)
		} else {
			for _, url := range urls {
				log.Infof("%s", url)
			}
		}
	}
	return nil
}

var clientExportConfigFunc = func(s []string) error {
	_, err := appctl.LoadClientConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ClientConfigNotExist)
		} else {
			return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
		}
	}
	out, err := appctl.GetURLClientConfig()
	if err != nil {
		return fmt.Errorf(stderror.GetClientConfigFailedErr, err)
	}
	log.Infof("%s", out)
	return nil
}

// clientSocks5Address returns the address that the client socks5 server
// listens to.
func clientSocks5Address(config *appctlpb.ClientConfig) string {
	port := strconv.Itoa(int(config.GetSocks5Port()))
	if config.GetSocks5ListenLAN() {
		return "0.0.0.0:" + port
	}
	return common.MaybeDecorateIPv6(common.LocalIPAddr()) + ":" + port
}
