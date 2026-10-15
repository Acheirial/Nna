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

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlcommon"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/sockopts"
	"github.com/enfein/mieru/v3/pkg/socks5"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

// RegisterClientCommands registers all the client side CLI commands.
func RegisterClientCommands() {
	RegisterCallback(
		[]string{"", "help"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		clientHelpFunc,
	)
	RegisterCallback(
		[]string{"", "start"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		clientStartFunc,
	)
	RegisterCallback(
		[]string{"", "run"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		clientRunFunc,
	)
	RegisterCallback(
		[]string{"", "stop"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		clientStopFunc,
	)
	RegisterCallback(
		[]string{"", "status"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		clientStatusFunc,
	)
	RegisterCallback(
		[]string{"", "apply", "config"},
		func(s []string) error {
			if len(s) < 4 {
				return fmt.Errorf("usage: mieru apply config <FILE>. No config file is provided")
			} else if len(s) > 4 {
				return fmt.Errorf("usage: mieru apply config <FILE>. More than 1 config file is provided")
			}
			return nil
		},
		clientApplyConfigFunc,
	)
	RegisterCallback(
		[]string{"", "replace", "config"},
		func(s []string) error {
			if len(s) < 4 {
				return fmt.Errorf("usage: mieru replace config <FILE>. No config file is provided")
			} else if len(s) > 4 {
				return fmt.Errorf("usage: mieru replace config <FILE>. More than 1 config file is provided")
			}
			return nil
		},
		clientReplaceConfigFunc,
	)
	RegisterCallback(
		[]string{"", "describe", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientDescribeConfigFunc,
	)
	RegisterCallback(
		[]string{"", "import", "config"},
		func(s []string) error {
			if len(s) < 4 {
				return fmt.Errorf("usage: mieru import config <URL>. No URL is provided")
			} else if len(s) > 4 {
				return fmt.Errorf("usage: mieru import config <URL>. More than 1 URL is provided")
			}
			return nil
		},
		clientImportConfigFunc,
	)
	RegisterCallback(
		[]string{"", "export", "config", "simple"},
		func(s []string) error {
			return unexpectedArgsError(s, 4)
		},
		clientExportConfigSimpleFunc,
	)
	RegisterCallback(
		[]string{"", "export", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		clientExportConfigFunc,
	)
	RegisterCallback(
		[]string{"", "version"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		versionFunc,
	)
}

var clientHelpFunc = func(s []string) error {
	helpFmt := helpFormatter{
		appName: "mieru",
		entries: []helpCmdEntry{
			{
				cmd:  "help",
				help: []string{"Show mieru client help."},
			},
			{
				cmd:  "start",
				help: []string{"Start mieru client in background."},
			},
			{
				cmd:  "stop",
				help: []string{"Stop mieru client."},
			},
			{
				cmd:  "status",
				help: []string{"Check mieru client status."},
			},
			{
				cmd: "apply config <JSON_FILE>",
				help: []string{
					"Apply client configuration patch from a file.",
					"It merges the patch with existing client configuration.",
				},
			},
			{
				cmd: "replace config <JSON_FILE>",
				help: []string{
					"Replace saved client configuration with a complete JSON file.",
					"Omitted settings and profiles are removed.",
				},
			},
			{
				cmd:  "describe config",
				help: []string{"Show current client configuration."},
			},
			{
				cmd: "import config <URL>",
				help: []string{
					"Import client configuration from a URL.",
					"The URL can be standard format mieru:// or simple format mierus://.",
					"Please use quotation marks to wrap the URL, so it can be parsed correctly.",
				},
			},
			{
				cmd:  "export config simple",
				help: []string{"Export client configuration as URLs in simple format."},
			},
			{
				cmd:  "export config",
				help: []string{"Export client configuration as a URL."},
			},
			{
				cmd:  "version",
				help: []string{"Show mieru client version."},
			},
		},
		advanced: []helpCmdEntry{
			{
				cmd: "run",
				help: []string{
					"Run mieru client in foreground.",
					"Use environment variable MIERU_CONFIG_JSON_FILE to load configuration.",
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
		log.Infof("mieru client is running, listening to socks5://%s", clientSocks5Address(config))
		return nil
	}

	if err := appctl.StartAppDaemon(s[0], pidFilePath); err != nil {
		return fmt.Errorf(stderror.StartClientFailedErr, err)
	}
	log.Infof("mieru client is started, listening to socks5://%s", clientSocks5Address(config))
	return nil
}

var clientRunFunc = func(s []string) error {
	log.SetFormatter(&log.DaemonFormatter{})

	if _, found := os.LookupEnv(appctl.EnvMieruConfigFile); found {
		log.Debugf("log to stdout because environment variable %s is set", appctl.EnvMieruConfigFile)
	} else if _, found := os.LookupEnv(appctl.EnvMieruConfigJSONFile); found {
		log.Debugf("log to stdout because environment variable %s is set", appctl.EnvMieruConfigJSONFile)
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
	if running, pid := appctl.IsAppRunning(pidFilePath); running && pid != os.Getpid() {
		return fmt.Errorf("mieru client is already running with PID %d", pid)
	}
	if err = appctl.WritePidFile(pidFilePath); err != nil {
		return fmt.Errorf(stderror.WriteClientPidFileFailedErr, err)
	}
	defer appctl.RemovePidFile(pidFilePath)

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
	if activeProfile.GetHandshakeMode() == appctlpb.HandshakeMode_HANDSHAKE_NO_WAIT {
		socks5Config.HandshakeNoWait = true
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
		log.Infof("mieru client socks5 server is running, listening to socks5://%s", socks5Addr)
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
	select {
	case sig := <-stopChan:
		log.Infof("received signal %v, stop mieru client", sig)
	case err := <-serveErr:
		log.Fatalf("run socks5 server failed: %v", err)
	}

	if err := socks5Server.Close(); err != nil {
		log.Errorf("socks5 server Close() failed: %v", err)
	}
	if err := mux.Close(); err != nil {
		log.Errorf("client mux Close() failed: %v", err)
	}
	wg.Wait()
	log.Infof("mieru client socks5 server is stopped")

	log.Infof("mieru client exit now")
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
	log.Infof("mieru client is stopped")
	return nil
}

var clientStatusFunc = func(s []string) error {
	pidFilePath, err := appctl.ClientPidFilePath()
	if err != nil {
		return fmt.Errorf(stderror.GetClientPidFilePathFailedErr, err)
	}
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("mieru client status is %q", "RUNNING")
	} else {
		log.Infof("mieru client status is %q", "STOPPED")
	}
	return nil
}

var clientApplyConfigFunc = func(s []string) error {
	if _, err := appctl.LoadClientConfig(); err == stderror.ErrFileNotExist {
		if err = appctl.StoreClientConfig(&appctlpb.ClientConfig{}); err != nil {
			return fmt.Errorf(stderror.StoreClientConfigFailedErr, err)
		}
	}
	return appctl.ApplyJSONClientConfig(s[3])
}

var clientReplaceConfigFunc = func(s []string) error {
	return appctl.ReplaceJSONClientConfig(s[3])
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
	return appctl.ApplyURLClientConfig(s[3])
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
