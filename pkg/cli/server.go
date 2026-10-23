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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/enfein/mieru/v3/pkg/appctl"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

// RegisterServerCommands registers all the server side CLI commands.
func RegisterServerCommands() {
	RegisterCallback(
		[]string{"", "server", "help"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverHelpFunc,
	)
	RegisterCallback(
		[]string{"", "server", "start"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverStartFunc,
	)
	RegisterCallback(
		[]string{"", "server", "run"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverRunFunc,
	)
	RegisterCallback(
		[]string{"", "server", "stop"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverStopFunc,
	)
	RegisterCallback(
		[]string{"", "server", "status"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverStatusFunc,
	)
	RegisterCallback(
		[]string{"", "server", "apply", "config"},
		func(s []string) error {
			if len(s) < 5 {
				return fmt.Errorf("usage: shadowlemon server apply config <FILE>. no config file is provided")
			} else if len(s) > 5 {
				return fmt.Errorf("usage: shadowlemon server apply config <FILE>. more than 1 config file is provided")
			}
			return nil
		},
		serverApplyConfigFunc,
	)
	RegisterCallback(
		[]string{"", "server", "replace", "config"},
		func(s []string) error {
			if len(s) < 5 {
				return fmt.Errorf("usage: shadowlemon server replace config <FILE>. no config file is provided")
			} else if len(s) > 5 {
				return fmt.Errorf("usage: shadowlemon server replace config <FILE>. more than 1 config file is provided")
			}
			return nil
		},
		serverReplaceConfigFunc,
	)
	RegisterCallback(
		[]string{"", "server", "describe", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 4)
		},
		serverDescribeConfigFunc,
	)
	RegisterCallback(
		[]string{"", "server", "version"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		versionFunc,
	)
}

var serverHelpFunc = func(s []string) error {
	helpFmt := helpFormatter{
		appName: "shadowlemon server",
		entries: []helpCmdEntry{
			{
				cmd:  "server help",
				help: []string{"Show shadowlemon server help."},
			},
			{
				cmd:  "server start",
				help: []string{"Start shadowlemon server in background."},
			},
			{
				cmd:  "server stop",
				help: []string{"Stop shadowlemon server."},
			},
			{
				cmd:  "server status",
				help: []string{"Check shadowlemon server status."},
			},
			{
				cmd: "server apply config <JSON_FILE>",
				help: []string{
					"Apply server configuration patch from a file.",
					"It merges the patch with existing server configuration.",
				},
			},
			{
				cmd: "server replace config <JSON_FILE>",
				help: []string{
					"Replace saved server configuration with a complete JSON file.",
					"Omitted settings and users are removed.",
				},
			},
			{
				cmd:  "server describe config",
				help: []string{"Show current server configuration."},
			},
			{
				cmd:  "server version",
				help: []string{"Show shadowlemon server version."},
			},
		},
		advanced: []helpCmdEntry{
			{
				cmd: "server run",
				help: []string{
					"Run shadowlemon server in foreground.",
					"Use environment variable MITA_CONFIG_JSON_FILE to load configuration.",
				},
			},
		},
	}
	helpFmt.print()
	return nil
}

var serverStartFunc = func(s []string) error {
	// Load and verify server config, so that an invalid config is reported
	// immediately, instead of waiting for the daemon to start and time out.
	config, err := appctl.LoadServerConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ServerConfigNotExist)
		}
		return fmt.Errorf(stderror.GetServerConfigFailedErr, err)
	}
	if err = appctl.ValidateFullServerConfig(config); err != nil {
		return fmt.Errorf(stderror.ValidateFullServerConfigFailedErr, err)
	}

	pidFilePath := appctl.ServerPidFilePath()
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("shadowlemon server is running")
		return nil
	}

	if err := appctl.StartAppDaemon(s[0], pidFilePath, "server"); err != nil {
		return fmt.Errorf(stderror.StartServerFailedErr, err)
	}
	log.Infof("shadowlemon server is started")
	return nil
}

var serverRunFunc = func(s []string) error {
	if _, found := os.LookupEnv("MITA_LOG_NO_TIMESTAMP"); found {
		log.SetFormatter(&log.DaemonFormatter{NoTimestamp: true})
	} else {
		log.SetFormatter(&log.DaemonFormatter{})
	}

	// Load and verify server config.
	config, err := appctl.LoadServerConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ServerConfigNotExist)
		}
		return fmt.Errorf(stderror.GetServerConfigFailedErr, err)
	}
	if err = appctl.ValidateFullServerConfig(config); err != nil {
		return fmt.Errorf(stderror.ValidateFullServerConfigFailedErr, err)
	}

	// Write the pid file, so that the start, stop and status commands
	// can control this process.
	pidFilePath := appctl.ServerPidFilePath()
	if err = appctl.AcquirePidFile(pidFilePath); err != nil {
		return fmt.Errorf(stderror.WriteServerPidFileFailedErr, err)
	}
	defer appctl.RemoveOwnPidFile(pidFilePath)

	// Set logging level based on server config.
	loggingLevel := config.GetLoggingLevel().String()
	if loggingLevel != appctlpb.LoggingLevel_DEFAULT.String() {
		log.SetLevel(loggingLevel)
	}

	// Detect and log TCP congestion control algorithm.
	if algo := common.TCPCongestionControlAlgorithm(); algo != "" {
		log.Infof("TCP congestion control algorithm is %q", algo)
	}

	if err = appctl.StartServerProxy(config); err != nil {
		return fmt.Errorf(stderror.StartServerProxyFailedErr, err)
	}
	log.Debugf("Started proxy after %v", appctl.Elapsed())

	// Wait until a stop signal is received.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	sig := <-stopChan
	log.Infof("received signal %v, stop shadowlemon server", sig)

	if err := appctl.StopServerProxy(); err != nil {
		log.Errorf("StopServerProxy() failed: %v", err)
	}

	log.Infof("shadowlemon server exit now")
	return nil
}

var serverStopFunc = func(s []string) error {
	pidFilePath := appctl.ServerPidFilePath()
	running, err := appctl.StopAppDaemon(pidFilePath)
	if err != nil {
		return fmt.Errorf(stderror.StopServerFailedErr, err)
	}
	if !running {
		log.Infof(stderror.ServerNotRunning)
		return nil
	}
	log.Infof("shadowlemon server is stopped")
	return nil
}

var serverStatusFunc = func(s []string) error {
	pidFilePath := appctl.ServerPidFilePath()
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("shadowlemon server status is %q", "RUNNING")
	} else {
		log.Infof("shadowlemon server status is %q", "STOPPED")
	}
	return nil
}

var serverApplyConfigFunc = func(s []string) error {
	path := s[4]
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	patch := &appctlpb.ServerConfig{}
	if err = common.UnmarshalJSON(b, patch); err != nil {
		return fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
	}
	if err := appctl.ValidateServerConfigPatch(patch); err != nil {
		return fmt.Errorf(stderror.ValidateServerConfigPatchFailedErr, err)
	}

	config, err := appctl.LoadServerConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			config = &appctlpb.ServerConfig{}
		} else {
			return fmt.Errorf(stderror.GetServerConfigFailedErr, err)
		}
	}
	if err = appctl.MergeServerConfig(config, patch); err != nil {
		return fmt.Errorf("MergeServerConfig() failed: %w", err)
	}
	if err = appctl.ValidateFullServerConfig(config); err != nil {
		return fmt.Errorf("ValidateFullServerConfig() failed: %w", err)
	}
	if err = appctl.StoreServerConfig(config); err != nil {
		return fmt.Errorf(stderror.StoreServerConfigFailedErr, err)
	}
	return nil
}

var serverReplaceConfigFunc = func(s []string) error {
	path := s[4]
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	config := &appctlpb.ServerConfig{}
	if err = common.UnmarshalJSON(b, config); err != nil {
		return fmt.Errorf("common.UnmarshalJSON() failed: %w", err)
	}
	if err = appctl.ValidateFullServerConfig(config); err != nil {
		return fmt.Errorf("ValidateFullServerConfig() failed: %w", err)
	}
	if err = appctl.StoreServerConfig(config); err != nil {
		return fmt.Errorf(stderror.StoreServerConfigFailedErr, err)
	}
	return nil
}

var serverDescribeConfigFunc = func(s []string) error {
	config, err := appctl.LoadServerConfig()
	if err != nil {
		if err == stderror.ErrFileNotExist {
			return fmt.Errorf(stderror.ServerConfigNotExist)
		}
		return fmt.Errorf(stderror.GetServerConfigFailedErr, err)
	}
	jsonBytes, err := common.MarshalJSON(config)
	if err != nil {
		return fmt.Errorf("common.MarshalJSON() failed: %w", err)
	}
	log.Infof("%s", string(jsonBytes))
	return nil
}
