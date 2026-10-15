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
	binaryName = "mita"
	RegisterCallback(
		[]string{"", "help"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		serverHelpFunc,
	)
	RegisterCallback(
		[]string{"", "start"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		serverStartFunc,
	)
	RegisterCallback(
		[]string{"", "run"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		serverRunFunc,
	)
	RegisterCallback(
		[]string{"", "stop"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		serverStopFunc,
	)
	RegisterCallback(
		[]string{"", "status"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		serverStatusFunc,
	)
	RegisterCallback(
		[]string{"", "apply", "config"},
		func(s []string) error {
			if len(s) < 4 {
				return fmt.Errorf("usage: mita apply config <FILE>. no config file is provided")
			} else if len(s) > 4 {
				return fmt.Errorf("usage: mita apply config <FILE>. more than 1 config file is provided")
			}
			return nil
		},
		serverApplyConfigFunc,
	)
	RegisterCallback(
		[]string{"", "replace", "config"},
		func(s []string) error {
			if len(s) < 4 {
				return fmt.Errorf("usage: mita replace config <FILE>. no config file is provided")
			} else if len(s) > 4 {
				return fmt.Errorf("usage: mita replace config <FILE>. more than 1 config file is provided")
			}
			return nil
		},
		serverReplaceConfigFunc,
	)
	RegisterCallback(
		[]string{"", "describe", "config"},
		func(s []string) error {
			return unexpectedArgsError(s, 3)
		},
		serverDescribeConfigFunc,
	)
	RegisterCallback(
		[]string{"", "version"},
		func(s []string) error {
			return unexpectedArgsError(s, 2)
		},
		versionFunc,
	)
}

var serverHelpFunc = func(s []string) error {
	helpFmt := helpFormatter{
		appName: "mita",
		entries: []helpCmdEntry{
			{
				cmd:  "help",
				help: []string{"Show mita server help."},
			},
			{
				cmd:  "start",
				help: []string{"Start mita server in background."},
			},
			{
				cmd:  "stop",
				help: []string{"Stop mita server."},
			},
			{
				cmd:  "status",
				help: []string{"Check mita server status."},
			},
			{
				cmd: "apply config <JSON_FILE>",
				help: []string{
					"Apply server configuration patch from a file.",
					"It merges the patch with existing server configuration.",
				},
			},
			{
				cmd: "replace config <JSON_FILE>",
				help: []string{
					"Replace saved server configuration with a complete JSON file.",
					"Omitted settings and users are removed.",
				},
			},
			{
				cmd:  "describe config",
				help: []string{"Show current server configuration."},
			},
			{
				cmd:  "version",
				help: []string{"Show mita server version."},
			},
		},
		advanced: []helpCmdEntry{
			{
				cmd: "run",
				help: []string{
					"Run mita server in foreground.",
					"Use environment variable MITA_CONFIG_JSON_FILE to load configuration.",
				},
			},
		},
	}
	helpFmt.print()
	return nil
}

var serverStartFunc = func(s []string) error {
	pidFilePath := appctl.ServerPidFilePath()
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("mita server is running")
		return nil
	}

	if err := appctl.StartAppDaemon(s[0], pidFilePath); err != nil {
		return fmt.Errorf(stderror.StartServerFailedErr, err)
	}
	log.Infof("mita server is started")
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
	if running, pid := appctl.IsAppRunning(pidFilePath); running && pid != os.Getpid() {
		return fmt.Errorf("mita server is already running with PID %d", pid)
	}
	if err = appctl.WritePidFile(pidFilePath); err != nil {
		return fmt.Errorf(stderror.WriteServerPidFileFailedErr, err)
	}
	defer appctl.RemovePidFile(pidFilePath)

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
	log.Infof("received signal %v, stop mita server", sig)

	if err := appctl.StopServerProxy(); err != nil {
		log.Errorf("StopServerProxy() failed: %v", err)
	}

	log.Infof("mita server exit now")
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
	log.Infof("mita server is stopped")
	return nil
}

var serverStatusFunc = func(s []string) error {
	pidFilePath := appctl.ServerPidFilePath()
	if running, _ := appctl.IsAppRunning(pidFilePath); running {
		log.Infof("mita server status is %q", "RUNNING")
	} else {
		log.Infof("mita server status is %q", "STOPPED")
	}
	return nil
}

var serverApplyConfigFunc = func(s []string) error {
	path := s[3]
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
	path := s[3]
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
