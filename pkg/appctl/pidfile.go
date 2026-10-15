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
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

const (
	// serverPidFilePath is the file that stores the PID of the running mita server.
	serverPidFilePath = "/var/run/mita/mita.pid"

	// daemonStartTimeout is how long the start command waits for
	// the started daemon to become alive.
	daemonStartTimeout = 10 * time.Second

	// daemonStartPollInterval is the polling interval to check
	// whether the daemon is alive.
	daemonStartPollInterval = 100 * time.Millisecond

	// daemonStopTimeout is how long the stop command waits for
	// the daemon to exit after SIGTERM is sent, before SIGKILL is sent.
	daemonStopTimeout = 10 * time.Second

	// daemonStopPollInterval is the polling interval to check
	// whether the daemon has exited.
	daemonStopPollInterval = 100 * time.Millisecond
)

// ClientPidFilePath returns the file path that stores the PID of the running mieru client.
func ClientPidFilePath() (string, error) {
	if err := prepareClientConfigDir(); err != nil {
		return "", fmt.Errorf("prepareClientConfigDir() failed: %w", err)
	}
	return filepath.Join(cachedClientConfigDir, "mieru.pid"), nil
}

// ServerPidFilePath returns the file path that stores the PID of the running mita server.
func ServerPidFilePath() string {
	return serverPidFilePath
}

// WritePidFile writes the PID of the current process into the given file.
func WritePidFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("os.MkdirAll() failed: %w", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		return fmt.Errorf("os.WriteFile(%q) failed: %w", path, err)
	}
	return nil
}

// ReadPidFile reads the PID stored in the given file.
// It returns stderror.ErrFileNotExist if the file is not found.
func ReadPidFile(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, stderror.ErrFileNotExist
		}
		return 0, fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	s := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid PID %q in pid file %q: %w", s, path, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid PID %d in pid file %q", pid, path)
	}
	return pid, nil
}

// RemovePidFile deletes the given pid file.
// Any error is logged rather than returned, because deleting a pid file
// is a cleanup operation.
func RemovePidFile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Debugf("os.Remove(%q) failed: %v", path, err)
	}
}

// IsAppRunning returns whether the application recorded in the given pid file
// is still running, and the PID recorded in the pid file.
func IsAppRunning(pidFilePath string) (running bool, pid int) {
	pid, err := ReadPidFile(pidFilePath)
	if err != nil {
		if !errors.Is(err, stderror.ErrFileNotExist) {
			log.Debugf("ReadPidFile(%q) failed: %v", pidFilePath, err)
		}
		return false, 0
	}
	if !processAlive(pid) {
		return false, pid
	}
	return true, pid
}

// StartAppDaemon starts the application in the background and waits until
// the background process becomes alive. execPath is the path of the executable
// to run, which is started with the "run" argument.
func StartAppDaemon(execPath, pidFilePath string) error {
	if running, pid := IsAppRunning(pidFilePath); running {
		log.Debugf("process %d is already running", pid)
		return nil
	}
	// The pid file is stale, remove it before starting a new process.
	RemovePidFile(pidFilePath)

	if err := spawnBackgroundProcess(execPath); err != nil {
		return fmt.Errorf("spawnBackgroundProcess() failed: %w", err)
	}

	deadline := time.Now().Add(daemonStartTimeout)
	for time.Now().Before(deadline) {
		if running, _ := IsAppRunning(pidFilePath); running {
			return nil
		}
		time.Sleep(daemonStartPollInterval)
	}
	return fmt.Errorf("background process is not running after %v", daemonStartTimeout)
}

// StopAppDaemon stops the application recorded in the given pid file.
// It returns true if a running application is stopped, and false if
// no running application is found.
func StopAppDaemon(pidFilePath string) (bool, error) {
	running, pid := IsAppRunning(pidFilePath)
	if !running {
		RemovePidFile(pidFilePath)
		return false, nil
	}

	if err := terminateProcess(pid); err != nil {
		return true, fmt.Errorf("terminate process %d failed: %w", pid, err)
	}
	deadline := time.Now().Add(daemonStopTimeout)
	for time.Now().Before(deadline) {
		if pidFileRemoved(pidFilePath) {
			return true, nil
		}
		if !processAlive(pid) {
			RemovePidFile(pidFilePath)
			return true, nil
		}
		time.Sleep(daemonStopPollInterval)
	}

	// The process doesn't exit gracefully. Kill it.
	log.Warnf("process %d is not stopped after %v, kill it now", pid, daemonStopTimeout)
	if err := killProcess(pid); err != nil {
		return true, fmt.Errorf("kill process %d failed: %w", pid, err)
	}
	deadline = time.Now().Add(daemonStopTimeout)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			break
		}
		time.Sleep(daemonStopPollInterval)
	}
	RemovePidFile(pidFilePath)
	return true, nil
}

// pidFileRemoved returns true if the given pid file no longer exists.
// The daemon deletes its own pid file before exit, so this is a reliable
// signal that the daemon has stopped, even when the process is not reaped
// by its parent yet.
func pidFileRemoved(path string) bool {
	_, err := os.Stat(path)
	return os.IsNotExist(err)
}

// spawnBackgroundProcess starts the given executable, which runs with
// the "run" argument, as a background process detached from the caller.
func spawnBackgroundProcess(execPath string) error {
	cmd := exec.Command(execPath, "run")
	if errors.Is(cmd.Err, exec.ErrDot) {
		cmd.Err = nil
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = daemonSysProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	// Release the process so that the caller doesn't wait for it.
	return cmd.Process.Release()
}
