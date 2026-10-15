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

	// pidFileAcquireAttempts is how many times the pid file is acquired
	// before giving up, if the file is held or written by another command.
	pidFileAcquireAttempts = 10

	// pidFileAcquireRetryInterval is the wait time between two attempts
	// to acquire the pid file.
	pidFileAcquireRetryInterval = 20 * time.Millisecond
)

// ErrPidFileExists is returned by WritePidFile if the pid file already exists.
// The caller decides whether the existing pid file is stale and can be removed,
// or is owned by another running process.
var ErrPidFileExists = errors.New("pid file already exists")

// errPidFileBeingWritten is returned when a pid file exists but its content is
// not written yet, which happens when a concurrent command creates the file.
var errPidFileBeingWritten = errors.New("pid file content is not written yet")

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

// WritePidFile writes the PID and the identity of the current process into the
// given file. The process identity is verified before a signal is sent to the
// PID, which detects a pid file that was left over by a crashed process, and
// whose PID is reused by an unrelated process.
// It returns ErrPidFileExists if the file already exists.
func WritePidFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("os.MkdirAll() failed: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%w: %q", ErrPidFileExists, path)
		}
		return fmt.Errorf("os.OpenFile(%q) failed: %w", path, err)
	}
	if _, err := f.WriteString(encodePidFile(os.Getpid())); err != nil {
		f.Close()
		RemovePidFile(path)
		return fmt.Errorf("write to pid file %q failed: %w", path, err)
	}
	if err := f.Close(); err != nil {
		RemovePidFile(path)
		return fmt.Errorf("close pid file %q failed: %w", path, err)
	}
	return nil
}

// AcquirePidFile writes the PID of the current process into the given file.
// It returns an error if the pid file is owned by another running process.
// A stale pid file, which was left over by a process that already exited, is
// removed and recreated. The file is created atomically, so that concurrent
// start commands don't delete the pid file of each other.
func AcquirePidFile(path string) error {
	for i := 0; i < pidFileAcquireAttempts; i++ {
		err := WritePidFile(path)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrPidFileExists) {
			return err
		}
		pid, identity, err := readPidFile(path)
		if err != nil {
			if errors.Is(err, errPidFileBeingWritten) {
				// Another command is creating the pid file right now.
				time.Sleep(pidFileAcquireRetryInterval)
			} else if !errors.Is(err, stderror.ErrFileNotExist) {
				// The pid file is corrupted, its content can't be trusted.
				RemovePidFile(path)
			}
			continue
		}
		if processRunning(pid, identity) {
			return fmt.Errorf("process %d is already running", pid)
		}
		// The recorded process is not running, the pid file is stale.
		RemovePidFile(path)
	}
	return fmt.Errorf("failed to write pid file %q", path)
}

// ReadPidFile reads the PID stored in the given file.
// It returns stderror.ErrFileNotExist if the file is not found.
func ReadPidFile(path string) (int, error) {
	pid, _, err := readPidFile(path)
	return pid, err
}

// readPidFile reads the PID and the process identity stored in the given file.
// The identity is empty if the file uses the legacy format, which only records
// the PID, or if the process identity was unavailable when the file was written.
// It returns stderror.ErrFileNotExist if the file is not found.
func readPidFile(path string) (pid int, identity string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, "", stderror.ErrFileNotExist
		}
		return 0, "", fmt.Errorf("os.ReadFile(%q) failed: %w", path, err)
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("pid file %q: %w", path, errPidFileBeingWritten)
	}
	pid, err = strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid PID %q in pid file %q: %w", fields[0], path, err)
	}
	if pid <= 0 {
		return 0, "", fmt.Errorf("invalid PID %d in pid file %q", pid, path)
	}
	if len(fields) > 1 {
		identity = fields[1]
	}
	return pid, identity, nil
}

// encodePidFile returns the content of a pid file that records the given
// process. The process identity is omitted if the operating system doesn't
// expose it, in which case the pid file keeps the legacy format.
func encodePidFile(pid int) string {
	if identity := processIdentity(pid); identity != "" {
		return fmt.Sprintf("%d %s", pid, identity)
	}
	return strconv.Itoa(pid)
}

// processRunning returns true if a process with the given PID is running.
// If identity is not empty, the identity of the process must match as well,
// which detects a PID that is reused by an unrelated process.
func processRunning(pid int, identity string) bool {
	if !processAlive(pid) {
		return false
	}
	if identity != "" {
		if current := processIdentity(pid); current != "" && current != identity {
			log.Debugf("process %d recorded in the pid file is not the process using the PID now", pid)
			return false
		}
	}
	return true
}

// processIdentity returns a token that identifies the process with the given
// PID. The token is derived from the process start time, which is read from
// /proc, so that a reused PID never has the same token. An empty string is
// returned if the operating system doesn't expose the start time, in which
// case only the liveness of the process can be verified.
func processIdentity(pid int) string {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	s := string(b)
	// The second field of /proc/<pid>/stat is the executable name, which may
	// contain spaces and parentheses. Fields after the last ')' don't have
	// this problem.
	i := strings.LastIndex(s, ")")
	if i < 0 || i+1 >= len(s) {
		return ""
	}
	fields := strings.Fields(s[i+1:])
	// Field 3 starts at fields[0], so the process start time, which is
	// field 22, is at fields[19].
	if len(fields) < 20 {
		return ""
	}
	if _, err := strconv.ParseInt(fields[19], 10, 64); err != nil {
		return ""
	}
	return fields[19]
}

// RemovePidFile deletes the given pid file.
// Any error is logged rather than returned, because deleting a pid file
// is a cleanup operation.
func RemovePidFile(path string) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		log.Debugf("os.Remove(%q) failed: %v", path, err)
	}
}

// RemoveOwnPidFile deletes the given pid file if it records the current process.
// It is used by a daemon before exit, so that a pid file which records another
// process, e.g. a process created by a concurrent start command, is not deleted.
// Any error is logged rather than returned, because deleting a pid file
// is a cleanup operation.
func RemoveOwnPidFile(path string) {
	pid, identity, err := readPidFile(path)
	if err != nil {
		log.Debugf("readPidFile(%q) failed: %v", path, err)
		return
	}
	if pid != os.Getpid() {
		log.Debugf("pid file %q records process %d instead of the current process %d, don't remove it", path, pid, os.Getpid())
		return
	}
	if identity != "" {
		if current := processIdentity(pid); current != "" && current != identity {
			log.Debugf("pid file %q doesn't record the current process, don't remove it", path)
			return
		}
	}
	RemovePidFile(path)
}

// removePidFileIfRecords deletes the given pid file if it records the given PID.
// The pid file is not deleted if another process replaced it, e.g. a concurrent
// start command, since the file was read.
func removePidFileIfRecords(path string, pid int) {
	p, _, err := readPidFile(path)
	if err != nil || p != pid {
		return
	}
	RemovePidFile(path)
}

// IsAppRunning returns whether the application recorded in the given pid file
// is still running, and the PID recorded in the pid file.
// A pid file that records the identity of a process, which is different from
// the identity of the process that uses the PID now, is considered stale,
// because the PID was likely reused by an unrelated process.
func IsAppRunning(pidFilePath string) (running bool, pid int) {
	pid, identity, err := readPidFile(pidFilePath)
	if err != nil {
		if !errors.Is(err, stderror.ErrFileNotExist) {
			log.Debugf("readPidFile(%q) failed: %v", pidFilePath, err)
		}
		return false, 0
	}
	if !processRunning(pid, identity) {
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
	// Remove the stale pid file, so that the started process can write its own
	// pid file. The pid file of a concurrent start command is not removed.
	if pid, _, err := readPidFile(pidFilePath); err == nil {
		removePidFileIfRecords(pidFilePath, pid)
	}

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
// no running application is found. No signal is sent if the pid file records
// a process that is not running, or a process that is not the application.
func StopAppDaemon(pidFilePath string) (bool, error) {
	running, pid := IsAppRunning(pidFilePath)
	if !running {
		// The PID either no longer exists, or is used by an unrelated process.
		// Don't send a signal to it, just clean up the stale pid file.
		if pid > 0 {
			removePidFileIfRecords(pidFilePath, pid)
		} else {
			RemovePidFile(pidFilePath)
		}
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
			removePidFileIfRecords(pidFilePath, pid)
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
	removePidFileIfRecords(pidFilePath, pid)
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
