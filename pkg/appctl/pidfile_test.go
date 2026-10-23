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
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

// Every test below passes an explicit pid file path inside t.TempDir(), so the
// tests never read or write the pid file of a running application, and they
// don't run in parallel with each other.

// pidFilePath returns the path of a pid file in a temporary directory.
func pidFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "app.pid")
}

// writePidFileContent writes the given raw content to a pid file, which is used
// to simulate a pid file written by another process.
func writePidFileContent(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", path, err)
	}
}

// requireProcessAliveSupport skips the test on a platform where processAlive()
// always returns false, because the pid file logic can not detect a running
// process there.
func requireProcessAliveSupport(t *testing.T) {
	t.Helper()
	if !processAlive(os.Getpid()) {
		t.Skip("processAlive() doesn't detect the current process on this platform")
	}
}

// unusedPid returns a PID that no process uses, which simulates the PID
// recorded in a pid file left over by a process that already exited.
func unusedPid(t *testing.T) int {
	t.Helper()
	for i := range 1000 {
		pid := (1 << 21) + i
		if !processAlive(pid) {
			return pid
		}
	}
	t.Skip("can't find an unused PID")
	return 0
}

// otherIdentity returns a process identity token that is different from the
// given one, which simulates a PID that is reused by an unrelated process.
func otherIdentity(identity string) string {
	if identity == "0" {
		return "1"
	}
	return "0"
}

// TestAcquirePidFileWritesCurrentProcess checks that AcquirePidFile() creates
// the pid file and records the current process.
func TestAcquirePidFileWritesCurrentProcess(t *testing.T) {
	requireProcessAliveSupport(t)
	path := pidFilePath(t)

	if err := AcquirePidFile(path); err != nil {
		t.Fatalf("AcquirePidFile(%q) failed: %v", path, err)
	}

	pid, err := ReadPidFile(path)
	if err != nil {
		t.Fatalf("ReadPidFile(%q) failed: %v", path, err)
	}
	if pid != os.Getpid() {
		t.Errorf("ReadPidFile(%q) = %d, want the current PID %d", path, pid, os.Getpid())
	}

	// The pid file records the process identity, so that a PID which is reused
	// by an unrelated process is detected.
	_, identity, err := readPidFile(path)
	if err != nil {
		t.Fatalf("readPidFile(%q) failed: %v", path, err)
	}
	if want := processIdentity(os.Getpid()); want != "" && identity != want {
		t.Errorf("pid file %q records identity %q, want %q", path, identity, want)
	}
}

// TestAcquirePidFileOfRunningProcess checks that a second AcquirePidFile() on a
// pid file that records a running process fails, and doesn't touch the pid file.
func TestAcquirePidFileOfRunningProcess(t *testing.T) {
	requireProcessAliveSupport(t)
	path := pidFilePath(t)

	if err := AcquirePidFile(path); err != nil {
		t.Fatalf("AcquirePidFile(%q) failed: %v", path, err)
	}
	err := AcquirePidFile(path)
	if err == nil {
		t.Fatalf("the second AcquirePidFile(%q) succeeded, want an error", path)
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Errorf("AcquirePidFile(%q) failed with %v, want an error that reports the process is already running", path, err)
	}

	// The pid file of the running process must still record it.
	pid, readErr := ReadPidFile(path)
	if readErr != nil {
		t.Fatalf("ReadPidFile(%q) failed: %v", path, readErr)
	}
	if pid != os.Getpid() {
		t.Errorf("ReadPidFile(%q) = %d, want the current PID %d", path, pid, os.Getpid())
	}
}

// TestAcquirePidFileReclaimsStalePidFile checks that a pid file left over by a
// process that already exited, and a pid file whose PID was reused by an
// unrelated process, are both reclaimed.
func TestAcquirePidFileReclaimsStalePidFile(t *testing.T) {
	t.Run("PID is not used", func(t *testing.T) {
		path := pidFilePath(t)
		writePidFileContent(t, path, strconv.Itoa(unusedPid(t)))

		if err := AcquirePidFile(path); err != nil {
			t.Fatalf("AcquirePidFile(%q) failed: %v", path, err)
		}
		pid, err := ReadPidFile(path)
		if err != nil {
			t.Fatalf("ReadPidFile(%q) failed: %v", path, err)
		}
		if pid != os.Getpid() {
			t.Errorf("ReadPidFile(%q) = %d, want the current PID %d", path, pid, os.Getpid())
		}
	})

	t.Run("PID is reused by an unrelated process", func(t *testing.T) {
		want := processIdentity(os.Getpid())
		if want == "" {
			t.Skip("the platform doesn't expose the process start time")
		}
		path := pidFilePath(t)
		// The pid file records the current PID, but not the start time of the
		// process that uses the PID now.
		writePidFileContent(t, path, fmt.Sprintf("%d %s", os.Getpid(), otherIdentity(want)))

		if err := AcquirePidFile(path); err != nil {
			t.Fatalf("AcquirePidFile(%q) failed: %v", path, err)
		}
		pid, identity, err := readPidFile(path)
		if err != nil {
			t.Fatalf("readPidFile(%q) failed: %v", path, err)
		}
		if pid != os.Getpid() {
			t.Errorf("pid file %q records PID %d, want the current PID %d", path, pid, os.Getpid())
		}
		if identity != want {
			t.Errorf("pid file %q records identity %q, want %q", path, identity, want)
		}
	})
}

// TestReadPidFile checks the parsing of a pid file, and the error reported for
// a pid file that can't be trusted.
func TestReadPidFile(t *testing.T) {
	tests := []struct {
		name         string
		content      string
		writeFile    bool
		wantPid      int
		wantIdentity string
		wantErr      error
		wantAnyErr   bool
	}{
		{
			name:    "file does not exist",
			wantErr: stderror.ErrFileNotExist,
		},
		{
			name:      "legacy format",
			content:   "1234",
			writeFile: true,
			wantPid:   1234,
		},
		{
			name:         "with process identity",
			content:      "1234 5678",
			writeFile:    true,
			wantPid:      1234,
			wantIdentity: "5678",
		},
		{
			name:         "content is surrounded by whitespace",
			content:      " \n\t1234\t5678 \n",
			writeFile:    true,
			wantPid:      1234,
			wantIdentity: "5678",
		},
		{
			name:       "file is empty",
			writeFile:  true,
			wantAnyErr: true,
		},
		{
			name:       "file only contains whitespace",
			content:    " \n",
			writeFile:  true,
			wantAnyErr: true,
		},
		{
			name:       "PID is not a number",
			content:    "abc",
			writeFile:  true,
			wantAnyErr: true,
		},
		{
			name:       "PID is zero",
			content:    "0",
			writeFile:  true,
			wantAnyErr: true,
		},
		{
			name:       "PID is negative",
			content:    "-1",
			writeFile:  true,
			wantAnyErr: true,
		},
		{
			name:       "PID doesn't fit in an int",
			content:    "99999999999999999999",
			writeFile:  true,
			wantAnyErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := pidFilePath(t)
			if test.writeFile {
				writePidFileContent(t, path, test.content)
			}

			pid, err := ReadPidFile(path)
			if test.wantAnyErr {
				if err == nil {
					t.Fatalf("ReadPidFile(%q) = %d, want an error", path, pid)
				}
				return
			}
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) {
					t.Fatalf("ReadPidFile(%q) failed with %v, want %v", path, err, test.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadPidFile(%q) failed: %v", path, err)
			}
			if pid != test.wantPid {
				t.Errorf("ReadPidFile(%q) = %d, want %d", path, pid, test.wantPid)
			}
			if test.wantIdentity != "" {
				_, identity, err := readPidFile(path)
				if err != nil {
					t.Fatalf("readPidFile(%q) failed: %v", path, err)
				}
				if identity != test.wantIdentity {
					t.Errorf("readPidFile(%q) returned identity %q, want %q", path, identity, test.wantIdentity)
				}
			}
		})
	}
}

// TestRemoveOwnPidFile checks that RemoveOwnPidFile() deletes the pid file of
// the current process, and keeps the pid file of another process.
func TestRemoveOwnPidFile(t *testing.T) {
	// otherPid records the PID of the pid file written by the "records another
	// process" case, so that the file content is checked against its own PID.
	// The subtests don't run in parallel, so the access is safe.
	var otherPid int

	tests := []struct {
		name       string
		setup      func(t *testing.T, path string)
		wantExists bool
		verify     func(t *testing.T, path string)
	}{
		{
			name: "records the current process",
			setup: func(t *testing.T, path string) {
				t.Helper()
				requireProcessAliveSupport(t)
				if err := AcquirePidFile(path); err != nil {
					t.Fatalf("AcquirePidFile(%q) failed: %v", path, err)
				}
			},
		},
		{
			name: "records another process",
			setup: func(t *testing.T, path string) {
				t.Helper()
				otherPid = unusedPid(t)
				writePidFileContent(t, path, strconv.Itoa(otherPid))
			},
			wantExists: true,
			verify: func(t *testing.T, path string) {
				t.Helper()
				pid, err := ReadPidFile(path)
				if err != nil {
					t.Fatalf("ReadPidFile(%q) failed: %v", path, err)
				}
				if pid != otherPid {
					t.Errorf("pid file %q records PID %d, want %d", path, pid, otherPid)
				}
			},
		},
		{
			name: "records a stale identity of the current PID",
			setup: func(t *testing.T, path string) {
				t.Helper()
				identity := processIdentity(os.Getpid())
				if identity == "" {
					t.Skip("the platform doesn't expose the process start time")
				}
				writePidFileContent(t, path, fmt.Sprintf("%d %s", os.Getpid(), otherIdentity(identity)))
			},
			wantExists: true,
			verify: func(t *testing.T, path string) {
				t.Helper()
				pid, err := ReadPidFile(path)
				if err != nil {
					t.Fatalf("ReadPidFile(%q) failed: %v", path, err)
				}
				if pid != os.Getpid() {
					t.Errorf("pid file %q records PID %d, want the current PID %d", path, pid, os.Getpid())
				}
			},
		},
		{
			name:  "file does not exist",
			setup: func(t *testing.T, path string) {},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := pidFilePath(t)
			test.setup(t, path)

			RemoveOwnPidFile(path)

			_, statErr := os.Stat(path)
			if exists := !os.IsNotExist(statErr); exists != test.wantExists {
				t.Fatalf("RemoveOwnPidFile(%q): pid file exists = %t, want %t (stat error: %v)", path, exists, test.wantExists, statErr)
			}
			if test.verify != nil {
				test.verify(t, path)
			}
		})
	}
}
