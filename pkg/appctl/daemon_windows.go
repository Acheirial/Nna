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

//go:build windows

package appctl

import (
	"errors"
	"syscall"
)

// daemonSysProcAttr returns the process attributes to start a background
// process without a console window, which is detached from the current terminal.
func daemonSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | syscall.DETACHED_PROCESS}
}

// processAlive returns true if a process with the given PID exists.
func processAlive(pid int) bool {
	h, err := syscall.OpenProcess(syscall.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		// A process owned by another user can't be opened due to the lack of
		// permission, but it is still running.
		return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
	}
	syscall.CloseHandle(h)
	return true
}

// terminateProcess forces the process with the given PID to exit.
func terminateProcess(pid int) error {
	return killProcess(pid)
}

// killProcess forces the process with the given PID to exit.
func killProcess(pid int) error {
	h, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer syscall.CloseHandle(h)
	return syscall.TerminateProcess(h, 1)
}
