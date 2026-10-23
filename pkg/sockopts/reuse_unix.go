// Copyright (C) 2022  mieru authors
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

//go:build android || darwin || dragonfly || freebsd || linux || netbsd || openbsd

package sockopts

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// setReuseSockopts sets SO_REUSEADDR, and optionally SO_REUSEPORT, to fd.
//
// This file covers Linux, Android, macOS, iOS, and the BSDs, where
// golang.org/x/sys/unix exposes SO_REUSEPORT. Android satisfies the linux build
// tag and iOS satisfies the darwin build tag. AIX and z/OS expose the constant
// too, but shadowlemon is not built or released for them, so their
// implementation and behavior are not verified, and they are handled in
// reuse.go.
func setReuseSockopts(fd uintptr, reusePort bool) error {
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setsockopt SO_REUSEADDR failed: %w", err)
	}
	if !reusePort {
		return nil
	}
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		return fmt.Errorf("setsockopt SO_REUSEPORT failed: %w", err)
	}
	return nil
}
