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

//go:build !(android || darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package sockopts

// setReuseSockopts does nothing on platforms where the socket options can not
// be set.
//
// golang.org/x/sys/unix does not expose SO_REUSEPORT on Solaris and illumos, so
// the address and port reuse control can not be implemented there without
// hardcoding an unverified constant. This is not a loss for a listener, because
// the standard library already sets SO_REUSEADDR for stream listeners on these
// platforms.
//
// js, wasip1, plan9 and hurd have no socket option API in the syscall package.
// AIX, z/OS and other remaining platforms are not built or released by
// shadowlemon, and there is no test environment to verify a change of the
// historical no-op behavior.
//
// Windows, and the platforms that support the options, are implemented in
// separate files.
func setReuseSockopts(_ uintptr, _ bool) error {
	return nil
}
