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

package sockopts

// setReuseSockopts does nothing on Windows, which is a deliberate no-op.
//
// Windows does not have SO_REUSEPORT, and SO_REUSEADDR means something else
// there: a socket that sets SO_REUSEADDR can bind to an address and port that
// is already bound by another socket. Any local process can therefore hijack
// or block the traffic of a listener, and the correct socket that serves a
// connection is not deterministic. For the same reason, the standard library
// does not set SO_REUSEADDR for listeners (see sockopt_windows.go in the net
// package).
//
// The options are also not needed by shadowlemon: Windows reuses a recently
// used address by default, so a listener can be restarted after the previous
// process exited without setting any socket option, and dialer sockets use an
// ephemeral local port instead of a fixed one.
func setReuseSockopts(_ uintptr, _ bool) error {
	return nil
}
