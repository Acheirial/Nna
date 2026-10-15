// Copyright (C) 2024  mieru authors
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

package sockopts

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

// Control is the Control function used by net.Dialer.
type Control = func(network, address string, c syscall.RawConn) error

// RawControl is the Control function used by syscall.RawConn.
type RawControl = func(fd uintptr)

// RawControlErr returns an error with RawControl.
type RawControlErr = func(fd uintptr) error

// ApplyTCPControl applies the control to the TCP listener.
func ApplyTCPControl(l *net.TCPListener, controlFunc Control) error {
	rawConn, err := l.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn() failed: %w", err)
	}
	return controlFunc(l.Addr().Network(), l.Addr().String(), rawConn)
}

// ApplyUDPControl applies the control to the UDP connection.
func ApplyUDPControl(c *net.UDPConn, controlFunc Control) error {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn() failed: %w", err)
	}
	return controlFunc(c.LocalAddr().Network(), c.LocalAddr().String(), rawConn)
}

// ReuseAddrPort sets SO_REUSEADDR and SO_REUSEPORT options to a given connection.
//
// SO_REUSEPORT allows more than one socket to bind to the same address and
// port. Another local process can join the same group and receive a part of the
// traffic of this socket, so only use this control for a listener when this
// risk is accepted.
//
// The options are not set on platforms where they are not supported.
func ReuseAddrPort() Control {
	return controlFromRawErr(ReuseAddrPortRawErr())
}

// ReuseAddrPortRaw is the same as ReuseAddrPort, but ignores error.
func ReuseAddrPortRaw() RawControl {
	return func(fd uintptr) {
		ReuseAddrPortRawErr()(fd)
	}
}

// ReuseAddrPortRawErr is the same as ReuseAddrPort, but returns error.
func ReuseAddrPortRawErr() RawControlErr {
	return func(fd uintptr) error {
		return setReuseSockopts(fd, true)
	}
}

// DefaultDialerControl is the default control function for dialer.
//
// It sets SO_REUSEADDR, which allows a socket to bind to a local address that
// is still in the TIME_WAIT state. SO_REUSEPORT is not set, because a dialer
// socket does not need it, and because rejecting every new connection when an
// optional option can not be set is worse than not setting the option.
//
// If the MIERU_PROTECT_PATH environment variable is set (the Android VPN
// service), the file descriptor is also sent to that path.
func DefaultDialerControl() Control {
	return func(network, address string, c syscall.RawConn) error {
		if err := applyRawControlErr(c, reuseAddrRawErr()); err != nil {
			return err
		}
		if path, found := os.LookupEnv("MIERU_PROTECT_PATH"); found {
			if err := c.Control(ProtectPathRaw(path)); err != nil {
				return err
			}
		}
		return nil
	}
}

// DefaultListenerControl is the default control function for listener.
//
// It only sets SO_REUSEADDR, which is enough to bind to a local address that is
// still in the TIME_WAIT state, so a listener can be restarted after the
// previous process exited. SO_REUSEPORT is intentionally not set, because it
// allows other local processes to bind the same address and port, and to steal
// a part of the traffic of this listener. Use ReusePortListenerControl() when
// zero down time restart is required and the risk is accepted.
func DefaultListenerControl() Control {
	return controlFromRawErr(reuseAddrRawErr())
}

// ReusePortListenerControl is the listener control function that sets both
// SO_REUSEADDR and SO_REUSEPORT.
//
// SO_REUSEPORT allows a new process to bind the same address and port while the
// old process is still listening, which enables zero down time restart. The
// cost is that any local process can join the same listening group and receive
// a part of the traffic of this listener, and the operating system does not
// always verify the identity of the process. Only use this control when the
// risk is accepted, for example on a server that has no untrusted local user.
//
// The control is a no-op on platforms without SO_REUSEPORT, for example
// Windows. The listener still works there, but zero down time restart is not
// supported.
func ReusePortListenerControl() Control {
	return controlFromRawErr(ReuseAddrPortRawErr())
}

// controlFromRawErr converts a RawControlErr to a Control.
func controlFromRawErr(rawControl RawControlErr) Control {
	return func(_, _ string, c syscall.RawConn) error {
		return applyRawControlErr(c, rawControl)
	}
}

// applyRawControlErr runs rawControl on the file descriptor of c, and returns
// the error reported by either rawControl or c.Control().
func applyRawControlErr(c syscall.RawConn, rawControl RawControlErr) error {
	var err error
	if controlErr := c.Control(func(fd uintptr) { err = rawControl(fd) }); controlErr != nil {
		return fmt.Errorf("Control() failed: %w", controlErr)
	}
	return err
}

// reuseAddrRawErr sets SO_REUSEADDR, but not SO_REUSEPORT, to fd.
func reuseAddrRawErr() RawControlErr {
	return func(fd uintptr) error {
		return setReuseSockopts(fd, false)
	}
}
