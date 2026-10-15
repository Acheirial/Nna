// Copyright (C) 2025  mieru authors
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

package appctlcommon

import (
	"fmt"
	"net/netip"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

// ValidateServerListenIPAddress validates the optional server listen IP address.
// An empty address means listening on all interfaces.
func ValidateServerListenIPAddress(address string) error {
	if address == "" {
		return nil
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("server listen IP address %q is invalid", address)
	}
	return nil
}

// ValidateServerConfigSingleUser validates a single server config user.
//
// It validates:
//   - user name is not empty, and its length is not greater than 64 bytes
//   - user has either a password or a hashed password
//   - user password (if set) is strong enough, and is consistent with the
//     hashed password if both are set
//   - user hashed password (if set) is a hex encoded SHA-256 digest
func ValidateServerConfigSingleUser(user *pb.User) error {
	return validateUserCredentials(user)
}
