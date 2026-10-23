// Copyright (C) 2023  mieru authors
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

package version

const (
	AppVersion = "3.38.1"
)

// ProtocolName is the name of the wire protocol implemented by this program.
const ProtocolName = "ShadowLemon"

// ProtocolVersion is the human readable version of the wire protocol.
// It is independent from AppVersion, which versions the program itself, and
// from the protocol version byte carried by the handshake, which stays 3.
const ProtocolVersion = "V0.1"

// ProtocolIdentifier returns the protocol name followed by its version, for
// example "ShadowLemon V0.1".
func ProtocolIdentifier() string {
	return ProtocolName + " " + ProtocolVersion
}
