// Copyright (C) 2021  mieru authors
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

package stderror

const (
	ClientConfigNotExist               = "shadowlemon client config file doesn't exist"
	ClientGetActiveProfileFailedErr    = "shadowlemon client get active profile failed: %w"
	ClientNotRunning                   = "shadowlemon client is not running"
	CreateSocks5ServerFailedErr        = "create socks5 server failed: %w"
	DecodeHashedPasswordFailedErr      = "decode hashed password failed: %w"
	GetClientConfigFailedErr           = "get shadowlemon client config failed: %w"
	GetClientPidFilePathFailedErr      = "get shadowlemon client pid file path failed: %w"
	GetServerConfigFailedErr           = "get shadowlemon server config failed: %w"
	InvalidPortBindingsErr             = "invalid port bindings: %w"
	InvalidTransportProtocol           = "invalid transport protocol"
	IPAddressNotFound                  = "IP address not found from domain name %q"
	LookupIPFailedErr                  = "look up IP address failed: %w"
	ParseIPFailed                      = "parse IP address failed"
	RunSocks5ServerFailedErr           = "run socks5 server failed: %w"
	SegmentSizeTooBig                  = "segment size too big"
	ServerConfigNotExist               = "shadowlemon server config file doesn't exist"
	ServerNotRunning                   = "shadowlemon server is not running"
	StartClientFailedErr               = "start shadowlemon client failed: %w"
	StartServerFailedErr               = "start shadowlemon server failed: %w"
	StartServerProxyFailedErr          = "start shadowlemon server proxy failed: %w"
	StopClientFailedErr                = "stop shadowlemon client failed: %w"
	StopServerFailedErr                = "stop shadowlemon server failed: %w"
	StoreClientConfigFailedErr         = "store shadowlemon client config failed: %w"
	StoreServerConfigFailedErr         = "store shadowlemon server config failed: %w"
	ValidateFullClientConfigFailedErr  = "validate full client config failed: %w"
	ValidateFullServerConfigFailedErr  = "validate full server config failed: %w"
	ValidateServerConfigPatchFailedErr = "validate server config patch failed: %w"
	WriteClientPidFileFailedErr        = "write shadowlemon client pid file failed: %w"
	WriteServerPidFileFailedErr        = "write shadowlemon server pid file failed: %w"
)
