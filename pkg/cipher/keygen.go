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

package cipher

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// KeyIterV3 is the number of PBKDF2 iterations used to generate a key from
	// a password. It hardens the envelope against an offline search of the
	// password by an attacker who observes the first packet of a session: the
	// envelope key is derived from the password only, so a low iteration count
	// makes that search cheap.
	//
	// This is part of the ShadowLemon protocol. This value should not be changed.
	KeyIterV3 = 4096

	// KeyRefreshInterval is the amount of time when the salt used to generate cipher block is changed.
	// This is part of the ShadowLemon protocol. This value should not be changed.
	KeyRefreshInterval = 2 * time.Minute
)

// pbkdf2Gen implements KeyGenerator with PBKDF2 algorithm.
type pbkdf2Gen struct {
	Salt []byte
	Iter int
}

// NewKey creates a new key from the given password.
func (g *pbkdf2Gen) NewKey(password []byte, keyLen int) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	return pbkdf2.Key(password, g.Salt, g.Iter, keyLen, sha256.New), nil
}

// saltFromTime generates the three salts (each 32 bytes) of the previous, the
// current and the next key refresh interval for the given time. The three
// salts cover a peer key slot offset of at most one refresh interval
// (KeyRefreshInterval, 2 minutes) in either direction: a peer whose clock
// rounds to a neighboring slot still derives the same key as one of them.
//
// This bounds the key derivation layer only. The metadata of every data
// segment carries a timestamp in minutes that is accepted only within ±1
// minute of the local clock, so the end-to-end clock tolerance of the protocol
// is that stricter ±1 minute.
func saltFromTime(t time.Time) [][]byte {
	var times []time.Time
	rounded := t.Round(KeyRefreshInterval)
	times = append(times, rounded.Add(-KeyRefreshInterval))
	times = append(times, rounded)
	times = append(times, rounded.Add(KeyRefreshInterval))

	b := make([]byte, 8) // 64 bits
	var salts [][]byte

	for _, t := range times {
		binary.BigEndian.PutUint64(b, uint64(t.Unix()))
		sha := sha256.Sum256(b)
		salts = append(salts, sha[:])
	}

	return salts
}
