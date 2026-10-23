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

package appctlcommon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Acheirial/shadowlemon/v3/apis/constant"
	pb "github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"google.golang.org/protobuf/proto"
)

const (
	// minPasswordLen is the minimum length of a plaintext password in bytes.
	minPasswordLen = 8

	// maxPasswordLen is the maximum length of a plaintext password in bytes.
	maxPasswordLen = 64

	// hashedPasswordLen is the length of a hashed password in bytes.
	hashedPasswordLen = sha256.Size
)

// UserListToMap convert a slice of User to a map of <name, User>.
func UserListToMap(users []*pb.User) map[string]*pb.User {
	m := map[string]*pb.User{}
	for i := 0; i < len(users); i++ {
		u := users[i]
		m[u.GetName()] = u
	}
	return m
}

// HashUserPassword replaces user's password with hashed password.
//
// It returns an error if the user has both a password and a hashed password,
// and they are not consistent.
func HashUserPassword(user *pb.User, keepPlaintext bool) (*pb.User, error) {
	if user == nil || user.GetPassword() == "" {
		return user, nil
	}
	hashed := hashPassword(user.GetPassword(), user.GetName())
	if existing := user.GetHashedPassword(); existing != "" && existing != hashed {
		return user, fmt.Errorf("user %q password doesn't match the hashed password", user.GetName())
	}
	user.HashedPassword = proto.String(hashed)
	if !keepPlaintext {
		user.Password = proto.String("")
	}
	return user, nil
}

// HashUserPasswords replaces user's password with hashed password for a slice of users.
func HashUserPasswords(users []*pb.User, keepPlaintext bool) ([]*pb.User, error) {
	for i := 0; i < len(users); i++ {
		u, err := HashUserPassword(users[i], keepPlaintext)
		if err != nil {
			return users, err
		}
		users[i] = u
	}
	return users, nil
}

// hashPassword returns the hex encoded hashed password of a user.
func hashPassword(password, name string) string {
	return hex.EncodeToString(cipher.HashPassword([]byte(password), []byte(name)))
}

// validateUserCredentials validates the user name, password and hashed
// password fields shared by server config and client config.
//
// It validates:
//   - user name is not empty, and its length is not greater than 64 bytes
//   - user has either a password or a hashed password
//   - user password (if set) length is between 8 and 64 bytes, is not
//     composed of digits only or a single repeated character, and is
//     consistent with the hashed password if both are set
//   - user hashed password (if set) is a hex encoded SHA-256 digest
func validateUserCredentials(user *pb.User) error {
	if user.GetName() == "" {
		return fmt.Errorf("user name is not set")
	}
	if user.GetPassword() == "" && user.GetHashedPassword() == "" {
		return fmt.Errorf("user password is not set")
	}
	if len(user.GetName()) > constant.MaxUserNameLen {
		return fmt.Errorf("user name exceeds %d bytes", constant.MaxUserNameLen)
	}
	if user.GetPassword() != "" && len(user.GetPassword()) > maxPasswordLen {
		return fmt.Errorf("user password exceeds %d bytes", maxPasswordLen)
	}
	if user.GetHashedPassword() != "" {
		if err := validateHashedPassword(user.GetHashedPassword()); err != nil {
			return err
		}
	}
	if user.GetPassword() != "" {
		if err := validatePasswordStrength(user.GetPassword()); err != nil {
			return err
		}
		if hashed := user.GetHashedPassword(); hashed != "" && hashed != hashPassword(user.GetPassword(), user.GetName()) {
			return fmt.Errorf("user password doesn't match the hashed password")
		}
	}
	return nil
}

// validateHashedPassword validates a hex encoded hashed password.
func validateHashedPassword(hashedPassword string) error {
	b, err := hex.DecodeString(hashedPassword)
	if err != nil {
		return fmt.Errorf("user hashed password is not a valid hex string")
	}
	if len(b) != hashedPasswordLen {
		return fmt.Errorf("user hashed password decodes to %d bytes, want %d bytes", len(b), hashedPasswordLen)
	}
	return nil
}

// validatePasswordStrength validates the strength of a plaintext password.
func validatePasswordStrength(password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("user password is less than %d bytes", minPasswordLen)
	}
	allDigits := true
	allIdentical := true
	for i := 0; i < len(password); i++ {
		if password[i] < '0' || password[i] > '9' {
			allDigits = false
		}
		if password[i] != password[0] {
			allIdentical = false
		}
	}
	if allDigits {
		return fmt.Errorf("user password contains digits only")
	}
	if allIdentical {
		return fmt.Errorf("user password repeats a single character")
	}
	return nil
}
