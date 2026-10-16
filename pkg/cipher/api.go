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
	"bytes"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

const (
	DefaultNonceSize = 24 // 24 bytes. In mieru v2, the value was 12.
	DefaultOverhead  = 16 // 16 bytes
	DefaultKeyLen    = 32 // 256 bits

	NoncePrefixLenForUserHint = 16 // 16 bytes user hint input
	NonceSuffixLenForUserHint = 4  // 4 bytes user hint output
)

// BlockCipher is an interface of block encryption and decryption.
type BlockCipher interface {
	// Encrypt appends the nonce when needed, then the encrypted plaintext, to dst.
	// The caller must provide enough capacity in dst for the complete result.
	Encrypt(dst, plaintext []byte) error

	// EncryptWithNonce encrypts plaintext with the given nonce and appends the
	// result to dst. The caller must provide enough capacity in dst for the
	// complete result.
	// This method is not supported by stateful BlockCipher.
	EncryptWithNonce(dst, nonce, plaintext []byte) error

	// Decrypt method removes the nonce in the src, then decryptes the src.
	Decrypt(ciphertext []byte) ([]byte, error)

	// DecryptWithNonce decrypts the src with the given nonce.
	// This method is not supported by stateful BlockCipher.
	DecryptWithNonce(ciphertext, nonce []byte) ([]byte, error)

	// EncryptPayloadWithNonce encrypts a payload with a nonce derived from the given message nonce.
	// The derived nonce is the message nonce with a single byte XORed with a
	// constant value, so a message nonce is never used to encrypt both the
	// metadata and the payload of the same message.
	// This method is not supported by stateful BlockCipher.
	EncryptPayloadWithNonce(dst, nonce, plaintext []byte) error

	// DecryptPayloadWithNonce decrypts a payload encrypted by EncryptPayloadWithNonce.
	// This method is not supported by stateful BlockCipher.
	DecryptPayloadWithNonce(ciphertext, nonce []byte) ([]byte, error)

	// DecryptStatelessTo decrypts ciphertext with its prepended nonce and
	// appends the plaintext to dst.
	// It MUST only be called on a stateless cipher that is not being mutated
	// concurrently.
	// This code is performance sensitive and may not check all invariants.
	DecryptStatelessTo(ciphertext, dst []byte) ([]byte, error)

	// NonceSize returns the size of the wire format nonce that must be passed
	// to the Encrypt and Decrypt methods. It is DefaultNonceSize for every
	// cipher suite.
	NonceSize() int

	// Suite returns the AEAD cipher suite used by the block cipher.
	Suite() Suite

	// Overhead returns the maximum difference between the lengths of a
	// plaintext and its ciphertext.
	Overhead() int

	// Clone method creates a deep copy of block cipher itself.
	// Panic if this operation fails.
	Clone() BlockCipher

	// CloneStatelessFast creates a new BlockCipher.
	// The BlockCipher being cloned must be stateless and not being mutated
	// concurrently.
	// BlockContext and NoncePattern are NOT cloned.
	// This code is performance sensitive and may not check all invariants.
	CloneStatelessFast() BlockCipher

	// SetImplicitNonceMode enables or disables implicit nonce mode.
	// Under implicit nonce mode, the nonce is set exactly once on the first
	// Encrypt() or Decrypt() call. After that, all Encrypt() or Decrypt()
	// calls will not look up nonce in the data. Each Encrypt() or Decrypt()
	// will cause the nonce value to be increased by 1.
	//
	// Implicit nonce mode is disabled by default.
	//
	// Disabling implicit nonce mode removes the implicit nonce (state)
	// from the block cipher.
	SetImplicitNonceMode(enable bool)

	// IsStateless returns true if the BlockCipher can do arbitrary Encrypt()
	// and Decrypt() in any sequence.
	IsStateless() bool

	// BlockContext returns a copy of BlockContext.
	BlockContext() BlockContext

	// SetBlockContext sets the BlockContext.
	SetBlockContext(bc BlockContext)

	// NoncePattern returns a copy of NoncePattern associated with the cipher block.
	NoncePattern() *appctlpb.NoncePattern

	// SetNoncePattern sets the NoncePattern associated with the cipher block.
	SetNoncePattern(pattern *appctlpb.NoncePattern)
}

// BlockContext contains optional context associated to a cipher block.
type BlockContext struct {
	UserName string
}

// HashPassword generates a hashed password from
// the raw password and a unique value that decorates the password.
func HashPassword(rawPassword, uniqueValue []byte) []byte {
	p := append(rawPassword, 0x00) // 0x00 separates the password and username.
	p = append(p, uniqueValue...)
	hashed := sha256.Sum256(p)
	return hashed[:]
}

// NewBlockCipherFromKey creates a BlockCipher object from an AEAD key.
// The key is copied, so the caller can erase the input afterwards.
// At least suite.KeyLen() key bytes must be provided, and only the first
// suite.KeyLen() bytes are used; extra key bytes are ignored.
func NewBlockCipherFromKey(suite Suite, key []byte, stateless bool) (BlockCipher, error) {
	block, err := newBlockCipher(suite, key)
	if err != nil {
		return nil, err
	}
	if !stateless {
		block.SetImplicitNonceMode(true)
	}
	return block, nil
}

// BlockCipherFromPassword creates a BlockCipher object from the password
// with the supplied cipher suite and the default settings.
func BlockCipherFromPassword(suite Suite, password []byte, stateless bool) (BlockCipher, error) {
	entry, err := getCachedCiphers(string(password), suite, time.Now())
	if err != nil {
		return nil, err
	}
	block := entry.cipherList[1].CloneStatelessFast()
	if !stateless {
		block.SetImplicitNonceMode(true)
	}
	return block, nil
}

// BlockCipherListFromPassword creates three BlockCipher objects of the given
// cipher suite, using three different salts from the password with the default
// settings. Element 0 uses the salt of the previous key refresh interval,
// element 1 uses the salt of the current one, and element 2 uses the salt of
// the next one, which allows a caller to handle a peer with a clock offset of
// up to two minutes in either direction.
func BlockCipherListFromPassword(suite Suite, password []byte, stateless bool) ([]BlockCipher, error) {
	entry, err := getCachedCiphers(string(password), suite, time.Now())
	if err != nil {
		return nil, err
	}
	blocks := make([]BlockCipher, len(entry.cipherList))
	for i, template := range entry.cipherList {
		blocks[i] = template.CloneStatelessFast()
		if !stateless {
			blocks[i].SetImplicitNonceMode(true)
		}
	}
	return blocks, nil
}

// CheckUserFromHint checks if the user is the one associated with the nonce.
// The user hint embedded in the nonce is only used to quickly filter candidate
// users before real authentication. It can be computed by anyone who knows the
// user name, so a matching hint provides no authentication by itself and must
// never be used as an access control check.
// It panics if the user is empty or too long, or the nonce is too short.
func CheckUserFromHint(user, nonce []byte) bool {
	if len(user) == 0 {
		panic("user is empty")
	}
	if len(user) > constant.MaxUserNameLen {
		panic(fmt.Sprintf("user name length %d exceeds maximum %d", len(user), constant.MaxUserNameLen))
	}
	if len(nonce) < NoncePrefixLenForUserHint+NonceSuffixLenForUserHint {
		panic(fmt.Sprintf("nonce length %d is too short", len(nonce)))
	}
	var input [constant.MaxUserNameLen + NoncePrefixLenForUserHint]byte
	n := copy(input[:], user)
	n += copy(input[n:], nonce[:NoncePrefixLenForUserHint])
	output := sha256.Sum256(input[:n])
	return bytes.Equal(output[:NonceSuffixLenForUserHint], nonce[len(nonce)-NonceSuffixLenForUserHint:])
}

// NewStatelessDecryptor builds a StatelessDecryptor for the given cipher
// suites and password. An empty suite list means all the supported cipher
// suites. The password bytes are copied, so the caller can erase the input
// afterwards.
func NewStatelessDecryptor(suites []Suite, password []byte) (*StatelessDecryptor, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password is empty")
	}
	if len(suites) == 0 {
		suites = AllSuites()
	}
	configured := make([]Suite, len(suites))
	for i, suite := range suites {
		if !suite.IsValid() {
			return nil, fmt.Errorf("invalid cipher suite %d", uint8(suite))
		}
		configured[i] = suite
	}
	p := make([]byte, len(password))
	copy(p, password)
	return &StatelessDecryptor{password: p, suites: configured}, nil
}

// preparedCiphers holds the decryption material of a StatelessDecryptor for a
// single key epoch. It contains one list per configured cipher suite, and each
// list contains the three time slot ciphers of that suite.
type preparedCiphers struct {
	lists [][]*aeadBlockCipher
	epoch int64
}

// StatelessDecryptor is optimized and safe for concurrent decryption.
type StatelessDecryptor struct {
	// mu guards password and suites. Caller must hold mu to access them.
	mu       sync.RWMutex
	password []byte
	suites   []Suite
	ciphers  atomic.Pointer[preparedCiphers]
}

// Clear erases the password stored in the decryptor. The decryptor must not be
// used to decrypt data after Clear returns.
func (d *StatelessDecryptor) Clear() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.password {
		d.password[i] = 0
	}
	d.password = nil
	d.suites = nil
	d.ciphers.Store(nil)
}

// TryDecrypt tries to decrypt the ciphertext with the three time slot ciphers
// of every configured cipher suite, with its prepended wire format nonce.
// The suite ciphers are tried in the configured order, and the first cipher
// suite whose AEAD tag verifies wins. The returned BlockCipher exposes the
// cipher suite that authenticated the ciphertext through Suite().
func (d *StatelessDecryptor) TryDecrypt(ciphertext, dst []byte) (BlockCipher, []byte, error) {
	return d.tryDecryptAt(ciphertext, dst, time.Now())
}

func (d *StatelessDecryptor) tryDecryptAt(ciphertext, dst []byte, now time.Time) (BlockCipher, []byte, error) {
	if d == nil {
		return nil, nil, fmt.Errorf("stateless decryptor is nil")
	}
	// Hold the read lock so that Clear() can't erase the password while it is
	// in use.
	d.mu.RLock()
	defer d.mu.RUnlock()
	if len(d.password) == 0 {
		return nil, nil, fmt.Errorf("stateless decryptor is cleared")
	}
	epoch := cipherKeyEpoch(now)
	entry := d.ciphers.Load()
	if entry == nil || entry.epoch != epoch {
		lists := make([][]*aeadBlockCipher, 0, len(d.suites))
		for _, suite := range d.suites {
			cached, err := getCachedCiphers(string(d.password), suite, now)
			if err != nil {
				return nil, nil, err
			}
			lists = append(lists, cached.cipherList)
		}
		entry = &preparedCiphers{lists: lists, epoch: epoch}
		d.ciphers.Store(entry)
	}
	// The cipher suites are tried in the configured order, and the three time
	// slots of a suite are tried by selectDecryptStateless. The first cipher
	// suite that authenticates the ciphertext wins.
	for _, list := range entry.lists {
		block, plaintext, err := selectDecryptStateless(ciphertext, dst, list)
		if err == nil {
			return block.CloneStatelessFast(), plaintext, nil
		}
	}
	return nil, nil, errUnableToDecrypt
}

func cipherKeyEpoch(t time.Time) int64 {
	return t.Round(KeyRefreshInterval).Unix()
}
