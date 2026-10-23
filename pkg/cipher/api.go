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

	"github.com/Acheirial/shadowlemon/v3/apis/constant"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/version"
)

const (
	DefaultNonceSize = 24 // 24 bytes.
	DefaultOverhead  = 16 // 16 bytes
	DefaultKeyLen    = 32 // 256 bits

	NoncePrefixLenForUserHint = 16 // 16 bytes user hint input
	NonceSuffixLenForUserHint = 4  // 4 bytes user hint output

	// HintPepperLen is the length in bytes of the user hint pepper returned by
	// HintPepper. Only the first HintPepperLen bytes of a pepper are used, both
	// when a hint is written and when it is checked.
	HintPepperLen = 16
)

// BlockCipher is an interface of block encryption and decryption.
type BlockCipher interface {
	// Encrypt appends the nonce when needed, then the encrypted plaintext, to dst.
	// The caller must provide enough capacity in dst for the complete result.
	//
	// It fails if the block context carries a user name without a user hint
	// pepper, because the block would then have to write a user hint that no
	// server can check, see BlockContext.Pepper.
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
	// UserName is the name of the user the block belongs to. When it is not
	// empty the block embeds a user hint in the last
	// NonceSuffixLenForUserHint bytes of every wire nonce it writes, see
	// CheckUserFromHintV3.
	UserName string

	// Pepper is the user hint pepper of the user, see HintPepper. It is
	// required when UserName is not empty: the hint is derived from the pepper
	// and the user name, and a block that holds a user name without a pepper
	// cannot write a hint. The hint also depends on the credential shared by
	// the client and the server, so an attacker who does not hold that
	// credential cannot compute or verify a candidate hint.
	//
	// The caller must not modify the bytes of Pepper while the block is in use,
	// and must keep them alive for as long as the block is used: the block
	// keeps a reference to the slice, it does not copy it.
	Pepper []byte
}

// hintPepperUniqueValue separates the keyed user hint pepper from the uses of
// HashPassword that derive a credential, so the pepper of a user is a value of
// its own and never the credential of a user.
var hintPepperUniqueValue = version.ProtocolIdentifier() + " user hint pepper"

// HintPepper derives the HintPepperLen bytes pepper of the keyed user hint
// from a user name and the credential shared with the server. In shadowlemon
// that credential is HashPassword(rawPassword, userName), which is also the
// password the block cipher keys are derived from.
//
// The result is deterministic: it depends only on the arguments, never on the
// current time slot or on the cipher suite. A server can therefore precompute
// the pepper of its users and use it to check the hint of an incoming packet.
// An empty user name or an empty password returns nil; such a block must not
// write a user hint, see BlockContext.Pepper.
//
// Security: the pepper is derived from the shared credential, so an attacker
// who does not hold that credential cannot compute the hint of a user, nor
// tell whether a candidate hint belongs to a user. The pepper is not an
// authentication secret: whoever holds the credential can still compute hints,
// so a matching hint never authenticates a segment by itself, it only narrows
// down which credentials are worth an AEAD trial. A hint match must never be
// used as an access control check.
func HintPepper(userName, password string) []byte {
	if userName == "" || password == "" {
		return nil
	}
	hashed := HashPassword([]byte(password), []byte(hintPepperUniqueValue+userName))
	pepper := make([]byte, HintPepperLen)
	copy(pepper, hashed)
	return pepper
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
// with the supplied cipher suite and the default settings. The key is derived
// with KeyIterV3 PBKDF2 iterations.
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
// the next one, which covers a peer key slot offset of up to one refresh
// interval (KeyRefreshInterval, two minutes) in either direction.
//
// These three ciphers only cover the key derivation layer. Every data segment
// also carries a timestamp in its metadata, which is accepted only within ±1
// minute of the local clock, so a caller that implements the protocol end to
// end tolerates a peer clock offset of ±1 minute rather than two minutes.
//
// The keys are derived with KeyIterV3 PBKDF2 iterations.
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

// CheckUserFromHintV3 checks if the user is the one associated with the nonce,
// using the keyed user hint. pepper is the HintPepper of the user and name is
// the user name; at most the first HintPepperLen bytes of pepper are used. It
// is the counterpart of the hint that addUserHintToNonce writes, and it must be
// used for a nonce whose block had a non-empty BlockContext.Pepper.
//
// The user hint embedded in the nonce is only used to quickly filter candidate
// users before real authentication. It cannot be computed without the
// credential shared by the client and the server, so an attacker who only knows
// a user name cannot tell whether a hint belongs to that user. It is still not
// an authentication check: whoever holds the credential can compute a matching
// hint, so a match only narrows down the users worth an AEAD trial and must
// never grant access.
//
// It panics if the pepper or the user is empty, if the user is too long, or if
// the nonce is too short.
func CheckUserFromHintV3(pepper, name, nonce []byte) bool {
	if len(pepper) == 0 {
		panic("user hint pepper is empty")
	}
	if len(name) == 0 {
		panic("user is empty")
	}
	if len(name) > constant.MaxUserNameLen {
		panic(fmt.Sprintf("user name length %d exceeds maximum %d", len(name), constant.MaxUserNameLen))
	}
	if len(nonce) < NoncePrefixLenForUserHint+NonceSuffixLenForUserHint {
		panic(fmt.Sprintf("nonce length %d is too short", len(nonce)))
	}
	var input [HintPepperLen + constant.MaxUserNameLen + NoncePrefixLenForUserHint]byte
	n := copy(input[:], pepper)
	n += copy(input[n:], name)
	n += copy(input[n:], nonce[:NoncePrefixLenForUserHint])
	output := sha256.Sum256(input[:n])
	return bytes.Equal(output[:NonceSuffixLenForUserHint], nonce[len(nonce)-NonceSuffixLenForUserHint:])
}

// NewStatelessDecryptor builds a StatelessDecryptor for the given cipher
// suites and password, using the KeyIterV3 key derivation. An empty suite list
// means all the supported cipher suites. The password bytes are copied, so the
// caller can erase the input afterwards.
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
// of every configured cipher suite, with its prepended wire format nonce. The
// suites are tried in the configured order, and the first combination whose
// AEAD tag verifies wins. The returned BlockCipher exposes the cipher suite
// that authenticated the ciphertext through Suite(), and it is the cipher that
// authenticated it, so it can be used to protect the response to that
// ciphertext.
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
	// slots of a suite are tried by selectDecryptStateless. The first suite
	// that authenticates the ciphertext wins.
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
