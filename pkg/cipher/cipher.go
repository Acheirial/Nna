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
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/proto"
)

var (
	_ BlockCipher = &aeadBlockCipher{}

	errCiphertextTooShort  = errors.New("ciphertext is smaller than nonce size")
	errDestinationTooSmall = errors.New("destination capacity is too small")
)

// aeadBlockCipher implements BlockCipher interface with one AEAD algorithm.
type aeadBlockCipher struct {
	aead cipher.AEAD
	// suite is immutable after the cipher is created.
	suite               Suite
	key                 [DefaultKeyLen]byte
	enableImplicitNonce bool
	implicitNonce       []byte
	mu                  sync.Mutex
	ctx                 BlockContext
	noncePattern        *appctlpb.NoncePattern
	noncePatternApplied bool
	// payloadNonceBuf is the scratch buffer filled by payloadNonceInto(). It
	// avoids a heap allocation of the derived nonce on every payload
	// encryption and decryption. It is guarded by mu.
	payloadNonceBuf []byte
}

// newBlockCipher creates a new AEAD block cipher with the supplied suite and key.
// At least suite.KeyLen() key bytes must be provided, and only the first
// suite.KeyLen() bytes are used.
func newBlockCipher(suite Suite, key []byte) (*aeadBlockCipher, error) {
	keyLen := suite.KeyLen()
	if keyLen == 0 {
		return nil, fmt.Errorf("invalid cipher suite %d", uint8(suite))
	}
	if len(key) < keyLen {
		return nil, fmt.Errorf("%s key length is %d bytes, want %d bytes", suite, len(key), keyLen)
	}

	var ownedKey [DefaultKeyLen]byte
	copy(ownedKey[:], key[:keyLen])
	var aead cipher.AEAD
	var err error
	switch suite {
	case SuiteXChaCha20Poly1305:
		aead, err = chacha20poly1305.NewX(ownedKey[:keyLen])
	case SuiteAES256GCM, SuiteAES128GCM:
		aead, err = newAESGCM(ownedKey[:keyLen])
	}
	if err != nil {
		return nil, fmt.Errorf("create %s cipher failed: %w", suite, err)
	}

	return &aeadBlockCipher{
		aead:                aead,
		suite:               suite,
		enableImplicitNonce: false,
		key:                 ownedKey,
		implicitNonce:       nil,
		payloadNonceBuf:     make([]byte, DefaultNonceSize),
	}, nil
}

// newAESGCM creates an AES-GCM AEAD with the supplied key. The key length
// selects AES-128 or AES-256. The AEAD nonce is 12 bytes and the tag is 16
// bytes long.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher() failed: %w", err)
	}
	aead, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM() failed: %w", err)
	}
	return aead, nil
}

// newXChaCha20Poly1305BlockCipher creates a new XChaCha20-Poly1305 cipher with the supplied key.
func newXChaCha20Poly1305BlockCipher(key []byte) (*aeadBlockCipher, error) {
	return newBlockCipher(SuiteXChaCha20Poly1305, key)
}

// NonceSize returns the size of the wire format nonce that must be passed to
// the Encrypt and Decrypt methods. It is DefaultNonceSize for every cipher
// suite: the wire format always carries a 24 bytes nonce, and the AEAD nonce
// is derived from it by aeadNonce().
func (c *aeadBlockCipher) NonceSize() int {
	return DefaultNonceSize
}

// aeadNonce derives the AEAD nonce from the wire format nonce. See the "AEAD
// nonce derivation" comment in suite.go for the rationale of taking the last
// bytes of the wire format nonce.
func (c *aeadBlockCipher) aeadNonce(wireNonce []byte) []byte {
	return wireNonce[len(wireNonce)-c.aead.NonceSize():]
}

// Suite returns the cipher suite of the block cipher. The suite is immutable,
// so it doesn't need to be synchronized.
func (c *aeadBlockCipher) Suite() Suite {
	return c.suite
}

func (c *aeadBlockCipher) Overhead() int {
	return c.aead.Overhead()
}

func (c *aeadBlockCipher) Encrypt(dst, plaintext []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	var wireNonce []byte
	var err error
	needSendNonce := !c.enableImplicitNonce || len(c.implicitNonce) == 0
	resultLen := len(plaintext) + c.aead.Overhead()
	if needSendNonce {
		resultLen += DefaultNonceSize
	}
	if cap(dst)-len(dst) < resultLen {
		return errDestinationTooSmall
	}
	if c.enableImplicitNonce {
		if len(c.implicitNonce) == 0 {
			c.implicitNonce, err = c.newNonce()
			if err != nil {
				return fmt.Errorf("newNonce() failed: %w", err)
			}
			c.implicitNonce = c.addUserHintToNonce(c.implicitNonce)
		} else {
			c.increaseNonce()
		}
		wireNonce = c.implicitNonce
	} else {
		start := len(dst)
		dst = dst[:start+DefaultNonceSize]
		wireNonce = dst[start:]
		if err = c.newNonceTo(wireNonce); err != nil {
			return fmt.Errorf("newNonceTo() failed: %w", err)
		}
		wireNonce = c.addUserHintToNonce(wireNonce)
	}

	if needSendNonce {
		if c.enableImplicitNonce {
			dst = append(dst, wireNonce...)
		}
	}
	c.aead.Seal(dst, c.aeadNonce(wireNonce), plaintext, nil)
	return nil
}

func (c *aeadBlockCipher) EncryptWithNonce(dst, nonce, plaintext []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enableImplicitNonce {
		return fmt.Errorf("EncryptWithNonce() is not supported when implicit nonce is enabled")
	}
	if len(nonce) != c.NonceSize() {
		return fmt.Errorf("want nonce size %d, got %d", c.NonceSize(), len(nonce))
	}
	if cap(dst)-len(dst) < len(plaintext)+c.aead.Overhead() {
		return errDestinationTooSmall
	}
	c.aead.Seal(dst, c.aeadNonce(nonce), plaintext, nil)
	return nil
}

func (c *aeadBlockCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var wireNonce []byte
	if c.enableImplicitNonce {
		if len(c.implicitNonce) == 0 {
			if len(ciphertext) < DefaultNonceSize {
				return nil, errCiphertextTooShort
			}
			c.implicitNonce = make([]byte, DefaultNonceSize)
			copy(c.implicitNonce, ciphertext[:DefaultNonceSize])
			ciphertext = ciphertext[DefaultNonceSize:]
		} else {
			c.increaseNonce()
		}
		wireNonce = c.implicitNonce
	} else {
		if len(ciphertext) < DefaultNonceSize {
			return nil, errCiphertextTooShort
		}
		wireNonce = ciphertext[:DefaultNonceSize]
		ciphertext = ciphertext[DefaultNonceSize:]
	}

	plaintext, err := c.aead.Open(nil, c.aeadNonce(wireNonce), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cipher.AEAD.Open() failed: %w", err)
	}
	return plaintext, nil
}

func (c *aeadBlockCipher) DecryptWithNonce(ciphertext, nonce []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enableImplicitNonce {
		return nil, fmt.Errorf("DecryptWithNonce() is not supported when implicit nonce is enabled")
	}
	if len(nonce) != c.NonceSize() {
		return nil, fmt.Errorf("want nonce size %d, got %d", c.NonceSize(), len(nonce))
	}
	plaintext, err := c.aead.Open(nil, c.aeadNonce(nonce), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cipher.AEAD.Open() failed: %w", err)
	}
	return plaintext, nil
}

const (
	// payloadNonceOffset is the index of the nonce byte changed to derive the
	// payload nonce from the message nonce.
	//
	// The user hint occupies the last 4 nonce bytes, and the nonce pattern
	// rewrites at most the first maxNoncePatternLen (12) nonce bytes, so byte 16
	// belongs to neither of them.
	//
	// The offset must also fall into the AEAD nonce of every cipher suite. The
	// smallest AEAD nonce is the minAEADNonceLen (12) bytes AES-GCM nonce,
	// which covers the nonce bytes [12, 24), so flipping byte 16 changes the
	// AEAD nonce of the payload but not the AEAD nonce of the metadata. This
	// keeps the metadata and the payload of a message separated for AES-GCM as
	// well.
	payloadNonceOffset = 16
	// payloadNonceMask is XORed with the byte at payloadNonceOffset. Any non
	// zero value works, it only needs to guarantee that the derived nonce is
	// different from the message nonce.
	payloadNonceMask = 0x01
)

// payloadNonce returns a copy of the wire format nonce used to encrypt or
// decrypt the payload of a message, derived from the wire format nonce used to
// encrypt or decrypt its metadata. See payloadNonceInto() for the derivation
// rule.
//
// Production code uses payloadNonceInto(), which writes into a reusable
// scratch buffer instead of allocating. This package level entry point is kept
// for callers that need a nonce copy independent of any cipher instance.
func payloadNonce(nonce []byte) []byte {
	derived := make([]byte, len(nonce))
	copy(derived, nonce)
	applyPayloadNonceMask(derived)
	return derived
}

// applyPayloadNonceMask XORs the byte at payloadNonceOffset of derived with
// payloadNonceMask, in place.
func applyPayloadNonceMask(derived []byte) {
	derived[payloadNonceOffset] ^= payloadNonceMask
}

// payloadNonceInto derives the wire format nonce used to encrypt or decrypt the
// payload of a message from the wire format nonce used to encrypt or decrypt
// its metadata, and stores the result in the receiver scratch buffer. The AEAD
// nonce is then derived from it by aeadNonce(), so the metadata and the payload
// of the same message never share an AEAD nonce.
//
// The derived nonce has the same length as nonce. The returned slice aliases
// the receiver scratch buffer, therefore it is only valid while c.mu is held
// and only until the next call of this method on the same cipher: the caller
// must pass it to Seal or Open inside the same critical section, and must never
// retain it or share it with another goroutine.
func (c *aeadBlockCipher) payloadNonceInto(nonce []byte) []byte {
	if cap(c.payloadNonceBuf) < len(nonce) {
		c.payloadNonceBuf = make([]byte, len(nonce))
	}
	derived := c.payloadNonceBuf[:len(nonce)]
	copy(derived, nonce)
	applyPayloadNonceMask(derived)
	return derived
}

func (c *aeadBlockCipher) EncryptPayloadWithNonce(dst, nonce, plaintext []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enableImplicitNonce {
		return fmt.Errorf("EncryptPayloadWithNonce() is not supported when implicit nonce is enabled")
	}
	if len(nonce) != c.NonceSize() {
		return fmt.Errorf("want nonce size %d, got %d", c.NonceSize(), len(nonce))
	}
	if cap(dst)-len(dst) < len(plaintext)+c.aead.Overhead() {
		return errDestinationTooSmall
	}
	c.aead.Seal(dst, c.aeadNonce(c.payloadNonceInto(nonce)), plaintext, nil)
	return nil
}

func (c *aeadBlockCipher) DecryptPayloadWithNonce(ciphertext, nonce []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enableImplicitNonce {
		return nil, fmt.Errorf("DecryptPayloadWithNonce() is not supported when implicit nonce is enabled")
	}
	if len(nonce) != c.NonceSize() {
		return nil, fmt.Errorf("want nonce size %d, got %d", c.NonceSize(), len(nonce))
	}
	plaintext, err := c.aead.Open(nil, c.aeadNonce(c.payloadNonceInto(nonce)), ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("cipher.AEAD.Open() failed: %w", err)
	}
	return plaintext, nil
}

func (c *aeadBlockCipher) DecryptStatelessTo(ciphertext, dst []byte) ([]byte, error) {
	if len(ciphertext) < DefaultNonceSize {
		return nil, errCiphertextTooShort
	}
	return c.aead.Open(dst, c.aeadNonce(ciphertext[:DefaultNonceSize]), ciphertext[DefaultNonceSize:], nil)
}

func (c *aeadBlockCipher) Clone() BlockCipher {
	c.mu.Lock()
	defer c.mu.Unlock()

	newCipher, err := newBlockCipher(c.suite, c.key[:c.suite.KeyLen()])
	if err != nil {
		panic(err)
	}

	newCipher.enableImplicitNonce = c.enableImplicitNonce
	if len(c.implicitNonce) != 0 {
		newCipher.implicitNonce = make([]byte, len(c.implicitNonce))
		copy(newCipher.implicitNonce, c.implicitNonce)
	}
	newCipher.ctx = c.ctx
	newCipher.noncePattern = proto.Clone(c.noncePattern).(*appctlpb.NoncePattern)
	return newCipher
}

func (c *aeadBlockCipher) CloneStatelessFast() BlockCipher {
	return c.cloneStatelessFast()
}

func (c *aeadBlockCipher) SetImplicitNonceMode(enable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enableImplicitNonce = enable
	if !enable {
		c.implicitNonce = nil
	}
}

func (c *aeadBlockCipher) IsStateless() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.enableImplicitNonce
}

func (c *aeadBlockCipher) BlockContext() BlockContext {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ctx
}

func (c *aeadBlockCipher) SetBlockContext(bc BlockContext) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ctx = bc
}

func (c *aeadBlockCipher) NoncePattern() *appctlpb.NoncePattern {
	c.mu.Lock()
	defer c.mu.Unlock()
	return proto.Clone(c.noncePattern).(*appctlpb.NoncePattern)
}

func (c *aeadBlockCipher) SetNoncePattern(pattern *appctlpb.NoncePattern) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noncePattern = proto.Clone(pattern).(*appctlpb.NoncePattern)
}

// newNonce generates a new nonce.
func (c *aeadBlockCipher) newNonce() ([]byte, error) {
	nonce := make([]byte, c.NonceSize())
	if err := c.newNonceTo(nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}

func (c *aeadBlockCipher) newNonceTo(nonce []byte) error {
	if len(nonce) < c.NonceSize() {
		return errDestinationTooSmall
	}
	nonce = nonce[:c.NonceSize()]
	if _, err := crand.Read(nonce); err != nil {
		return err
	}

	if c.noncePattern == nil {
		return nil
	}

	// For UDP (stateless) cipher, if the pattern was already applied
	// and applyToAllUDPPacket is false, don't change the nonce.
	if !c.enableImplicitNonce && c.noncePatternApplied && !c.noncePattern.GetApplyToAllUDPPacket() {
		return nil
	}

	switch c.noncePattern.GetType() {
	case appctlpb.NonceType_NONCE_TYPE_RANDOM:
		// No change to the nonce.
	case appctlpb.NonceType_NONCE_TYPE_PRINTABLE:
		rewriteLen := c.nonceRewriteLen()
		common.ToPrintableChar(nonce, 0, rewriteLen)
	case appctlpb.NonceType_NONCE_TYPE_PRINTABLE_SUBSET:
		rewriteLen := c.nonceRewriteLen()
		common.ToCommon64Set(nonce, 0, rewriteLen)
	case appctlpb.NonceType_NONCE_TYPE_FIXED:
		hexStrings := c.noncePattern.GetCustomHexStrings()
		if len(hexStrings) > 0 {
			idx := mrand.IntN(len(hexStrings))
			prefix, err := hex.DecodeString(hexStrings[idx])
			if err == nil {
				copyLen := len(prefix)
				// The pattern must never rewrite the bytes of the wire nonce
				// that AES-GCM uses as its AEAD nonce, see maxNoncePatternLen.
				if copyLen > maxNoncePatternLen {
					copyLen = maxNoncePatternLen
				}
				copy(nonce[:copyLen], prefix[:copyLen])
			} else {
				panic(fmt.Errorf("fail to decode hex string: %w", err))
			}
		}
		// If no hex strings are provided, use plain random nonce.
	}

	c.noncePatternApplied = true
	return nil
}

// nonceRewriteLen returns a random length in [minLen, maxLen] clamped to
// maxNoncePatternLen. The clamp keeps the nonce pattern away from the bytes
// that AES-GCM uses as its AEAD nonce, see maxNoncePatternLen.
func (c *aeadBlockCipher) nonceRewriteLen() int {
	minLen := int(c.noncePattern.GetMinLen())
	maxLen := int(c.noncePattern.GetMaxLen())
	if maxLen > maxNoncePatternLen {
		maxLen = maxNoncePatternLen
	}
	if minLen > maxLen {
		minLen = maxLen
	}
	if minLen == maxLen {
		return minLen
	}
	rangeSize := mrand.IntN(maxLen - minLen + 1)
	return minLen + rangeSize
}

func (c *aeadBlockCipher) increaseNonce() {
	if !c.enableImplicitNonce || len(c.implicitNonce) == 0 {
		panic("implicit nonce mode is not enabled")
	}
	for i := range c.implicitNonce {
		j := len(c.implicitNonce) - 1 - i
		c.implicitNonce[j] += 1
		if c.implicitNonce[j] != 0 {
			break
		}
	}
}

func (c *aeadBlockCipher) cloneStatelessFast() *aeadBlockCipher {
	return &aeadBlockCipher{
		aead:  c.aead,
		suite: c.suite,
		key:   c.key,
	}
}

// addUserHintToNonce embeds the user hint of the block context into the last
// NonceSuffixLenForUserHint bytes of the wire nonce, in place, and returns the
// nonce. The length and the position of the hint are the same whatever hint is
// written, only the 4 bytes at the end of the nonce change.
//
// When the block context has no pepper, this writes the legacy hint of
// protocol v2, which is derived from the user name only and therefore
// computable by anyone who knows that name; it is the same value that
// CheckUserFromHint recomputes. When the block context has a pepper, this
// writes the keyed hint of protocol v3, which also depends on the credential
// shared by the client and the server; it is the same value that
// CheckUserFromHintV3 recomputes. Both derivations are the same computation,
// sha256(pepper ‖ user name ‖ nonce prefix), so a keyed hint can never collide
// with the legacy hint of the same user for the same nonce.
func (c *aeadBlockCipher) addUserHintToNonce(nonce []byte) []byte {
	if c.ctx.UserName == "" {
		return nonce
	}
	if len(c.ctx.UserName) > constant.MaxUserNameLen {
		panic(fmt.Sprintf("user name length %d exceeds maximum %d", len(c.ctx.UserName), constant.MaxUserNameLen))
	}
	if len(nonce) < NoncePrefixLenForUserHint+NonceSuffixLenForUserHint {
		panic(fmt.Sprintf("nonce length %d is too short", len(nonce)))
	}
	var input [HintPepperLen + constant.MaxUserNameLen + NoncePrefixLenForUserHint]byte
	n := copy(input[:], c.ctx.Pepper)
	n += copy(input[n:], c.ctx.UserName)
	n += copy(input[n:], nonce[:NoncePrefixLenForUserHint])
	output := sha256.Sum256(input[:n])
	copy(nonce[len(nonce)-NonceSuffixLenForUserHint:], output[:NonceSuffixLenForUserHint])
	return nonce
}

func selectDecryptStateless(ciphertext, dst []byte, blocks []*aeadBlockCipher) (*aeadBlockCipher, []byte, error) {
	if dst == nil && len(ciphertext) >= DefaultNonceSize+DefaultOverhead {
		dst = make([]byte, 0, len(ciphertext)-DefaultNonceSize-DefaultOverhead)
	}
	for _, block := range blocks {
		decrypted, err := block.DecryptStatelessTo(ciphertext, dst)
		if err != nil {
			continue
		}
		return block, decrypted, nil
	}
	return nil, nil, errUnableToDecrypt
}
