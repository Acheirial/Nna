// Copyright (C) 2022  mieru authors
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
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"time"
)

const (
	cacheValidInterval    = KeyRefreshInterval / 4
	cacheValidMaxJitterMs = 5000

	// maxCacheSize is the maximum number of password entries kept in
	// blockCipherCache. Once the limit is reached, the oldest entries are
	// evicted, preferring entries that don't belong to the current key epoch.
	maxCacheSize = 256
)

type cachedCiphers struct {
	cipherList []*aeadBlockCipher
	createTime time.Time
	epoch      int64
}

// cipherCacheKey identifies a cached cipher list. The key contains the cipher
// suite as well as the password, so that the same password used with different
// cipher suites generates independent cipher lists.
type cipherCacheKey struct {
	password string
	suite    Suite
}

var (
	// blockCipherCacheMu guards blockCipherCache and blockCipherCacheQueue.
	blockCipherCacheMu sync.RWMutex
	// blockCipherCache maps a password and a cipher suite to the cached
	// stateless block ciphers of that suite.
	blockCipherCache = make(map[cipherCacheKey]*cachedCiphers)
	// blockCipherCacheQueue records the insertion order of the keys in
	// blockCipherCache, oldest first.
	blockCipherCacheQueue []cipherCacheKey
)

var errUnableToDecrypt = errors.New("unable to decrypt from supplied cipher blocks")

// getBlockCipherList returns three AEAD block ciphers of the given cipher
// suite. Stateless results are immutable cache templates and must never be
// consumed directly. Stateful results are mutable clones.
func getBlockCipherList(password string, suite Suite, stateless bool) ([]*aeadBlockCipher, error) {
	entry, err := getCachedCiphers(password, suite, time.Now())
	if err != nil {
		return nil, err
	}
	blocks := make([]*aeadBlockCipher, len(entry.cipherList))
	for i, block := range entry.cipherList {
		if stateless {
			blocks[i] = block
		} else {
			blocks[i] = block.cloneStatelessFast()
			blocks[i].SetImplicitNonceMode(true)
		}
	}
	return blocks, nil
}

func getCachedCiphers(password string, suite Suite, now time.Time) (*cachedCiphers, error) {
	// Try to find []BlockCipher from cache.
	key := cipherCacheKey{password: password, suite: suite}
	epoch := cipherKeyEpoch(now)
	if entry, ok := loadCachedCiphers(key); ok {
		// Check if the cached entry is expired.
		jitter := time.Duration(mrand.IntN(cacheValidMaxJitterMs)) * time.Millisecond
		if entry.epoch == epoch && !entry.createTime.Add(cacheValidInterval-jitter).Before(now) {
			return entry, nil
		}
	}

	// If not found, generate the stateless []BlockCipher.
	blockCiphers, err := newBlockCipherList([]byte(password), suite, now)
	if err != nil {
		return nil, fmt.Errorf("newBlockCipherList() failed: %v", err)
	}

	// Insert to cache.
	entry := &cachedCiphers{
		cipherList: blockCiphers,
		createTime: now,
		epoch:      epoch,
	}
	storeCachedCiphers(key, entry)
	return entry, nil
}

// loadCachedCiphers returns the cached entry of the key if it exists.
func loadCachedCiphers(key cipherCacheKey) (*cachedCiphers, bool) {
	blockCipherCacheMu.RLock()
	defer blockCipherCacheMu.RUnlock()
	entry, ok := blockCipherCache[key]
	return entry, ok
}

// storeCachedCiphers inserts entry into blockCipherCache, then evicts the
// oldest entries until the cache size is within maxCacheSize.
func storeCachedCiphers(key cipherCacheKey, entry *cachedCiphers) {
	blockCipherCacheMu.Lock()
	defer blockCipherCacheMu.Unlock()
	if _, ok := blockCipherCache[key]; !ok {
		blockCipherCacheQueue = append(blockCipherCacheQueue, key)
	}
	blockCipherCache[key] = entry
	for len(blockCipherCache) > maxCacheSize {
		idx := oldestCachedIndexLocked(entry.epoch, true)
		if idx < 0 {
			// Every remaining entry belongs to the current key epoch. Evict
			// the oldest one anyway to keep the cache bounded. This doesn't
			// lose correctness: the salts only depend on the password and the
			// key epoch, so the same (password, suite, epoch) generates the
			// same cipher blocks again when it is requested later.
			idx = oldestCachedIndexLocked(entry.epoch, false)
		}
		if idx < 0 {
			return
		}
		delete(blockCipherCache, blockCipherCacheQueue[idx])
		blockCipherCacheQueue = append(blockCipherCacheQueue[:idx], blockCipherCacheQueue[idx+1:]...)
	}
}

// oldestCachedIndexLocked returns the index in blockCipherCacheQueue of the
// oldest cached entry. When otherEpochOnly is true, only entries whose key
// epoch is different from the given epoch are considered. It returns -1 if no
// entry satisfies the condition.
// Caller must hold blockCipherCacheMu.
func oldestCachedIndexLocked(epoch int64, otherEpochOnly bool) int {
	for i, key := range blockCipherCacheQueue {
		entry, ok := blockCipherCache[key]
		if !ok {
			continue
		}
		if !otherEpochOnly || entry.epoch != epoch {
			return i
		}
	}
	return -1
}

// newBlockCipherList generates the three time slot block ciphers of a cipher
// suite from the password. The key material is always DefaultKeyLen (32) bytes
// long, and the cipher suite key is its prefix of suite.KeyLen() bytes.
func newBlockCipherList(password []byte, suite Suite, now time.Time) ([]*aeadBlockCipher, error) {
	salts := saltFromTime(now)
	blockCiphers := make([]*aeadBlockCipher, 0, 3)
	for i := range 3 {
		keygen := pbkdf2Gen{
			Salt: salts[i],
			Iter: KeyIter,
		}
		cipherKey, err := keygen.NewKey(password, DefaultKeyLen)
		if err != nil {
			return nil, fmt.Errorf("NewKey() failed: %w", err)
		}
		blockCipher, err := newBlockCipher(suite, cipherKey)
		if err != nil {
			return nil, fmt.Errorf("newBlockCipher() failed: %w", err)
		}
		blockCiphers = append(blockCiphers, blockCipher)
	}
	return blockCiphers, nil
}
