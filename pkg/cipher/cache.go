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

// Cache sizing.
//
// A cached entry holds the three time slot ciphers of one (password, cipher
// suite, key iteration variant) triple, and a server user occupies one entry
// per cipher suite and per key derivation variant it must accept: with the
// default suite list and the compatibility variant that is len(suites) * 2 = 6
// entries per user per key epoch.
//
// The capacity is deliberately large because a cache miss is expensive: the
// envelope key is derived with KeyIterV3 (4096 PBKDF2 iterations) instead of
// the legacy 64, for every suite and every time slot, which costs milliseconds
// of CPU per miss. A server that evicts the entries of its live users pays that
// cost again for every packet it receives from them, so a few MB to a few tens
// of MB of cached AEAD state is cheap compared to the PBKDF2 work it avoids.
const (
	cacheValidInterval    = KeyRefreshInterval / 4
	cacheValidMaxJitterMs = 5000

	// maxCacheSize is the maximum number of (password, cipher suite, key
	// iteration variant) entries kept in blockCipherCache.
	//
	// Each user occupies at most len(suites) * 2 entries per key epoch, one per
	// cipher suite and per key derivation variant accepted, so 8192 entries
	// hold the current epoch of about 1300 users with the default suite list.
	// The memory of a full cache is the AEAD state of three time slot ciphers
	// per entry, a few MB to a few tens of MB depending on the cipher suites in
	// use.
	//
	// Once the limit is reached the oldest entries are evicted, preferring the
	// entries of a retired key epoch, see storeCachedCiphers. Evicting a live
	// entry is not a correctness problem, because the same (password, suite,
	// iter, epoch) derives the same cipher blocks again, but it makes the next
	// packet of that user pay the full key derivation, see the note above.
	maxCacheSize = 8192
)

type cachedCiphers struct {
	cipherList []*aeadBlockCipher
	createTime time.Time
	epoch      int64
}

// cipherCacheKey identifies a cached cipher list. The key contains the cipher
// suite, the PBKDF2 iteration variant as well as the password, so that the
// same password used with different cipher suites or derived with a different
// iteration count generates independent cipher lists.
type cipherCacheKey struct {
	password string
	suite    Suite
	iter     int
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
// suite, derived from the password with iter PBKDF2 iterations. Stateless
// results are immutable cache templates and must never be consumed directly.
// Stateful results are mutable clones.
func getBlockCipherList(password string, suite Suite, stateless bool, iter int) ([]*aeadBlockCipher, error) {
	entry, err := getCachedCiphers(password, suite, time.Now(), iter)
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

func getCachedCiphers(password string, suite Suite, now time.Time, iter int) (*cachedCiphers, error) {
	// Try to find []BlockCipher from cache.
	key := cipherCacheKey{password: password, suite: suite, iter: iter}
	epoch := cipherKeyEpoch(now)
	if entry, ok := loadCachedCiphers(key); ok {
		// Check if the cached entry is expired.
		jitter := time.Duration(mrand.IntN(cacheValidMaxJitterMs)) * time.Millisecond
		if entry.epoch == epoch && !entry.createTime.Add(cacheValidInterval-jitter).Before(now) {
			return entry, nil
		}
	}

	// If not found, generate the stateless []BlockCipher.
	blockCiphers, err := newBlockCipherList([]byte(password), suite, now, iter)
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
//
// Eviction prefers entries whose key epoch is not entry.epoch. Those entries
// belong to a retired epoch: they are only useful to a peer whose clock still
// rounds to that epoch when it starts a session, while the entries of the
// current epoch are the ones that keep a running server from re-deriving keys.
// Only when every remaining entry belongs to the current epoch does the
// function evict the oldest of them anyway, which keeps the cache bounded
// without ever widening the accepted clock skew.
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
			// key epoch, so the same (password, suite, iter, epoch) generates
			// the same cipher blocks again when it is requested later.
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
// oldest cached entry, which is the entry that has been in the cache for the
// longest time. When otherEpochOnly is true, only entries whose key epoch is
// different from the given epoch are considered. It returns -1 if no entry
// satisfies the condition.
//
// The scan is linear in the number of cached entries and it runs while
// blockCipherCacheMu is held. It is only reached when the cache is at
// maxCacheSize, and the work it does is negligible next to the key derivation
// that a miss triggers, see the note on maxCacheSize.
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
// suite from the password, using iter PBKDF2 iterations. The key material is
// always DefaultKeyLen (32) bytes long, and the cipher suite key is its prefix
// of suite.KeyLen() bytes.
func newBlockCipherList(password []byte, suite Suite, now time.Time, iter int) ([]*aeadBlockCipher, error) {
	salts := saltFromTime(now)
	blockCiphers := make([]*aeadBlockCipher, 0, 3)
	for i := range 3 {
		keygen := pbkdf2Gen{
			Salt: salts[i],
			Iter: iter,
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
