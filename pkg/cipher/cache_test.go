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
	"bytes"
	"fmt"
	"testing"
	"time"
)

// The synthetic entries of the capacity tests use two key epochs that only have
// to be different from each other: the epoch stored in an entry is compared
// against the epoch of the entry that triggers an eviction, never against the
// wall clock.
const (
	cacheTestCurrentEpoch = 2_000_000
	cacheTestRetiredEpoch = cacheTestCurrentEpoch - 120
)

// withCacheRestored runs fn with an empty block cipher cache and puts the
// previous content of the cache back when the test ends, so that a test can
// fill and overflow the cache without disturbing the other tests of the
// package.
func withCacheRestored(t *testing.T, fn func()) {
	t.Helper()
	blockCipherCacheMu.Lock()
	oldCache, oldQueue := blockCipherCache, blockCipherCacheQueue
	blockCipherCache = make(map[cipherCacheKey]*cachedCiphers)
	blockCipherCacheQueue = nil
	blockCipherCacheMu.Unlock()
	t.Cleanup(func() {
		blockCipherCacheMu.Lock()
		blockCipherCache, blockCipherCacheQueue = oldCache, oldQueue
		blockCipherCacheMu.Unlock()
	})
	fn()
}

// fillTestCache inserts count synthetic entries of the given key epoch,
// oldest first, and returns the keys in insertion order. It writes the cache
// directly to keep the test independent of the key derivation, and it varies
// the cipher suite of the keys so that a filled cache looks like the cache of a
// multi user server.
func fillTestCache(t *testing.T, count int, epoch int64) []cipherCacheKey {
	t.Helper()
	suites := AllSuites()
	keys := make([]cipherCacheKey, 0, count)
	blockCipherCacheMu.Lock()
	defer blockCipherCacheMu.Unlock()
	for i := range count {
		key := cipherCacheKey{
			password: fmt.Sprintf("synthetic-password-%d", i),
			suite:    suites[i%len(suites)],
		}
		if _, ok := blockCipherCache[key]; ok {
			t.Fatalf("synthetic key %d is not unique", i)
		}
		blockCipherCache[key] = &cachedCiphers{epoch: epoch}
		blockCipherCacheQueue = append(blockCipherCacheQueue, key)
		keys = append(keys, key)
	}
	return keys
}

// cacheLen returns the number of entries in the block cipher cache.
func cacheLen() int {
	blockCipherCacheMu.RLock()
	defer blockCipherCacheMu.RUnlock()
	return len(blockCipherCache)
}

// cacheTestKey builds a distinct key of the current key epoch.
func cacheTestKey(i int) cipherCacheKey {
	suites := AllSuites()
	return cipherCacheKey{
		password: fmt.Sprintf("current-epoch-password-%d", i),
		suite:    suites[i%len(suites)],
	}
}

func TestGetBlockCipherList(t *testing.T) {
	password := string([]byte{0x00, 0xff, 0x08, 0x09, 0x06, 0x04})
	ciphers, err := getBlockCipherList(password, SuiteXChaCha20Poly1305, true)
	if err != nil {
		t.Fatalf("getBlockCipherList() failed: %v", err)
	}
	if len(ciphers) != 3 {
		t.Fatalf("number of ciphers = %d, want %d", len(ciphers), 3)
	}
	for _, cipher := range ciphers {
		if !cipher.IsStateless() {
			t.Errorf("IsStateless() = %v, want %v", cipher.IsStateless(), true)
		}
	}

	ciphers, err = getBlockCipherList(password, SuiteXChaCha20Poly1305, false)
	if err != nil {
		t.Fatalf("getBlockCipherList() failed: %v", err)
	}
	if len(ciphers) != 3 {
		t.Fatalf("number of ciphers = %d, want %d", len(ciphers), 3)
	}
	for _, cipher := range ciphers {
		if cipher.IsStateless() {
			t.Errorf("IsStateless() = %v, want %v", cipher.IsStateless(), false)
		}
	}
}

func TestGetCachedCiphersKeyedBySuite(t *testing.T) {
	password := string([]byte{0x11, 0x22, 0x33})
	now := time.Now()
	first, err := getCachedCiphers(password, SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	// The same password and cipher suite must hit the same cache entry.
	again, err := getCachedCiphers(password, SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	if first != again {
		t.Errorf("getCachedCiphers() returned a different entry for the same password and suite")
	}
	// A different cipher suite must use a different cache entry.
	//
	// The key material of a suite is the prefix of the PBKDF2 output (see the
	// frozen design), so suites with the same KeyLen() hold identical key bytes
	// by design, and the suite itself is the only thing that separates their
	// ciphertexts. What must be verified here is the suite of the cached cipher
	// and that newBlockCipher() retained only suite.KeyLen() bytes of the
	// PBKDF2 output.
	for _, suite := range []Suite{SuiteAES256GCM, SuiteAES128GCM} {
		other, err := getCachedCiphers(password, suite, now)
		if err != nil {
			t.Fatalf("getCachedCiphers(%s) failed: %v", suite, err)
		}
		if other == first {
			t.Errorf("getCachedCiphers(%s) returned the entry of %s", suite, SuiteXChaCha20Poly1305)
		}
		if got := other.cipherList[1].Suite(); got != suite {
			t.Errorf("cached cipher suite = %s, want %s", got, suite)
		}
		// XChaCha20-Poly1305 uses the whole DefaultKeyLen (32) bytes PBKDF2
		// output as its key, so the key of any other suite must be its prefix.
		keyLen := suite.KeyLen()
		if !bytes.Equal(other.cipherList[1].key[:keyLen], first.cipherList[1].key[:keyLen]) {
			t.Errorf("getCachedCiphers(%s) key is not the PBKDF2 key prefix of %s", suite, SuiteXChaCha20Poly1305)
		}
		for i := keyLen; i < DefaultKeyLen; i++ {
			if other.cipherList[1].key[i] != 0 {
				t.Errorf("getCachedCiphers(%s) retained key byte %d = %d, want 0", suite, i, other.cipherList[1].key[i])
			}
		}
	}
	// A different password must use a different cache entry.
	otherPassword, err := getCachedCiphers(password+"x", SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	if otherPassword == first {
		t.Errorf("getCachedCiphers() returned the same entry for different passwords")
	}
}

// TestCacheCapacityModel checks that the cache can hold the discovery material
// of a multi user server: a user occupies one entry per cipher suite, so
// thousands of distinct (password, suite) entries must coexist without
// shadowing each other, and the documented capacity of the cache must stay in
// reach of a server with about 2700 users.
func TestCacheCapacityModel(t *testing.T) {
	withCacheRestored(t, func() {
		// 3000 entries: about 1000 users of the default suite list.
		const entries = 3000
		keys := fillTestCache(t, entries, cacheTestCurrentEpoch)
		if got := cacheLen(); got != entries {
			t.Fatalf("cache size = %d, want %d", got, entries)
		}
		for _, key := range keys {
			entry, ok := loadCachedCiphers(key)
			if !ok || entry.epoch != cacheTestCurrentEpoch {
				t.Fatalf("cached entry of %q is missing or has the wrong epoch", key.password)
			}
		}

		// The capacity model documented on maxCacheSize: a user of the default
		// suite list occupies len(suites) entries per key epoch, and the cache
		// must cover at least 2700 such users, because a miss now costs
		// KeyIterV3 key derivations.
		const documentedUsers = 2700
		entriesPerUser := len(AllSuites())
		if got := maxCacheSize / entriesPerUser; got < documentedUsers {
			t.Fatalf("maxCacheSize %d holds %d users at %d entries per user, want at least %d users", maxCacheSize, got, entriesPerUser, documentedUsers)
		}
	})
}

// TestCacheEvictionPrefersRetiredEpoch checks that a full cache drops the
// entries of a retired key epoch before the entries of the current one: the
// entries of the current epoch are the ones that keep a running server from
// re-deriving the keys of its live users.
func TestCacheEvictionPrefersRetiredEpoch(t *testing.T) {
	withCacheRestored(t, func() {
		retired := fillTestCache(t, maxCacheSize, cacheTestRetiredEpoch)
		// The filled entries differ in every component of the cache key: the
		// password and the cipher suite.
		suites := make(map[Suite]struct{})
		for _, key := range retired {
			suites[key.suite] = struct{}{}
		}
		if want := len(AllSuites()); len(suites) != want {
			t.Fatalf("filled cache covers %d cipher suites, want %d", len(suites), want)
		}

		const currentEntries = 4
		current := make([]cipherCacheKey, 0, currentEntries)
		for i := range currentEntries {
			key := cacheTestKey(i)
			storeCachedCiphers(key, &cachedCiphers{epoch: cacheTestCurrentEpoch})
			current = append(current, key)
		}

		if got := cacheLen(); got != maxCacheSize {
			t.Fatalf("cache size = %d, want %d", got, maxCacheSize)
		}
		// Every current epoch entry survived, and the retired entries were
		// evicted oldest first.
		for i, key := range current {
			entry, ok := loadCachedCiphers(key)
			if !ok || entry.epoch != cacheTestCurrentEpoch {
				t.Fatalf("current epoch entry %d was evicted by a retired epoch entry", i)
			}
		}
		for i, key := range retired {
			_, ok := loadCachedCiphers(key)
			if i < currentEntries && ok {
				t.Errorf("oldest retired entry %d was not evicted", i)
			}
			if i >= currentEntries && !ok {
				t.Errorf("retired entry %d was evicted before an older one", i)
			}
		}
	})
}

// TestCacheEvictionRemovesRetiredEntryBehindCurrentEpoch checks the scan of the
// eviction: a live entry that sits in front of the retired entries in the
// insertion order must be skipped, and the oldest retired entry behind it must
// be removed instead.
func TestCacheEvictionRemovesRetiredEntryBehindCurrentEpoch(t *testing.T) {
	withCacheRestored(t, func() {
		leading := []cipherCacheKey{cacheTestKey(0), cacheTestKey(1)}
		for _, key := range leading {
			storeCachedCiphers(key, &cachedCiphers{epoch: cacheTestCurrentEpoch})
		}
		retired := fillTestCache(t, maxCacheSize-len(leading), cacheTestRetiredEpoch)
		if got := cacheLen(); got != maxCacheSize {
			t.Fatalf("cache size = %d, want %d", got, maxCacheSize)
		}

		added := cacheTestKey(2)
		storeCachedCiphers(added, &cachedCiphers{epoch: cacheTestCurrentEpoch})

		if got := cacheLen(); got != maxCacheSize {
			t.Fatalf("cache size = %d, want %d", got, maxCacheSize)
		}
		for _, key := range leading {
			if _, ok := loadCachedCiphers(key); !ok {
				t.Errorf("current epoch entry %q in front of the retired entries was evicted", key.password)
			}
		}
		if _, ok := loadCachedCiphers(added); !ok {
			t.Errorf("current epoch entry %q was evicted", added.password)
		}
		if _, ok := loadCachedCiphers(retired[0]); ok {
			t.Errorf("the oldest retired entry %q was not evicted", retired[0].password)
		}
		if _, ok := loadCachedCiphers(retired[1]); !ok {
			t.Errorf("retired entry %q was evicted before an older one", retired[1].password)
		}
	})
}

// TestCacheEvictionDropsOldestWithoutRetiredEpoch checks the second half of the
// eviction policy: when every entry belongs to the current key epoch, the
// oldest entry is evicted anyway, so the cache stays bounded.
func TestCacheEvictionDropsOldestWithoutRetiredEpoch(t *testing.T) {
	withCacheRestored(t, func() {
		filled := fillTestCache(t, maxCacheSize, cacheTestCurrentEpoch)

		const extraEntries = 3
		for i := range extraEntries {
			key := cacheTestKey(i)
			storeCachedCiphers(key, &cachedCiphers{epoch: cacheTestCurrentEpoch})
		}

		if got := cacheLen(); got != maxCacheSize {
			t.Fatalf("cache size = %d, want %d", got, maxCacheSize)
		}
		for i := range extraEntries {
			if _, ok := loadCachedCiphers(cacheTestKey(i)); !ok {
				t.Errorf("the entry %d that was just stored is missing", i)
			}
		}
		for i, key := range filled {
			_, ok := loadCachedCiphers(key)
			if i < extraEntries && ok {
				t.Errorf("oldest entry %d was not evicted", i)
			}
			if i == extraEntries && !ok {
				t.Errorf("entry %d was evicted before the older ones", i)
			}
		}
		// A middle entry of the filled cache must survive: eviction only
		// touches the oldest entries.
		if _, ok := loadCachedCiphers(filled[maxCacheSize/2]); !ok {
			t.Errorf("entry %d was evicted although it is not among the oldest", maxCacheSize/2)
		}
	})
}

// TestCacheEntryEpochIsAValueProperty keeps the shape of the cache key: the key
// is (password, suite), while the key epoch belongs to the cached value.
// A new epoch therefore replaces the value in place instead of adding a second
// entry for the same key.
func TestCacheEntryEpochIsAValueProperty(t *testing.T) {
	withCacheRestored(t, func() {
		key := cipherCacheKey{password: "epoch-replacement", suite: SuiteXChaCha20Poly1305}
		storeCachedCiphers(key, &cachedCiphers{epoch: cacheTestRetiredEpoch})
		storeCachedCiphers(key, &cachedCiphers{epoch: cacheTestCurrentEpoch})
		if got := cacheLen(); got != 1 {
			t.Fatalf("cache size = %d, want 1", got)
		}
		entry, ok := loadCachedCiphers(key)
		if !ok {
			t.Fatal("the replaced entry is missing")
		}
		if entry.epoch != cacheTestCurrentEpoch {
			t.Errorf("cached epoch = %d, want %d", entry.epoch, cacheTestCurrentEpoch)
		}
	})
}
