// Copyright (C) 2026  mieru authors
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

package serveruser

import (
	"math"
	"sync"
	"testing"

	"github.com/enfein/mieru/v3/pkg/cipher"
)

func TestSourceFailCacheRecordMissClear(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	key := sourceUserCacheTestKey(1001)
	hint := [4]byte{0xde, 0xad, 0xbe, 0xef}

	if cache.miss(key, hint) {
		t.Fatal("empty cache reported a miss")
	}
	cache.recordFailure(key, hint)
	if !cache.miss(key, hint) {
		t.Fatal("recorded failure was not reported as a miss")
	}
	cache.clear(key)
	if cache.miss(key, hint) {
		t.Fatal("cleared failure was still reported as a miss")
	}
	cache.clear(key) // Clearing an absent entry is a no-op.
}

func TestSourceFailCacheScopesSourceAndHint(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	keyA := sourceUserCacheTestKey(1002)
	keyB := sourceUserCacheTestKey(1003)
	hintA := [4]byte{0, 0, 0, 1}
	hintB := [4]byte{0, 0, 0, 2}

	cache.recordFailure(keyA, hintA)
	if cache.miss(keyB, hintA) {
		t.Fatal("failure of one source was attributed to another source")
	}
	if cache.miss(keyA, hintB) {
		t.Fatal("failure with one hint was attributed to another hint")
	}
	if !cache.miss(keyA, hintA) {
		t.Fatal("the recorded source and hint did not match")
	}
}

func TestSourceFailCacheRefreshesHintAndExpiry(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	key := sourceUserCacheTestKey(1004)
	hintA := [4]byte{1, 1, 1, 1}
	hintB := [4]byte{2, 2, 2, 2}

	cache.recordFailure(key, hintA)
	clock.set(100 + sourceFailCacheLifeSeconds - 1)
	cache.recordFailure(key, hintB)
	if cache.miss(key, hintA) {
		t.Fatal("refreshed entry still matched the previous hint")
	}
	if !cache.miss(key, hintB) {
		t.Fatal("refreshed entry did not match the latest hint")
	}

	clock.set(100 + sourceFailCacheLifeSeconds - 1 + sourceFailCacheLifeSeconds - 1)
	if !cache.miss(key, hintB) {
		t.Fatal("entry expired before its refreshed lifetime")
	}
	clock.set(100 + sourceFailCacheLifeSeconds - 1 + sourceFailCacheLifeSeconds)
	if cache.miss(key, hintB) {
		t.Fatal("entry did not expire after its refreshed lifetime")
	}
}

func TestSourceFailCacheTickWraparound(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(math.MaxUint32 - 2)
	cache := newSourceFailCacheWithTick(clock.now)
	key := sourceUserCacheTestKey(1005)
	hint := [4]byte{3, 3, 3, 3}

	cache.recordFailure(key, hint)
	clock.set(5)
	if !cache.miss(key, hint) {
		t.Fatal("entry expired too early across tick wraparound")
	}
	clock.set(8)
	if cache.miss(key, hint) {
		t.Fatal("entry did not expire after tick wraparound")
	}
}

func TestSourceFailCacheFourWayReplacement(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	keys := sourceFailCacheCollidingKeys(sourceFailCacheWays + 1)

	for i, key := range keys {
		cache.recordFailure(key, [4]byte{0, 0, 0, byte(i)})
	}
	// All entries share the same timestamp, so the first inserted entry is the
	// oldest and its way is reused by the fifth insertion.
	if cache.miss(keys[0], [4]byte{0, 0, 0, 0}) {
		t.Fatal("oldest entry survived four-way replacement")
	}
	for i := 1; i < len(keys); i++ {
		if !cache.miss(keys[i], [4]byte{0, 0, 0, byte(i)}) {
			t.Fatalf("entry %d was evicted unexpectedly", i)
		}
	}
}

func TestSourceFailCacheRetirement(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	key := sourceUserCacheTestKey(1006)
	hint := [4]byte{4, 4, 4, 4}

	cache.recordFailure(key, hint)
	cache.retire()
	if cache.loadTable() != nil {
		t.Fatal("retired cache still publishes a table")
	}
	if cache.miss(key, hint) {
		t.Fatal("retired cache reported a miss")
	}
	cache.recordFailure(key, hint) // No-op after retirement.
	cache.clear(key)               // No-op after retirement.
}

func TestSourceFailCacheConcurrentOperations(t *testing.T) {
	clock := &sourceUserCacheTestClock{}
	clock.set(100)
	cache := newSourceFailCacheWithTick(clock.now)
	key := sourceUserCacheTestKey(1007)
	hint := [4]byte{5, 5, 5, 5}

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				cache.recordFailure(key, hint)
				_ = cache.miss(key, hint)
				if i%2 == 0 {
					cache.clear(key)
				}
			}
		}()
	}
	wg.Wait()

	cache.recordFailure(key, hint)
	if !cache.miss(key, hint) {
		t.Fatal("concurrent operations lost the final recorded failure")
	}
}

func TestDiscoveryFailureCacheRequiresMandatoryHint(t *testing.T) {
	const userName = "failure-cache-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	plaintext := newDummyMetadata()

	// The hint names the registered user, but the payload is protected by a
	// different credential, so the trial decryption fails.
	unknownCredential := cipher.HashPassword([]byte("unknown"), []byte(userName))
	failedMetadata := encryptDiscoveryMetadata(t, unknownCredential, userName, users, true, plaintext)
	// A correctly authenticated packet with the same source hint.
	validMetadata := encryptDiscoveryMetadata(t, credential, userName, users, true, plaintext)
	source := Source{key: sourceUserCacheTestKey(1008), valid: true}

	t.Run("MandatoryRecordsFailure", func(t *testing.T) {
		publisher, mandatory := testPublisher(users, true)
		if _, err := discoverUser(publisher, mandatory, failedMetadata, source, false, nil); err == nil {
			t.Fatal("discovery with a wrong credential succeeded")
		}
		st := publisher.Load()
		if !st.failCache.miss(source.key, userHintFromMetadata(failedMetadata)) {
			t.Fatal("mandatory discovery did not record the failed source hint")
		}
		// A repeated packet returns before the trial loop. afterAttempt is
		// called only after tryState, so it must not run.
		calls := 0
		if _, err := discoverUser(publisher, mandatory, failedMetadata, source, false, func(*state) { calls++ }); err == nil {
			t.Fatal("repeated discovery was not suppressed")
		}
		if calls != 0 {
			t.Fatalf("suppressed discovery entered the trial loop %d times", calls)
		}
	})

	t.Run("OptionalHintIgnoresCache", func(t *testing.T) {
		publisher, mandatory := testPublisher(users, false)
		state := publisher.Load()
		// Simulate a previous failure with the valid packet's source hint. With
		// optional hints the cache must be ignored, otherwise a legitimate
		// user could be rejected.
		state.failCache.recordFailure(source.key, userHintFromMetadata(validMetadata))
		result, err := discoverUser(publisher, mandatory, validMetadata, source, false, nil)
		if err != nil {
			t.Fatalf("optional-hint discovery was rejected by the failure cache: %v", err)
		}
		if result.block == nil || result.policy.name != userName {
			t.Fatalf("optional-hint discovery = (block nil=%t, policy %q), want authenticated %q", result.block == nil, result.policy.name, userName)
		}

		// Optional discovery must not populate the cache either.
		if _, err := discoverUser(publisher, mandatory, failedMetadata, source, false, nil); err == nil {
			t.Fatal("discovery with a wrong credential succeeded")
		}
		if state.failCache.miss(source.key, userHintFromMetadata(failedMetadata)) {
			t.Fatal("optional-hint discovery populated the failure cache")
		}
	})

	t.Run("MandatorySuppressesValidRetry", func(t *testing.T) {
		publisher, mandatory := testPublisher(users, true)
		state := publisher.Load()
		state.failCache.recordFailure(source.key, userHintFromMetadata(validMetadata))
		if _, err := discoverUser(publisher, mandatory, validMetadata, source, false, nil); err == nil {
			t.Fatal("mandatory discovery ignored a recorded source failure")
		}
	})
}

func sourceFailCacheCollidingKeys(count int) [][16]byte {
	keys := make([][16]byte, 0, count)
	target := sourceFailCacheBucketIndex(sourceUserCacheTestKey(0))
	for value := uint64(0); len(keys) < count; value++ {
		key := sourceUserCacheTestKey(value)
		if sourceFailCacheBucketIndex(key) == target {
			keys = append(keys, key)
		}
	}
	return keys
}
