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
	"encoding/binary"
	"hash/maphash"
	"sync"
	"sync/atomic"
	"time"
)

// The source failure cache remembers the user hint that a source address used
// when its last discovery attempt failed. A repeated packet from the same
// source with the same hint is rejected before entering the trial decryption
// loop. It is a negative cache: entries carry no authentication value and are
// only consulted while the server requires a user hint.
const (
	// sourceFailCacheLifeSeconds is how long a failed (source, hint) pair is
	// suppressed. It is short because a client may legitimately retry with
	// the same hint after a transient failure.
	sourceFailCacheLifeSeconds = 10
	sourceFailCacheBucketCount = 1024
	sourceFailCacheWays        = 4
	sourceFailCacheLockStripes = 64
)

var sourceFailCacheProcessStart = time.Now()

type sourceFailCacheTickFunc func() uint32

// sourceFailCache owns an atomically detachable table, using the same
// concurrency and retirement semantics as sourceUserCache. Lookups never take
// a lock; recordFailure and clear serialize writers of one bucket.
type sourceFailCache struct {
	table       atomic.Pointer[sourceFailCacheTable]
	tick        sourceFailCacheTickFunc
	bucketLocks [sourceFailCacheLockStripes]sync.Mutex
}

type sourceFailCacheTable struct {
	buckets [sourceFailCacheBucketCount]sourceFailCacheBucket
}

type sourceFailCacheBucket struct {
	ways [sourceFailCacheWays]atomic.Pointer[sourceFailCacheEntry]
}

// sourceFailCacheEntry is published by atomic pointer replacement when its key
// changes, and updated in place when the same key fails again. The key is
// immutable after publication. hint is always stored before failedAt, so a
// reader that observes a fresh timestamp also observes the hint written with
// it; Go atomic operations are sequentially consistent.
type sourceFailCacheEntry struct {
	key      [16]byte
	hint     atomic.Uint32
	failedAt atomic.Uint32
}

func sourceFailCacheCurrentTick() uint32 {
	return uint32(time.Since(sourceFailCacheProcessStart) / time.Second)
}

func newSourceFailCache() *sourceFailCache {
	return newSourceFailCacheWithTick(sourceFailCacheCurrentTick)
}

func newSourceFailCacheWithTick(tick sourceFailCacheTickFunc) *sourceFailCache {
	if tick == nil {
		tick = sourceFailCacheCurrentTick
	}
	c := &sourceFailCache{tick: tick}
	c.table.Store(&sourceFailCacheTable{})
	return c
}

func (c *sourceFailCache) loadTable() *sourceFailCacheTable {
	if c == nil {
		return nil
	}
	return c.table.Load()
}

func (c *sourceFailCache) retire() {
	if c != nil {
		c.table.Swap(nil)
	}
}

func (c *sourceFailCache) currentTick() uint32 {
	if c == nil || c.tick == nil {
		return sourceFailCacheCurrentTick()
	}
	return c.tick()
}

func sourceFailCacheBucketIndex(key [16]byte) uint32 {
	return uint32(maphash.Bytes(sourceUserCacheHashSeed, key[:])) & (sourceFailCacheBucketCount - 1)
}

func sourceFailCachePackHint(hint [4]byte) uint32 {
	return binary.LittleEndian.Uint32(hint[:])
}

func sourceFailCacheExpired(now, then uint32) bool {
	return now-then >= sourceFailCacheLifeSeconds
}

// miss reports whether this source recently failed discovery with exactly this
// user hint. A zero or retired cache never reports a miss.
func (c *sourceFailCache) miss(key [16]byte, hint [4]byte) bool {
	if c == nil {
		return false
	}
	table := c.loadTable()
	if table == nil {
		return false
	}

	now := c.currentTick()
	packedHint := sourceFailCachePackHint(hint)
	bucket := &table.buckets[sourceFailCacheBucketIndex(key)]
	for way := range sourceFailCacheWays {
		entry := bucket.ways[way].Load()
		if entry == nil || entry.key != key {
			continue
		}
		if sourceFailCacheExpired(now, entry.failedAt.Load()) {
			return false
		}
		return entry.hint.Load() == packedHint
	}
	return false
}

// recordFailure remembers that this source failed discovery with this hint.
func (c *sourceFailCache) recordFailure(key [16]byte, hint [4]byte) {
	if c == nil {
		return
	}
	table := c.loadTable()
	if table == nil {
		return
	}

	packedHint := sourceFailCachePackHint(hint)
	bucketIndex := sourceFailCacheBucketIndex(key)
	bucket := &table.buckets[bucketIndex]
	bucketLock := &c.bucketLocks[bucketIndex&(sourceFailCacheLockStripes-1)]
	bucketLock.Lock()
	defer bucketLock.Unlock()

	now := c.currentTick()
	var ways [sourceFailCacheWays]*sourceFailCacheEntry
	match := -1
	for way := range sourceFailCacheWays {
		ways[way] = bucket.ways[way].Load()
		if ways[way] != nil && ways[way].key == key && match < 0 {
			match = way
		}
	}

	if match >= 0 {
		ways[match].hint.Store(packedHint)
		ways[match].failedAt.Store(now)
		return
	}

	way := selectSourceFailCacheWay(ways, now)
	replacement := &sourceFailCacheEntry{key: key}
	replacement.hint.Store(packedHint)
	replacement.failedAt.Store(now)
	bucket.ways[way].Store(replacement)
}

// clear forgets any recorded failure of this source. The lock is taken only
// when a matching entry is present, so the successful discovery path stays
// lock-free in the common case.
func (c *sourceFailCache) clear(key [16]byte) {
	if c == nil {
		return
	}
	table := c.loadTable()
	if table == nil {
		return
	}

	bucketIndex := sourceFailCacheBucketIndex(key)
	bucket := &table.buckets[bucketIndex]
	found := false
	for way := range sourceFailCacheWays {
		entry := bucket.ways[way].Load()
		if entry != nil && entry.key == key {
			found = true
			break
		}
	}
	if !found {
		return
	}

	bucketLock := &c.bucketLocks[bucketIndex&(sourceFailCacheLockStripes-1)]
	bucketLock.Lock()
	defer bucketLock.Unlock()
	for way := range sourceFailCacheWays {
		entry := bucket.ways[way].Load()
		if entry != nil && entry.key == key {
			bucket.ways[way].Store(nil)
			return
		}
	}
}

// selectSourceFailCacheWay prefers an empty way, then an expired way, then the
// least recently failed way. The caller holds the bucket lock.
func selectSourceFailCacheWay(ways [sourceFailCacheWays]*sourceFailCacheEntry, now uint32) int {
	for way, entry := range ways {
		if entry == nil {
			return way
		}
	}

	var ticks [sourceFailCacheWays]uint32
	for way, entry := range ways {
		ticks[way] = entry.failedAt.Load()
		if sourceFailCacheExpired(now, ticks[way]) {
			return way
		}
	}

	oldest := 0
	oldestAge := now - ticks[0]
	for way := 1; way < sourceFailCacheWays; way++ {
		age := now - ticks[way]
		if age > oldestAge {
			oldest = way
			oldestAge = age
		}
	}
	return oldest
}
