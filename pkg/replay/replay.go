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

package replay

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	EmptyTag = ""
)

// FNV-1a 64 bit parameters. computeSignature() computes the exact hash of
// hash/fnv's New64a(), without allocating a hash.Hash object per call.
const (
	offset64 uint64 = 0xcbf29ce484222325
	prime64  uint64 = 0x100000001b3
)

// The number of locks and map pairs of a replay cache. shardCount must be a
// power of two, so that the shard index is a bit mask of the signature.
const (
	shardBits  = 4
	shardCount = 1 << shardBits
	shardMask  = shardCount - 1

	// shardShift selects the most significant bits of the signature when a
	// shard is picked. The low bits of FNV-1a are only a function of the low
	// bits of the hashed bytes (the prime is invertible modulo 16), so they
	// would collapse structured payloads into a few shards.
	shardShift = 64 - shardBits
)

// monotonicBase converts the monotonic clock reading of time.Time into an int64
// that can be stored and loaded atomically.
var monotonicBase = time.Now()

// monotonicNow returns the number of nanoseconds elapsed since monotonicBase.
// Unlike a wall clock reading it can't go backward, which matches the monotonic
// comparison of the unsharded implementation (time.Now().Add() and time.Since()).
func monotonicNow() int64 {
	return int64(time.Since(monotonicBase))
}

// shard is one lock protected partition of a ReplayCache.
type shard struct {
	// mu is required to access the current and previous map of this shard.
	mu sync.Mutex

	// current stores the current set of packet signatures.
	current map[uint64]string

	// previous stores the previous set of packet signatures.
	previous map[uint64]string
}

// ReplayCache stores the signature of recent decrypted packets to avoid
// a replay attack.
type ReplayCache struct {
	// shards partition the signature space, so that sessions carried by the
	// same underlay don't contend on a single lock.
	shards [shardCount]shard

	// rotateMu serializes the rotation and the expiry of the whole cache. The
	// common path of IsDuplicate() doesn't take it.
	rotateMu sync.Mutex

	// capacity is the soft upper bound of the number of entries in the whole
	// replay cache. Once the number of entries in the current maps of all
	// shards reaches capacity (i.e. count >= capacity), the current maps
	// replace the previous maps. The check is done before the lock of a shard
	// is taken, so concurrent calls can overshoot the capacity by at most the
	// number of calls in flight. The cache keeps the entries of the current
	// and previous generation, so overshooting only adds entries to the
	// deduplication window, it never removes any.
	capacity int

	// count is the number of entries stored in the current maps of all shards.
	// It is the sharded equivalent of len(current) of a single map cache, and
	// it is the value that decides when the cache rotates. A shard is never
	// rotated on its own, otherwise the capacity and the deduplication window
	// would depend on the signature distribution.
	count atomic.Int64

	// expireAt is the time (read by monotonicNow()) when the current maps
	// should replace the previous maps, regardless of the number of entries.
	expireAt atomic.Int64

	// expireInterval is the interval to reset expireAt.
	expireInterval time.Duration
}

// NewCache creates a new replay cache.
func NewCache(capacity int, expireInterval time.Duration) *ReplayCache {
	if capacity < 0 {
		panic("replay cache capacity can't be negative")
	}
	if expireInterval.Nanoseconds() <= 0 {
		panic("replay cache expire interval must be a positive time range")
	}
	c := &ReplayCache{
		capacity:       capacity,
		expireInterval: expireInterval,
	}
	for i := range c.shards {
		c.shards[i].current = make(map[uint64]string)
		c.shards[i].previous = make(map[uint64]string)
	}
	c.expireAt.Store(monotonicNow() + expireInterval.Nanoseconds())
	return c
}

// IsDuplicate checks if the given data is present in the replay cache.
// If a non-empty tag is provided, it is not considered as a duplicate
// when the same tag is used. This can allow retransmit exact content
// from the same network address. Use an empty tag disables this feature.
func (c *ReplayCache) IsDuplicate(data []byte, tag string) bool {
	if c == nil || c.capacity == 0 {
		// The replay cache is disabled.
		return false
	}
	signature := computeSignature(data)
	if c.count.Load() >= int64(c.capacity) || monotonicNow() > c.expireAt.Load() {
		c.rotate()
	}
	s := &c.shards[(signature>>shardShift)&shardMask]
	s.mu.Lock()
	defer s.mu.Unlock()

	// A signature is only stored in the `current` map of a shard, and only
	// while the lock of that shard is held, so that `count` can never drift
	// away from the number of entries of the current maps.
	if existingTag, ok := s.current[signature]; ok {
		if existingTag == EmptyTag || tag == EmptyTag {
			return true
		}
		return existingTag != tag
	} else {
		s.current[signature] = tag
		c.count.Add(1)
	}
	// The signature was missing from `current`, so it was stored into `current`
	// above. If it is also found in `previous` and this call reports a duplicate,
	// the signature is still promoted (re-inserted into `current` with the tag of
	// this call) as a side effect of that store.
	if existingTag, ok := s.previous[signature]; ok {
		if existingTag == EmptyTag || tag == EmptyTag {
			return true
		}
		return existingTag != tag
	}
	return false
}

// rotate moves the current maps to the previous maps of every shard, or drops
// both maps if they are expired. It is a no-op if another goroutine already did
// the work, so it is safe to call it whenever IsDuplicate() suspects that the
// cache needs to rotate. Shard locks are always taken one at a time, which
// keeps the lock order rotateMu -> shard.mu consistent.
func (c *ReplayCache) rotate() {
	c.rotateMu.Lock()
	defer c.rotateMu.Unlock()

	now := monotonicNow()
	if now-c.expireAt.Load() > c.expireInterval.Nanoseconds() {
		// Both current and previous are expired.
		for i := range c.shards {
			s := &c.shards[i]
			s.mu.Lock()
			n := len(s.current)
			s.current = make(map[uint64]string)
			s.previous = make(map[uint64]string)
			c.count.Add(-int64(n))
			s.mu.Unlock()
		}
		c.expireAt.Store(now + c.expireInterval.Nanoseconds())
		return
	}
	if c.count.Load() < int64(c.capacity) && now <= c.expireAt.Load() {
		// Another goroutine rotated the cache already.
		return
	}

	// Move current to previous.
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n := len(s.current)
		s.previous = s.current
		s.current = make(map[uint64]string)
		c.count.Add(-int64(n))
		s.mu.Unlock()
	}
	c.expireAt.Store(now + c.expireInterval.Nanoseconds())
}

// Sizes returns the number of entries in `current` map and `previous` map.
func (c *ReplayCache) Sizes() (int, int) {
	var current, previous int
	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		current += len(s.current)
		previous += len(s.previous)
		s.mu.Unlock()
	}
	return current, previous
}

// Clear removes all the data in the replay cache.
func (c *ReplayCache) Clear() {
	c.rotateMu.Lock()
	defer c.rotateMu.Unlock()

	for i := range c.shards {
		s := &c.shards[i]
		s.mu.Lock()
		n := len(s.current)
		s.current = make(map[uint64]string)
		s.previous = make(map[uint64]string)
		c.count.Add(-int64(n))
		s.mu.Unlock()
	}
}

// computeSignature returns the FNV-1a 64 bit hash of data. It doesn't allocate.
func computeSignature(data []byte) uint64 {
	hash := uint64(offset64)
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}
