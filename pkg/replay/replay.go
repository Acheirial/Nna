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
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Tag identifies the source of a packet. It is used to tell an exact
// retransmission of a packet apart from a replay of that packet by a different
// source. The zero value means that the packet has no tag at all, which
// disables the retransmission exception for that packet.
type Tag = netip.AddrPort

// Domain separates the replay detection of independent traffic classes, so
// that the same decrypted content observed in two domains is never mistaken for
// a replay of itself.
type Domain uint8

const (
	// DomainStream is the domain of the byte stream traffic (TCP).
	DomainStream Domain = iota + 1

	// DomainPacketClientToServer is the domain of the client to server packet
	// traffic (UDP).
	DomainPacketClientToServer

	// DomainPacketServerToClient is the domain of the server to client packet
	// traffic (UDP).
	DomainPacketServerToClient
)

// FNV-1a 64 bit parameters. computeSignature() computes the exact hash of
// hash/fnv's New64a() over the byte sequence it hashes, without allocating a
// hash.Hash object per call.
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

	// current stores the current set of packet signatures. The value is the
	// tag of the authenticated packet that recorded the signature.
	current map[uint64]Tag

	// previous stores the previous set of packet signatures.
	previous map[uint64]Tag
}

// ReplayCache stores the signature of recent decrypted packets to avoid
// a replay attack. Seen() may be called on unauthenticated data; Record() is
// the only entry point that changes the cache and it must be called after the
// data was authenticated.
type ReplayCache struct {
	// shards partition the signature space, so that sessions carried by the
	// same underlay don't contend on a single lock.
	shards [shardCount]shard

	// rotateMu serializes the rotation and the expiry of the whole cache. The
	// read only path of Seen() doesn't take it, because Seen() never rotates;
	// the rotation is triggered by Record().
	rotateMu sync.Mutex

	// capacity is the soft upper bound of the number of entries in the whole
	// replay cache. Once the number of entries in the current maps of all
	// shards reaches capacity (i.e. count >= capacity), Record() replaces the
	// current maps with the previous maps. The check is done before the lock of
	// a shard is taken, so concurrent calls can overshoot the capacity by at
	// most the number of calls in flight. The cache keeps the entries of the
	// current and previous generation, so overshooting only adds entries to the
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
	// Like the capacity, the expiry is only enforced by Record(), because
	// Seen() must not change the state of the cache.
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
		c.shards[i].current = make(map[uint64]Tag)
		c.shards[i].previous = make(map[uint64]Tag)
	}
	c.expireAt.Store(monotonicNow() + expireInterval.Nanoseconds())
	return c
}

// A replay cache is used in two steps. Seen() is a read only lookup, which is
// safe to call on data that is not authenticated yet, and it never changes the
// state of the cache. Record() is the only writer, and it must be called after
// the data was authenticated.
//
// The lookup used to write to the cache, which had two consequences. First, an
// attacker could fill the cache with unauthenticated data. Second, a lookup
// that found the signature of a packet in the previous generation while
// carrying a different tag still promoted that signature into the current
// generation, storing the tag of the attacker. The first call was reported as a
// replay, but the second call of the attacker with the same tag found the
// signature in the current generation and was let through. Because Seen() is
// free of side effects and the tag of a signature can only be replaced by an
// authenticated Record(), promotion can no longer hand the retransmission
// exemption to another source: every call of that attacker is a replay.

// Seen checks if the given data is a replay of the data recorded in the replay
// cache. It returns true when the data is a duplicate.
//
// Data that was recorded with the same non-zero tag is exempt from the replay
// detection, so that a lost packet can be retransmitted from the same source.
// A zero tag disables this exception, and a lookup never claims it for another
// source: the tag of a recorded signature is only changed by Record().
//
// Seen() doesn't write to the cache. It can't add an entry, can't refresh the
// tag of an entry, and can't rotate the cache.
func (c *ReplayCache) Seen(domain Domain, data []byte, tag Tag) bool {
	if c == nil || c.capacity == 0 {
		// The replay cache is disabled.
		return false
	}
	signature := computeSignature(domain, data)
	s := &c.shards[(signature>>shardShift)&shardMask]
	s.mu.Lock()
	defer s.mu.Unlock()

	// Both generations are checked, so a signature is still detected for one
	// whole generation after it left the current maps.
	if recordedTag, ok := s.current[signature]; ok {
		return !canRetransmit(recordedTag, tag)
	}
	if recordedTag, ok := s.previous[signature]; ok {
		return !canRetransmit(recordedTag, tag)
	}
	return false
}

// Record adds the given data to the replay cache. It is the only function that
// writes to the cache, and it must be called after the data was authenticated.
//
// Recording a signature that is already in the current map of a shard replaces
// its tag with tag. Recording a signature that is stored in the previous map
// promotes it into the current map with tag, so that a retransmission extends
// the deduplication window of its signature. The number of entries of the
// current maps decides when the cache rotates, and it is kept consistent with
// the maps while the lock of the shard is held.
func (c *ReplayCache) Record(domain Domain, data []byte, tag Tag) {
	if c == nil || c.capacity == 0 {
		// The replay cache is disabled.
		return
	}
	signature := computeSignature(domain, data)
	if c.count.Load() >= int64(c.capacity) || monotonicNow() > c.expireAt.Load() {
		c.rotate()
	}
	s := &c.shards[(signature>>shardShift)&shardMask]
	s.mu.Lock()
	defer s.mu.Unlock()

	// A signature is only stored in the `current` map of a shard, and only
	// while the lock of that shard is held, so that `count` can never drift
	// away from the number of entries of the current maps.
	if _, ok := s.current[signature]; !ok {
		c.count.Add(1)
	}
	s.current[signature] = tag
}

// canRetransmit reports whether a lookup that carries tag is a retransmission
// of the data that was recorded with recordedTag. A retransmission is exempt
// from the replay detection. A zero tag never grants the exemption, otherwise
// data that carries no tag at all could be replayed.
func canRetransmit(recordedTag, tag Tag) bool {
	return tag.IsValid() && recordedTag == tag
}

// rotate moves the current maps to the previous maps of every shard, or drops
// both maps if they are expired. It is a no-op if another goroutine already did
// the work, so it is safe to call it whenever Record() suspects that the cache
// needs to rotate. Shard locks are always taken one at a time, which keeps the
// lock order rotateMu -> shard.mu consistent.
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
			s.current = make(map[uint64]Tag)
			s.previous = make(map[uint64]Tag)
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
		s.current = make(map[uint64]Tag)
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
		s.current = make(map[uint64]Tag)
		s.previous = make(map[uint64]Tag)
		c.count.Add(-int64(n))
		s.mu.Unlock()
	}
}

// computeSignature returns the FNV-1a 64 bit hash of the length of data, the
// domain, and the content of data, in that order. It doesn't allocate.
//
// The length is hashed first, so that two inputs of a different length can't
// produce the same byte sequence for the hash. The domain is hashed as well, so
// that the same content observed in two traffic classes gets two different
// signatures.
func computeSignature(domain Domain, data []byte) uint64 {
	hash := uint64(offset64)
	length := uint64(len(data))
	for i := 7; i >= 0; i-- {
		hash ^= (length >> (8 * uint(i))) & 0xff
		hash *= prime64
	}
	hash ^= uint64(domain)
	hash *= prime64
	for _, b := range data {
		hash ^= uint64(b)
		hash *= prime64
	}
	return hash
}
