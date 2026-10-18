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
	crand "crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"io"
	"sync"
	"testing"
	"time"
)

// TestComputeSignatureMatchesFNV64a verifies that the inlined FNV-1a 64 bit
// implementation is identical to the hash.Hash based implementation of the byte
// sequence it hashes, which is the big endian length of the data, the domain,
// and the data itself.
func TestComputeSignatureMatchesFNV64a(t *testing.T) {
	domains := []Domain{DomainStream, DomainPacketClientToServer, DomainPacketServerToClient}
	for _, size := range []int{0, 1, 15, 16, 17, 255, 256, 4096, 1 << 16} {
		data := randomData(t, size)
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(data)))
		for _, domain := range domains {
			hash := fnv.New64a()
			writeAll(t, hash, length[:])
			writeAll(t, hash, []byte{byte(domain)})
			writeAll(t, hash, data)
			if got, want := computeSignature(domain, data), hash.Sum64(); got != want {
				t.Errorf("computeSignature(%d bytes, domain %d) = %#x, want %#x", size, domain, got, want)
			}
		}
	}
	for _, tt := range []struct {
		name   string
		domain Domain
		data   []byte
		want   uint64
	}{
		{"empty data", DomainStream, []byte{}, 0xe604813a2490280c},
		{"one zero byte", DomainStream, []byte{0}, 0x612cf2cc1c11d40b},
		{"letter a", DomainStream, []byte{'a'}, 0x612cd1cc1c119bf8},
		{"abc in the client to server domain", DomainPacketClientToServer, []byte("abc"), 0x8ae9a76bf265d4de},
		{"four one bytes", DomainPacketServerToClient, []byte{0xff, 0xff, 0xff, 0xff}, 0x1299d2e39b59680a},
	} {
		if got := computeSignature(tt.domain, tt.data); got != tt.want {
			t.Errorf("computeSignature(%s) = %#x, want %#x", tt.name, got, tt.want)
		}
	}
}

// TestComputeSignatureSeparatesInputs verifies that the domain and the length
// of the data are part of the signature, so that the same content can't be
// replayed across two domains, and a prefix of the content is not the same
// signature as the content.
func TestComputeSignatureSeparatesInputs(t *testing.T) {
	data := randomData(t, 32)
	seen := make(map[uint64]Domain)
	for _, domain := range []Domain{DomainStream, DomainPacketClientToServer, DomainPacketServerToClient} {
		signature := computeSignature(domain, data)
		if other, ok := seen[signature]; ok {
			t.Errorf("domain %d and domain %d share the signature of the same data.", other, domain)
		}
		seen[signature] = domain
	}
	if a, b := computeSignature(DomainStream, data), computeSignature(DomainStream, data[:len(data)-1]); a == b {
		t.Errorf("the data and its prefix share the signature %#x.", a)
	}
}

// TestGlobalCapacityAcrossShards verifies that the capacity and the rotation
// boundary belong to the whole cache and not to a single shard: a cache that
// holds fewer entries than its number of shards must still rotate when the
// total number of entries reaches the capacity. A per shard capacity would
// divide the deduplication window by the number of shards.
func TestGlobalCapacityAcrossShards(t *testing.T) {
	const capacity = 8
	if capacity > shardCount {
		t.Fatalf("this test requires a capacity of at most %d.", shardCount)
	}
	domain := DomainPacketClientToServer
	noTag := Tag{}
	cache := NewCache(capacity, 1*time.Minute)

	// One signature per shard, so that the cache is filled evenly.
	sigs := make([][]byte, capacity)
	for i := range uint64(capacity) {
		sigs[i] = dataForShard(t, domain, i, 0x1234)
	}
	for i, sig := range sigs {
		// Seen() is a lookup, so it neither records nor reports the signature.
		if res := cache.Seen(domain, sig, noTag); res == true {
			t.Fatalf("Seen(sig %d) before Record() = true, want false", i)
		}
		cache.Record(domain, sig, noTag)
		if res := cache.Seen(domain, sig, noTag); res == false {
			t.Fatalf("Seen(sig %d) after Record() = false, want true", i)
		}
	}
	if curr, prev := cache.Sizes(); curr != capacity || prev != 0 {
		t.Fatalf("cache sizes are %d %d, want %d 0.", curr, prev, capacity)
	}
	if got := cache.count.Load(); got != capacity {
		t.Fatalf("counter is %d, want %d.", got, capacity)
	}

	// The next signature reaches the capacity of the whole cache, so it must
	// rotate the current maps of every shard into the previous maps.
	extra := dataForShard(t, domain, 0, 0x5678)
	cache.Record(domain, extra, noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Fatalf("cache sizes are %d %d, want 1 %d.", curr, prev, capacity)
	}
	if got := cache.count.Load(); got != 1 {
		t.Fatalf("counter after the rotation is %d, want 1.", got)
	}

	// The signatures of the previous maps are still detected as duplicates, and
	// a lookup doesn't promote them back into the current maps.
	for i, sig := range sigs {
		if res := cache.Seen(domain, sig, noTag); res == false {
			t.Errorf("Seen(sig %d) in the previous map = false, want true", i)
		}
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Errorf("cache sizes after the lookups are %d %d, want 1 %d.", curr, prev, capacity)
	}
	if got := cache.count.Load(); got != 1 {
		t.Errorf("counter after the lookups is %d, want 1.", got)
	}

	// Only Record() promotes a signature of the previous map into the current
	// map, which grows the number of entries of the current maps by one.
	cache.Record(domain, sigs[0], noTag)
	if curr, prev := cache.Sizes(); curr != 2 || prev != capacity {
		t.Errorf("cache sizes after the promotion are %d %d, want 2 %d.", curr, prev, capacity)
	}
	if got := cache.count.Load(); got != 2 {
		t.Errorf("counter after the promotion is %d, want 2.", got)
	}
}

// TestCountStaysConsistentUnderConcurrency verifies that the counter which
// decides the rotation of the whole cache can't drift away from the number of
// entries of the current maps, and that the rotation boundary is still reached
// exactly when the total number of entries reaches the capacity. Run with -race.
func TestCountStaysConsistentUnderConcurrency(t *testing.T) {
	const (
		capacity  = 32
		workers   = 8
		perWorker = 128
	)
	domain := DomainPacketClientToServer
	noTag := Tag{}
	cache := NewCache(capacity, 1*time.Hour)

	// The input is generated before the goroutines start, so that the cache is
	// the only shared state.
	data := make([][][]byte, workers)
	for w := range data {
		data[w] = make([][]byte, perWorker)
		for i := range data[w] {
			data[w][i] = randomData(t, 16)
		}
	}

	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for _, d := range data[w] {
				cache.Record(domain, d, noTag)
			}
		}(w)
	}
	wg.Wait()

	// The counter is the number of entries of the current maps of all shards.
	var inCurrent int64
	for i := range cache.shards {
		s := &cache.shards[i]
		s.mu.Lock()
		inCurrent += int64(len(s.current))
		s.mu.Unlock()
	}
	if got := cache.count.Load(); got != inCurrent {
		t.Fatalf("counter is %d, but the current maps hold %d entries.", got, inCurrent)
	}
	if curr, _ := cache.Sizes(); int64(curr) != inCurrent {
		t.Fatalf("Sizes() reports %d current entries, but the current maps hold %d entries.", curr, inCurrent)
	}

	// From now on the cache is only accessed by this goroutine, so the number
	// of inserts needed to reach the rotation boundary is known exactly.
	for cache.count.Load() < int64(capacity) {
		d := randomData(t, 16)
		before := cache.count.Load()
		if res := cache.Seen(domain, d, noTag); res == true {
			t.Fatalf("Seen() of an unknown signature = true, want false")
		}
		cache.Record(domain, d, noTag)
		if got := cache.count.Load(); got != before+1 {
			t.Fatalf("counter after an insert is %d, want %d.", got, before+1)
		}
	}

	// One more entry reaches the capacity of the cache and rotates it.
	cache.Record(domain, randomData(t, 16), noTag)
	if got := cache.count.Load(); got != 1 {
		t.Fatalf("counter after the rotation is %d, want 1.", got)
	}
}

// TestExpireRotation verifies the time based rotation of the cache. The expiry
// of the current generation is injected by rewriting expireAt, which is exactly
// the field that Record() compares against, so the test doesn't sleep.
func TestExpireRotation(t *testing.T) {
	const expireInterval = 1 * time.Minute
	domain := DomainPacketServerToClient
	noTag := Tag{}
	cache := NewCache(64, expireInterval)
	sigs := make([][]byte, 3)
	for i := range sigs {
		sigs[i] = randomData(t, 16)
	}
	a, b, c := sigs[0], sigs[1], sigs[2]

	if res := cache.Seen(domain, a, noTag); res == true {
		t.Fatalf("Seen() before Record() = true, want false")
	}
	cache.Record(domain, a, noTag)

	// Age the current generation by less than one expire interval, so that the
	// next Record() moves it into the previous generation instead of dropping
	// both generations.
	cache.expireAt.Store(monotonicNow() - 1)
	cache.Record(domain, b, noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Fatalf("cache sizes after the time based rotation are %d %d, want 1 1.", curr, prev)
	}
	if res := cache.Seen(domain, a, noTag); res == false {
		t.Errorf("Seen() of the rotated out signature = false, want true")
	}

	// Both generations are expired now, but a lookup must not drop them.
	cache.expireAt.Store(monotonicNow() - expireInterval.Nanoseconds() - 1)
	if res := cache.Seen(domain, a, noTag); res == false {
		t.Errorf("Seen() of an expired signature before the rotation = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Errorf("cache sizes after a lookup on an expired cache are %d %d, want 1 1.", curr, prev)
	}

	// The next Record() drops every generation that is older than one expire
	// interval.
	cache.Record(domain, c, noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Fatalf("cache sizes after the expiry are %d %d, want 1 0.", curr, prev)
	}
	if got := cache.count.Load(); got != 1 {
		t.Fatalf("counter after the expiry is %d, want 1.", got)
	}
	for _, sig := range [][]byte{a, b} {
		if res := cache.Seen(domain, sig, noTag); res == true {
			t.Errorf("Seen() of an expired signature = true, want false")
		}
	}
	if res := cache.Seen(domain, c, noTag); res == false {
		t.Errorf("Seen() of the recorded signature = false, want true")
	}
}

// randomData returns size random bytes.
func randomData(t *testing.T, size int) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := crand.Read(data); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}
	return data
}

// writeAll writes b to w and fails the test if the write fails.
func writeAll(t *testing.T, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
}

// dataForShard returns a 16 byte payload that is stored in the given shard of
// the given domain and that is different for every (domain, seed, shardID)
// triple. The shard is searched with the same signature bits that the cache
// uses to pick a shard, so about 16 payloads are tried per call.
func dataForShard(t *testing.T, domain Domain, shardID uint64, seed uint64) []byte {
	t.Helper()
	if shardID&shardMask != shardID {
		t.Fatalf("shard %d doesn't exist.", shardID)
	}
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[8:], seed)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(data[:8], i)
		if computeSignature(domain, data)>>shardShift == shardID {
			return data
		}
	}
}
