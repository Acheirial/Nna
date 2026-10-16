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
	"sync"
	"testing"
	"time"
)

// TestComputeSignatureMatchesFNV64a verifies that the inlined FNV-1a 64 bit
// implementation is identical to the hash.Hash based implementation it
// replaced, so that the replay protection of a running process is unchanged.
func TestComputeSignatureMatchesFNV64a(t *testing.T) {
	for _, size := range []int{0, 1, 15, 16, 17, 255, 256, 4096, 1 << 16} {
		data := randomData(t, size)
		hash := fnv.New64a()
		if _, err := hash.Write(data); err != nil {
			t.Fatalf("hash.Write() failed: %v", err)
		}
		if got, want := computeSignature(data), hash.Sum64(); got != want {
			t.Errorf("computeSignature(%d bytes) = %#x, want %#x", size, got, want)
		}
	}
	for _, tt := range []struct {
		name string
		data []byte
		want uint64
	}{
		{"empty", []byte{}, 0xcbf29ce484222325},
		{"zero byte", []byte{0}, 0xaf63bd4c8601b7df},
		{"letter a", []byte{'a'}, 0xaf63dc4c8601ec8c},
		{"abc", []byte("abc"), 0xe71fa2190541574b},
		{"all one", []byte{0xff, 0xff, 0xff, 0xff}, 0x994f76653e2a3951},
	} {
		if got := computeSignature(tt.data); got != tt.want {
			t.Errorf("computeSignature(%s) = %#x, want %#x", tt.name, got, tt.want)
		}
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
	cache := NewCache(capacity, 1*time.Minute)

	// One signature per shard, so that the cache is filled evenly.
	sigs := make([][]byte, capacity)
	for i := range uint64(capacity) {
		sigs[i] = dataForShard(t, i, 0x1234)
	}
	for i, sig := range sigs {
		if res := cache.IsDuplicate(sig, EmptyTag); res == true {
			t.Fatalf("IsDuplicate(sig %d) = true, want false", i)
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
	extra := dataForShard(t, 0, 0x5678)
	if res := cache.IsDuplicate(extra, EmptyTag); res == true {
		t.Fatalf("IsDuplicate(extra) = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Fatalf("cache sizes are %d %d, want 1 %d.", curr, prev, capacity)
	}
	if got := cache.count.Load(); got != 1 {
		t.Fatalf("counter after the rotation is %d, want 1.", got)
	}

	// The signatures of the previous maps are still detected as duplicates.
	// Every signature is rechecked on a cache that was rotated exactly once,
	// because promoting a signature back to the current map grows the cache
	// and can rotate it again before the last signature is checked.
	for i, sig := range sigs {
		rotated := NewCache(capacity, 1*time.Minute)
		for _, s := range sigs {
			rotated.IsDuplicate(s, EmptyTag)
		}
		rotated.IsDuplicate(extra, EmptyTag) // reaches the capacity and rotates
		if res := rotated.IsDuplicate(sig, EmptyTag); res == false {
			t.Errorf("IsDuplicate(sig %d) = false, want true", i)
		}
		if curr, prev := rotated.Sizes(); curr != 2 || prev != capacity {
			t.Errorf("cache sizes are %d %d, want 2 %d.", curr, prev, capacity)
		}
		if got := rotated.count.Load(); got != 2 {
			t.Errorf("counter is %d, want 2.", got)
		}
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
	cache := NewCache(capacity, 1*time.Minute)

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
				cache.IsDuplicate(d, EmptyTag)
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
	before := cache.count.Load()
	for i := range int64(capacity) - before {
		if res := cache.IsDuplicate(randomData(t, 16), EmptyTag); res == true {
			t.Fatalf("IsDuplicate() of a new signature = true, want false")
		}
		if got := cache.count.Load(); got != before+i+1 {
			t.Fatalf("counter after %d inserts is %d, want %d.", i+1, got, before+i+1)
		}
	}

	// One more entry reaches the capacity of the cache and rotates it.
	if res := cache.IsDuplicate(randomData(t, 16), EmptyTag); res == true {
		t.Fatalf("IsDuplicate() of a new signature = true, want false")
	}
	if got := cache.count.Load(); got != 1 {
		t.Fatalf("counter after the rotation is %d, want 1.", got)
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

// dataForShard returns a 16 byte payload that is stored in the given shard and
// that is different for every (seed, shardID) pair. The shard is searched with
// the same signature bits that the cache uses to pick a shard, so about 16
// payloads are tried per call.
func dataForShard(t *testing.T, shardID uint64, seed uint64) []byte {
	t.Helper()
	if shardID&shardMask != shardID {
		t.Fatalf("shard %d doesn't exist.", shardID)
	}
	data := make([]byte, 16)
	binary.BigEndian.PutUint64(data[8:], seed)
	for i := uint64(0); ; i++ {
		binary.BigEndian.PutUint64(data[:8], i)
		if computeSignature(data)>>shardShift == shardID {
			return data
		}
	}
}
