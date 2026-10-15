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

package replay_test

import (
	crand "crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/replay"
)

func TestDuplicate(t *testing.T) {
	cache := replay.NewCache(10, 1*time.Minute)
	data := make([]byte, 256)
	if _, err := crand.Read(data); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}

	if res := cache.IsDuplicate(data, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(data, replay.EmptyTag); res == false {
		t.Errorf("IsDuplicate() = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}
}

func TestNoDuplicate(t *testing.T) {
	cache := replay.NewCache(10, 1*time.Minute)
	a := make([]byte, 1)
	if _, err := crand.Read(a); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}
	b := make([]byte, 31)
	if _, err := crand.Read(b); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}

	if res := cache.IsDuplicate(a, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(b, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 2 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 2 0.", curr, prev)
	}
}

func TestTag(t *testing.T) {
	cache := replay.NewCache(10, 1*time.Minute)
	data := make([]byte, 32)
	if _, err := crand.Read(data); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}

	if res := cache.IsDuplicate(data, "tag1"); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(data, "tag1"); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(data, "tag2"); res == false {
		t.Errorf("IsDuplicate() = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(data, "tag1"); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(data, replay.EmptyTag); res == false {
		t.Errorf("IsDuplicate() = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}
}

func TestCapacity(t *testing.T) {
	cache := replay.NewCache(1, 1*time.Minute)
	a := make([]byte, 256)
	if _, err := crand.Read(a); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}
	b := make([]byte, 256)
	if _, err := crand.Read(b); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}

	if res := cache.IsDuplicate(a, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	if res := cache.IsDuplicate(a, replay.EmptyTag); res == false {
		t.Errorf("IsDuplicate() = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Errorf("cache sizes are %d %d, want 1 1.", curr, prev)
	}

	if res := cache.IsDuplicate(b, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Errorf("cache sizes are %d %d, want 1 1.", curr, prev)
	}

	cache.Clear()
	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 0 0.", curr, prev)
	}
}

func TestExpireInterval(t *testing.T) {
	cache := replay.NewCache(10, 100*time.Millisecond)
	a := make([]byte, 256)
	if _, err := crand.Read(a); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}
	b := make([]byte, 256)
	if _, err := crand.Read(b); err != nil {
		t.Fatalf("rand.Read() failed: %v", err)
	}

	if res := cache.IsDuplicate(a, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	time.Sleep(150 * time.Millisecond)

	if res := cache.IsDuplicate(a, replay.EmptyTag); res == false {
		t.Errorf("IsDuplicate() = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Errorf("cache sizes are %d %d, want 1 1.", curr, prev)
	}

	time.Sleep(200 * time.Millisecond)

	if res := cache.IsDuplicate(b, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}
}

// newDistinctData returns n distinct random byte slices.
func newDistinctData(t *testing.T, n int) [][]byte {
	t.Helper()
	res := make([][]byte, n)
	for i := range res {
		res[i] = make([]byte, 256)
		if _, err := crand.Read(res[i]); err != nil {
			t.Fatalf("rand.Read() failed: %v", err)
		}
	}
	return res
}

// TestCapacityRotation verifies the rolling window behavior of a cache with a
// capacity larger than one: exactly `capacity` distinct signatures fill the
// current map, the next distinct signature rotates the current map into the
// previous map, and the signatures of the previous map are still detected as
// duplicates.
func TestCapacityRotation(t *testing.T) {
	const capacity = 4
	cache := replay.NewCache(capacity, 1*time.Minute)
	sigs := newDistinctData(t, capacity+1)

	// The first `capacity` signatures exactly fill the current map. No rotation
	// happens yet.
	for i := 0; i < capacity; i++ {
		if res := cache.IsDuplicate(sigs[i], replay.EmptyTag); res == true {
			t.Fatalf("IsDuplicate(sig %d) = true, want false", i)
		}
		if curr, prev := cache.Sizes(); curr != i+1 || prev != 0 {
			t.Fatalf("cache sizes after %d inserts are %d %d, want %d 0.", i+1, curr, prev, i+1)
		}
	}

	// The (capacity+1)-th distinct signature rotates the current map into the
	// previous map and starts a new current map.
	if res := cache.IsDuplicate(sigs[capacity], replay.EmptyTag); res == true {
		t.Fatalf("IsDuplicate(sig %d) = true, want false", capacity)
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Fatalf("cache sizes after %d inserts are %d %d, want 1 %d.", capacity+1, curr, prev, capacity)
	}

	// Every signature of the rotated out map is still a duplicate. A lookup of a
	// previous map signature re-inserts it into the current map, which grows the
	// current map by one entry, so each signature is checked on a cache that was
	// rotated exactly once.
	for i := 0; i < capacity; i++ {
		fresh := replay.NewCache(capacity, 1*time.Minute)
		for j := 0; j <= capacity; j++ {
			if res := fresh.IsDuplicate(sigs[j], replay.EmptyTag); res == true {
				t.Fatalf("IsDuplicate(sig %d) = true, want false", j)
			}
		}
		if res := fresh.IsDuplicate(sigs[i], replay.EmptyTag); res == false {
			t.Errorf("IsDuplicate(sig %d) in the previous map = false, want true", i)
		}
		if curr, prev := fresh.Sizes(); curr != 2 || prev != capacity {
			t.Errorf("cache sizes after rechecking sig %d are %d %d, want 2 %d.", i, curr, prev, capacity)
		}
	}
}

// TestConcurrentIsDuplicate verifies that concurrent users of the same cache
// don't lose entries and don't judge duplicates inconsistently. Run with -race.
func TestConcurrentIsDuplicate(t *testing.T) {
	const (
		goroutines    = 8
		sigsPerWorker = 8
		total         = goroutines * sigsPerWorker
	)
	// The capacity is larger than the number of signatures, so the cache never
	// rotates and the number of live entries is deterministic.
	cache := replay.NewCache(2*total, 1*time.Minute)

	// The input is generated in the goroutine running the test, because t.Fatalf
	// may only be called from that goroutine.
	data := make([][][]byte, goroutines)
	for g := range data {
		data[g] = newDistinctData(t, sigsPerWorker)
	}

	// Phase 1: every worker inserts its own signatures. A signature seen for the
	// first time must never be judged as a duplicate.
	fresh := make([]int, goroutines)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for _, d := range data[g] {
				if cache.IsDuplicate(d, replay.EmptyTag) {
					fresh[g]++
				}
			}
		}(g)
	}
	wg.Wait()
	for g, n := range fresh {
		if n != 0 {
			t.Errorf("worker %d judged %d unknown signatures as duplicate.", g, n)
		}
	}
	if curr, prev := cache.Sizes(); curr != total || prev != 0 {
		t.Fatalf("cache sizes after concurrent inserts are %d %d, want %d 0.", curr, prev, total)
	}

	// Phase 2: every worker rechecks every signature of every worker. All of
	// them must be judged as duplicate, and looking up a known signature must
	// not change the cache.
	lost := make([]int, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for _, worker := range data {
				for _, d := range worker {
					if !cache.IsDuplicate(d, replay.EmptyTag) {
						lost[g]++
					}
				}
			}
		}(g)
	}
	wg.Wait()
	for g, n := range lost {
		if n != 0 {
			t.Errorf("worker %d missed %d of the cached signatures.", g, n)
		}
	}
	if curr, prev := cache.Sizes(); curr != total || prev != 0 {
		t.Errorf("cache sizes after concurrent lookups are %d %d, want %d 0.", curr, prev, total)
	}

	// Phase 3: exactly one worker can be the first to observe an unknown
	// signature, every other worker must see it as a duplicate.
	hot := replay.NewCache(2*total, 1*time.Minute)
	hotData := newDistinctData(t, 1)[0]
	seen := make([]bool, goroutines)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			seen[g] = hot.IsDuplicate(hotData, replay.EmptyTag)
		}(g)
	}
	wg.Wait()
	firstSeen := 0
	for _, isDup := range seen {
		if !isDup {
			firstSeen++
		}
	}
	if firstSeen != 1 {
		t.Errorf("%d workers observed the same signature for the first time, want 1.", firstSeen)
	}
	if curr, prev := hot.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes after concurrent duplicate check are %d %d, want 1 0.", curr, prev)
	}
}

// TestTagRetransmitAcrossRotation verifies the tag semantics of IsDuplicate when
// the signature has moved from the current map to the previous map: a
// retransmission carrying the same tag is accepted, while a different tag and an
// empty tag are judged as duplicate.
func TestTagRetransmitAcrossRotation(t *testing.T) {
	cache := replay.NewCache(2, 1*time.Minute)
	sigs := newDistinctData(t, 3)
	a, b, c := sigs[0], sigs[1], sigs[2]

	if res := cache.IsDuplicate(a, "tag1"); res == true {
		t.Fatalf("IsDuplicate() = true, want false")
	}
	if res := cache.IsDuplicate(b, "tag1"); res == true {
		t.Fatalf("IsDuplicate() = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 2 || prev != 0 {
		t.Fatalf("cache sizes are %d %d, want 2 0.", curr, prev)
	}

	// The current map is full, so this retransmission rotates it into the
	// previous map and re-inserts the signature into the current map.
	if res := cache.IsDuplicate(a, "tag1"); res == true {
		t.Errorf("IsDuplicate() with the same tag = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 2 {
		t.Errorf("cache sizes are %d %d, want 1 2.", curr, prev)
	}

	// The same payload sent with a different tag is a replay.
	if res := cache.IsDuplicate(a, "tag2"); res == false {
		t.Errorf("IsDuplicate() with a different tag = false, want true")
	}
	// An empty tag disables the retransmission exception.
	if res := cache.IsDuplicate(a, replay.EmptyTag); res == false {
		t.Errorf("IsDuplicate() with an empty tag = false, want true")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 2 {
		t.Errorf("cache sizes are %d %d, want 1 2.", curr, prev)
	}

	// The entry in the current map still carries tag1, so the retransmission is
	// accepted again.
	if res := cache.IsDuplicate(a, "tag1"); res == true {
		t.Errorf("IsDuplicate() with the same tag = true, want false")
	}

	// A different payload with the same tag is not a duplicate.
	if res := cache.IsDuplicate(c, "tag1"); res == true {
		t.Errorf("IsDuplicate() with a new payload = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 2 || prev != 2 {
		t.Errorf("cache sizes are %d %d, want 2 2.", curr, prev)
	}
}

// TestDisabledCache verifies that a cache without capacity, and a nil cache,
// accept every packet.
func TestDisabledCache(t *testing.T) {
	cache := replay.NewCache(0, 1*time.Minute)
	data := newDistinctData(t, 1)[0]
	for i := 0; i < 3; i++ {
		if res := cache.IsDuplicate(data, replay.EmptyTag); res == true {
			t.Errorf("IsDuplicate() with a disabled cache = true, want false")
		}
	}
	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 0 0.", curr, prev)
	}

	var nilCache *replay.ReplayCache
	if res := nilCache.IsDuplicate(data, replay.EmptyTag); res == true {
		t.Errorf("IsDuplicate() on a nil cache = true, want false")
	}
}
