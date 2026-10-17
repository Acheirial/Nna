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
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/replay"
)

// Every test uses a fixed capacity and a one minute expire interval, so that
// the cache can only be rotated by the operations the test performs. No test
// waits for the clock to advance.
const (
	testCapacity       = 8
	testExpireInterval = 1 * time.Minute
)

// TestSeenRetransmitWithSameTag verifies that a packet which was recorded with
// a tag is not judged as a replay when it is sent again from the very same tag,
// and that a lookup alone never records anything.
func TestSeenRetransmitWithSameTag(t *testing.T) {
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(testCapacity, testExpireInterval)
	data := newDistinctData(t, 1)[0]
	tag := tagOf(t, "192.0.2.10:40000")

	// Seen() is a read only lookup: an unknown packet is not a duplicate, and
	// the cache stays empty.
	if res := cache.Seen(domain, data, tag); res == true {
		t.Errorf("Seen() of an unknown packet = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Fatalf("cache sizes after a lookup are %d %d, want 0 0.", curr, prev)
	}

	cache.Record(domain, data, tag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Fatalf("cache sizes after Record() are %d %d, want 1 0.", curr, prev)
	}

	// The same content of the same tag is a retransmission, not a replay.
	for i := range 3 {
		if res := cache.Seen(domain, data, tag); res == true {
			t.Errorf("Seen() with the recorded tag (call %d) = true, want false", i+1)
		}
		if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
			t.Errorf("cache sizes (call %d) are %d %d, want 1 0.", i+1, curr, prev)
		}
	}
}

// TestSeenDifferentTagIsAlwaysReplay verifies that the same content of another
// tag is a replay on every call. The lookup used to promote the signature into
// the current map while storing the tag of the caller, so the second call of
// that caller was judged as a retransmission and was let through.
func TestSeenDifferentTagIsAlwaysReplay(t *testing.T) {
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(testCapacity, testExpireInterval)
	data := newDistinctData(t, 1)[0]
	legit := tagOf(t, "192.0.2.10:40000")
	attacker := tagOf(t, "198.51.100.7:40000")

	cache.Record(domain, data, legit)

	for i := range 3 {
		if res := cache.Seen(domain, data, attacker); res == false {
			t.Errorf("Seen() with a different tag (call %d) = false, want true", i+1)
		}
	}

	// The recorded tag survived the replay attempts, so the retransmission of
	// the legitimate tag is still accepted.
	if res := cache.Seen(domain, data, legit); res == true {
		t.Errorf("Seen() with the recorded tag = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}
}

// TestSeenDifferentTagInPreviousGeneration verifies the same property for a
// signature that was rotated out of the current maps, and that only Record()
// promotes it back.
func TestSeenDifferentTagInPreviousGeneration(t *testing.T) {
	const capacity = 2
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(capacity, testExpireInterval)
	sigs := newDistinctData(t, capacity+1)
	legit := tagOf(t, "192.0.2.10:40000")
	attacker := tagOf(t, "198.51.100.7:40000")

	cache.Record(domain, sigs[0], legit)
	cache.Record(domain, sigs[1], tagOf(t, "192.0.2.11:40000"))
	// The current maps are full, so this Record() rotates them into the
	// previous maps.
	cache.Record(domain, sigs[2], tagOf(t, "192.0.2.12:40000"))
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Fatalf("cache sizes are %d %d, want 1 %d.", curr, prev, capacity)
	}

	for i := range 3 {
		if res := cache.Seen(domain, sigs[0], attacker); res == false {
			t.Errorf("Seen() of a rotated out signature with a different tag (call %d) = false, want true", i+1)
		}
	}
	// The retransmission exception still works for the tag of the recorded
	// packet, which is stored in the previous map.
	if res := cache.Seen(domain, sigs[0], legit); res == true {
		t.Errorf("Seen() with the recorded tag in the previous map = true, want false")
	}
	// No lookup changed the cache.
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Errorf("cache sizes after the lookups are %d %d, want 1 %d.", curr, prev, capacity)
	}

	// Record() promotes the signature into the current map.
	cache.Record(domain, sigs[0], legit)
	if curr, prev := cache.Sizes(); curr != 2 || prev != capacity {
		t.Errorf("cache sizes after the promotion are %d %d, want 2 %d.", curr, prev, capacity)
	}
}

// TestSeenDomainIsolation verifies that the same content observed in two
// domains is not a replay of itself.
func TestSeenDomainIsolation(t *testing.T) {
	cache := replay.NewCache(testCapacity, testExpireInterval)
	data := newDistinctData(t, 1)[0]
	tag := tagOf(t, "192.0.2.10:40000")
	otherTag := tagOf(t, "192.0.2.11:40000")

	cache.Record(replay.DomainStream, data, tag)

	// The data is a duplicate in the domain it was recorded in.
	if res := cache.Seen(replay.DomainStream, data, otherTag); res == false {
		t.Errorf("Seen() in the recorded domain = false, want true")
	}
	// The same data of any other domain is unknown, with any tag.
	for _, domain := range []replay.Domain{replay.DomainPacketClientToServer, replay.DomainPacketServerToClient} {
		if res := cache.Seen(domain, data, otherTag); res == true {
			t.Errorf("Seen() in domain %d = true, want false", domain)
		}
		if res := cache.Seen(domain, data, tag); res == true {
			t.Errorf("Seen() in domain %d with the tag of the recorded data = true, want false", domain)
		}
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	// Recording the same content in a second domain adds a second entry.
	cache.Record(replay.DomainPacketClientToServer, data, tag)
	if curr, prev := cache.Sizes(); curr != 2 || prev != 0 {
		t.Errorf("cache sizes after the second domain are %d %d, want 2 0.", curr, prev)
	}
	if res := cache.Seen(replay.DomainPacketClientToServer, data, otherTag); res == false {
		t.Errorf("Seen() in the second domain = false, want true")
	}
}

// TestSeenZeroTag verifies that a zero tag never grants the retransmission
// exception, so any duplicate of a packet without tag is a replay.
func TestSeenZeroTag(t *testing.T) {
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(testCapacity, testExpireInterval)
	sigs := newDistinctData(t, 2)
	var noTag replay.Tag
	tagged := tagOf(t, "192.0.2.10:40000")

	cache.Record(domain, sigs[0], noTag)
	if res := cache.Seen(domain, sigs[0], noTag); res == false {
		t.Errorf("Seen() of a packet without tag = false, want true")
	}
	if res := cache.Seen(domain, sigs[0], tagged); res == false {
		t.Errorf("Seen() of a packet without tag, looked up with a tag = false, want true")
	}

	// A packet that was recorded with a tag is a duplicate as well when the
	// same content is looked up without a tag.
	cache.Record(domain, sigs[1], tagged)
	if res := cache.Seen(domain, sigs[1], noTag); res == false {
		t.Errorf("Seen() of a tagged packet without tag = false, want true")
	}
	if res := cache.Seen(domain, sigs[1], tagged); res == true {
		t.Errorf("Seen() with the recorded tag = true, want false")
	}
	if curr, prev := cache.Sizes(); curr != 2 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 2 0.", curr, prev)
	}
}

// TestCapacityRotation verifies the rolling window behavior of a cache with a
// capacity larger than one: exactly `capacity` distinct signatures fill the
// current map, the next distinct signature rotates the current map into the
// previous map, and the signatures of the previous map are still detected as
// duplicates.
func TestCapacityRotation(t *testing.T) {
	const capacity = 4
	domain := replay.DomainStream
	cache := replay.NewCache(capacity, testExpireInterval)
	sigs := newDistinctData(t, capacity+1)
	var noTag replay.Tag

	// The first `capacity` signatures exactly fill the current map. No rotation
	// happens yet.
	for i := range capacity {
		if res := cache.Seen(domain, sigs[i], noTag); res == true {
			t.Fatalf("Seen(sig %d) before Record() = true, want false", i)
		}
		cache.Record(domain, sigs[i], noTag)
		if res := cache.Seen(domain, sigs[i], noTag); res == false {
			t.Fatalf("Seen(sig %d) after Record() = false, want true", i)
		}
		if curr, prev := cache.Sizes(); curr != i+1 || prev != 0 {
			t.Fatalf("cache sizes after %d inserts are %d %d, want %d 0.", i+1, curr, prev, i+1)
		}
	}

	// The (capacity+1)-th distinct signature rotates the current map into the
	// previous map and starts a new current map.
	cache.Record(domain, sigs[capacity], noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Fatalf("cache sizes after %d inserts are %d %d, want 1 %d.", capacity+1, curr, prev, capacity)
	}

	// Every signature of the rotated out map is still detected. A lookup
	// doesn't promote a signature, so the sizes don't change.
	for i := range capacity {
		if res := cache.Seen(domain, sigs[i], noTag); res == false {
			t.Errorf("Seen(sig %d) in the previous map = false, want true", i)
		}
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != capacity {
		t.Errorf("cache sizes after the lookups are %d %d, want 1 %d.", curr, prev, capacity)
	}
}

// TestSeenDoesNotRotate verifies that a lookup neither records a signature nor
// rotates a cache whose current maps are already full.
func TestSeenDoesNotRotate(t *testing.T) {
	const capacity = 1
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(capacity, testExpireInterval)
	sigs := newDistinctData(t, 2)
	var noTag replay.Tag

	cache.Record(domain, sigs[0], noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Fatalf("cache sizes are %d %d, want 1 0.", curr, prev)
	}

	// The cache is full, but only Record() may rotate it.
	for i := range 3 {
		if res := cache.Seen(domain, sigs[0], noTag); res == false {
			t.Errorf("Seen() of the recorded signature (call %d) = false, want true", i+1)
		}
	}
	if curr, prev := cache.Sizes(); curr != 1 || prev != 0 {
		t.Errorf("cache sizes after the lookups are %d %d, want 1 0.", curr, prev)
	}

	cache.Record(domain, sigs[1], noTag)
	if curr, prev := cache.Sizes(); curr != 1 || prev != 1 {
		t.Errorf("cache sizes after the rotation are %d %d, want 1 1.", curr, prev)
	}
	if res := cache.Seen(domain, sigs[0], noTag); res == false {
		t.Errorf("Seen() of the rotated out signature = false, want true")
	}
}

// TestSizesAndClear verifies the reported sizes and that Clear() removes every
// entry and resets the rotation bookkeeping.
func TestSizesAndClear(t *testing.T) {
	const capacity = 2
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(capacity, testExpireInterval)
	sigs := newDistinctData(t, capacity)
	var noTag replay.Tag

	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Fatalf("cache sizes of a new cache are %d %d, want 0 0.", curr, prev)
	}
	for i := range sigs {
		cache.Record(domain, sigs[i], noTag)
		if curr, prev := cache.Sizes(); curr != i+1 || prev != 0 {
			t.Fatalf("cache sizes after %d inserts are %d %d, want %d 0.", i+1, curr, prev, i+1)
		}
	}
	for i := range sigs {
		if res := cache.Seen(domain, sigs[i], noTag); res == false {
			t.Fatalf("Seen(sig %d) = false, want true", i)
		}
	}
	if curr, prev := cache.Sizes(); curr != capacity || prev != 0 {
		t.Errorf("cache sizes after the lookups are %d %d, want %d 0.", curr, prev, capacity)
	}

	cache.Clear()
	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Errorf("cache sizes after Clear() are %d %d, want 0 0.", curr, prev)
	}
	for i := range sigs {
		if res := cache.Seen(domain, sigs[i], noTag); res == true {
			t.Errorf("Seen(sig %d) after Clear() = true, want false", i)
		}
	}
	// Clear() resets the counter, so the next inserts don't rotate the cache.
	for i := range sigs {
		cache.Record(domain, sigs[i], noTag)
		if curr, prev := cache.Sizes(); curr != i+1 || prev != 0 {
			t.Fatalf("cache sizes after %d inserts following Clear() are %d %d, want %d 0.", i+1, curr, prev, i+1)
		}
	}
}

// TestDisabledCache verifies that a cache without capacity, and a nil cache,
// accept every packet and store nothing.
func TestDisabledCache(t *testing.T) {
	domain := replay.DomainPacketClientToServer
	cache := replay.NewCache(0, testExpireInterval)
	data := newDistinctData(t, 1)[0]
	tag := tagOf(t, "192.0.2.10:40000")

	for range 3 {
		cache.Record(domain, data, tag)
		if res := cache.Seen(domain, data, tag); res == true {
			t.Errorf("Seen() with a disabled cache = true, want false")
		}
	}
	if curr, prev := cache.Sizes(); curr != 0 || prev != 0 {
		t.Errorf("cache sizes are %d %d, want 0 0.", curr, prev)
	}

	var nilCache *replay.ReplayCache
	nilCache.Record(domain, data, tag)
	if res := nilCache.Seen(domain, data, tag); res == true {
		t.Errorf("Seen() on a nil cache = true, want false")
	}
}

// TestConcurrentSeenAndRecord verifies that concurrent users of the same cache
// don't lose entries and don't judge a packet inconsistently. Run with -race.
func TestConcurrentSeenAndRecord(t *testing.T) {
	const (
		workers   = 8
		perWorker = 16
		total     = workers * perWorker
	)
	domain := replay.DomainPacketClientToServer
	// The capacity is larger than the number of signatures, so the cache never
	// rotates and the number of live entries is deterministic.
	cache := replay.NewCache(4*total, testExpireInterval)
	var noTag replay.Tag

	// The input is generated in the goroutine running the test, because t.Fatalf
	// may only be called from that goroutine.
	data := make([][][]byte, workers)
	for w := range data {
		data[w] = newDistinctData(t, perWorker)
	}

	// Every worker records its own signatures. A signature must not be a
	// duplicate before it is recorded, and must be a duplicate right after.
	early := make([]int, workers)
	lost := make([]int, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for _, d := range data[w] {
				if cache.Seen(domain, d, noTag) {
					early[w]++
				}
				cache.Record(domain, d, noTag)
				if !cache.Seen(domain, d, noTag) {
					lost[w]++
				}
			}
		}(w)
	}
	wg.Wait()
	for w := range workers {
		if early[w] != 0 {
			t.Errorf("worker %d judged %d unknown signatures as duplicate.", w, early[w])
		}
		if lost[w] != 0 {
			t.Errorf("worker %d missed %d of the recorded signatures.", w, lost[w])
		}
	}
	if curr, prev := cache.Sizes(); curr != total || prev != 0 {
		t.Errorf("cache sizes after concurrent inserts are %d %d, want %d 0.", curr, prev, total)
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

// tagOf returns the tag of the given address and port.
func tagOf(t *testing.T, addr string) replay.Tag {
	t.Helper()
	tag, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("netip.ParseAddrPort(%q) failed: %v", addr, err)
	}
	return tag
}
