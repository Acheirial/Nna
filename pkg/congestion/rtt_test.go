// Copyright (C) 2023  mieru authors
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

package congestion

import (
	"sync"
	"testing"
	"time"
)

// rttSamples is the sample sequence used by the tests below. All values are
// whole milliseconds below one second, so the float32 arithmetic in UpdateRTT is
// exact and the invariants asserted here are not perturbed by rounding.
var rttSamples = []time.Duration{
	300 * time.Millisecond,
	200 * time.Millisecond,
	250 * time.Millisecond,
	120 * time.Millisecond,
	400 * time.Millisecond,
}

// mustPanic runs f and fails the test if f returns without panicking.
func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("%s() did not panic", name)
		}
	}()
	f()
}

// TestUpdateRTT verifies the contract of the estimators instead of their current
// smoothing coefficients: every sample is reflected in LatestRTT and MinRTT, the
// smoothed RTT stays inside the range of the samples seen so far, the first
// valid sample seeds the estimators, and an unmeasurable sample changes nothing.
func TestUpdateRTT(t *testing.T) {
	s := NewRTTStats()
	if s.MinRTT() != 0 || s.LatestRTT() != 0 || s.SmoothedRTT() != 0 || s.MeanDeviation() != 0 {
		t.Fatalf("new stats are not zeroed: min=%v latest=%v smoothed=%v deviation=%v", s.MinRTT(), s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
	}

	minSample, maxSample := rttSamples[0], rttSamples[0]
	for i, sample := range rttSamples {
		s.UpdateRTT(sample)
		if sample < minSample {
			minSample = sample
		}
		if sample > maxSample {
			maxSample = sample
		}

		if got := s.LatestRTT(); got != sample {
			t.Errorf("LatestRTT() after sample %d = %v, want %v", i, got, sample)
		}
		if got := s.MinRTT(); got != minSample {
			t.Errorf("MinRTT() after sample %d = %v, want %v", i, got, minSample)
		}
		// The smoothed RTT is a weighted average of the samples seen so far, so
		// it can't leave the observed range. A wrong blend weight, a missing
		// seed of the first sample, or an accumulating sum breaks this.
		if got := s.SmoothedRTT(); got < minSample || got > maxSample {
			t.Errorf("SmoothedRTT() after sample %d = %v, want in [%v, %v]", i, got, minSample, maxSample)
		}
		if got := s.MeanDeviation(); got < 0 || got > maxSample {
			t.Errorf("MeanDeviation() after sample %d = %v, want in [0, %v]", i, got, maxSample)
		}
		if i == 0 {
			if got := s.SmoothedRTT(); got != sample {
				t.Errorf("SmoothedRTT() after the first sample = %v, want %v", got, sample)
			}
			if got := s.MeanDeviation(); got != sample/2 {
				t.Errorf("MeanDeviation() after the first sample = %v, want %v", got, sample/2)
			}
		}
	}

	// Zero, negative and infinite samples are not measurements.
	minBefore, latestBefore := s.MinRTT(), s.LatestRTT()
	smoothedBefore, devBefore := s.SmoothedRTT(), s.MeanDeviation()
	for _, invalid := range []time.Duration{0, -1 * time.Millisecond, infDuration} {
		s.UpdateRTT(invalid)
		if s.MinRTT() != minBefore || s.LatestRTT() != latestBefore || s.SmoothedRTT() != smoothedBefore || s.MeanDeviation() != devBefore {
			t.Errorf("UpdateRTT(%v) changed the stats: min=%v latest=%v smoothed=%v deviation=%v", invalid, s.MinRTT(), s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
		}
	}
}

// TestUpdateRTTResponse verifies that the smoothed RTT follows the direction of
// the samples, which catches reversed or dropped smoothing weights.
func TestUpdateRTTResponse(t *testing.T) {
	s := NewRTTStats()
	s.UpdateRTT(300 * time.Millisecond)
	start := s.SmoothedRTT()

	s.UpdateRTT(200 * time.Millisecond)
	lower := s.SmoothedRTT()
	if lower >= start {
		t.Errorf("SmoothedRTT() after a smaller sample = %v, want < %v", lower, start)
	}
	if lower < 200*time.Millisecond || lower > 300*time.Millisecond {
		t.Errorf("SmoothedRTT() after a smaller sample = %v, want in [200ms, 300ms]", lower)
	}

	s.UpdateRTT(600 * time.Millisecond)
	higher := s.SmoothedRTT()
	if higher <= lower {
		t.Errorf("SmoothedRTT() after a bigger sample = %v, want > %v", higher, lower)
	}
	if higher < 200*time.Millisecond || higher > 600*time.Millisecond {
		t.Errorf("SmoothedRTT() after a bigger sample = %v, want in [200ms, 600ms]", higher)
	}
}

// TestUpdateRTTSampleCountInvariance verifies that the estimates stay bounded by
// the samples no matter how many samples are fed in, and that feeding one value
// repeatedly keeps the smoothed RTT at that value. Both fail if the smoothing
// weights are wrong or if the implementation accumulates samples instead of
// smoothing them.
func TestUpdateRTTSampleCountInvariance(t *testing.T) {
	const sample = 333 * time.Millisecond
	for _, n := range []int{1, 2, 10, 1000} {
		s := NewRTTStats()
		for i := 0; i < n; i++ {
			s.UpdateRTT(sample)
		}
		if got := s.SmoothedRTT(); got != sample {
			t.Errorf("SmoothedRTT() after %d identical samples = %v, want %v", n, got, sample)
		}
		if got := s.MinRTT(); got != sample {
			t.Errorf("MinRTT() after %d identical samples = %v, want %v", n, got, sample)
		}
		if got := s.LatestRTT(); got != sample {
			t.Errorf("LatestRTT() after %d identical samples = %v, want %v", n, got, sample)
		}
		if got := s.MeanDeviation(); got < 0 || got > sample/2 {
			t.Errorf("MeanDeviation() after %d identical samples = %v, want in [0, %v]", n, got, sample/2)
		}
	}

	// All samples are within [1ms, bound], so the estimates can't grow with the
	// number of samples: SmoothedRTT and MeanDeviation stay <= bound, hence the
	// deviation term of the RTO is at most 4*bound, and the RTO is at most
	// 5*bound.
	const bound = 1 * time.Second
	for _, n := range []int{1, 10, 10000} {
		s := NewRTTStats()
		for i := 0; i < n; i++ {
			s.UpdateRTT(bound - time.Duration(i%1000)*time.Millisecond)
		}
		if got := s.SmoothedRTT(); got > bound {
			t.Errorf("SmoothedRTT() after %d samples <= %v = %v, want <= %v", n, bound, got, bound)
		}
		if got := s.MeanDeviation(); got > bound {
			t.Errorf("MeanDeviation() after %d samples <= %v = %v, want <= %v", n, bound, got, bound)
		}
		if got := s.RTO(); got > 5*bound {
			t.Errorf("RTO() after %d samples <= %v = %v, want <= %v", n, bound, got, 5*bound)
		}
	}
}

// TestRTO verifies the RTO contract: the fallback value without a measurement,
// the lower bound derived from the smoothed RTT, the scale with the retransmit
// multiplier, and the fact that the ack delay is added on top.
func TestRTO(t *testing.T) {
	s := NewRTTStats()
	if got, want := s.RTO(), 2*defaultInitialRTT; got != want {
		t.Errorf("RTO() without measurement = %v, want %v", got, want)
	}

	const maxAckDelay = 2 * time.Second
	s.SetMaxAckDelay(maxAckDelay)
	for _, sample := range rttSamples {
		s.UpdateRTT(sample)
	}
	smoothed, deviation := s.SmoothedRTT(), s.MeanDeviation()
	maxSample := rttSamples[0]
	for _, sample := range rttSamples {
		if sample > maxSample {
			maxSample = sample
		}
	}
	if deviation <= 0 {
		t.Fatalf("MeanDeviation() = %v, want > 0", deviation)
	}
	// The deviation of these samples is far above the minimum term of the RTO,
	// so the RTO is the smoothed RTT plus 4 mean deviations plus the ack delay.
	want := smoothed + 4*deviation + maxAckDelay
	if got := s.RTO(); got != want {
		t.Errorf("RTO() = %v, want %v", got, want)
	}
	if got := s.RTO(); got <= smoothed+maxAckDelay {
		t.Errorf("RTO() = %v, want > %v", got, smoothed+maxAckDelay)
	}
	// SmoothedRTT and MeanDeviation are bounded by the samples, so the RTO is
	// too.
	if got := s.RTO(); got > maxSample+4*maxSample+maxAckDelay {
		t.Errorf("RTO() = %v, want <= %v", got, maxSample+4*maxSample+maxAckDelay)
	}

	// The ack delay is added on top of the computed timeout.
	noAckDelay := NewRTTStats()
	for _, sample := range rttSamples {
		noAckDelay.UpdateRTT(sample)
	}
	if got, want := s.RTO()-noAckDelay.RTO(), maxAckDelay; got != want {
		t.Errorf("RTO() difference with and without ack delay = %v, want %v", got, want)
	}

	// The RTO scales with the multiplier.
	doubled := NewRTTStats()
	doubled.SetMaxAckDelay(maxAckDelay)
	for _, sample := range rttSamples {
		doubled.UpdateRTT(sample)
	}
	doubled.SetRTOMultiplier(2)
	if got, want := doubled.RTO(), 2*s.RTO(); got != want {
		t.Errorf("RTO() with multiplier 2 = %v, want %v", got, want)
	}

	// A reset drops the measurement and restores the fallback RTO.
	s.Reset()
	if s.MinRTT() != 0 || s.LatestRTT() != 0 || s.SmoothedRTT() != 0 || s.MeanDeviation() != 0 {
		t.Errorf("stats after Reset() are min=%v latest=%v smoothed=%v deviation=%v, want all zero", s.MinRTT(), s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
	}
	if got, want := s.RTO(), 2*defaultInitialRTT; got != want {
		t.Errorf("RTO() after Reset() = %v, want %v", got, want)
	}
}

// TestRTTStateTransitions verifies SetInitialRTT, ExpireSmoothedMetrics and the
// guards of the setters.
func TestRTTStateTransitions(t *testing.T) {
	// SetInitialRTT seeds the estimators before the first measurement.
	const initial = 150 * time.Millisecond
	restored := NewRTTStats()
	restored.SetInitialRTT(initial)
	if got := restored.SmoothedRTT(); got != initial {
		t.Errorf("SmoothedRTT() after SetInitialRTT() = %v, want %v", got, initial)
	}
	if got := restored.LatestRTT(); got != initial {
		t.Errorf("LatestRTT() after SetInitialRTT() = %v, want %v", got, initial)
	}
	if got := restored.RTO(); got <= initial {
		t.Errorf("RTO() after SetInitialRTT() = %v, want > %v", got, initial)
	}

	// ExpireSmoothedMetrics only moves the estimates towards the latest sample.
	s := NewRTTStats()
	for _, sample := range rttSamples {
		s.UpdateRTT(sample)
	}
	smoothed, deviation, latest := s.SmoothedRTT(), s.MeanDeviation(), s.LatestRTT()
	diff := smoothed - latest
	if diff < 0 {
		diff = -diff
	}
	s.ExpireSmoothedMetrics()
	if got := s.SmoothedRTT(); got < smoothed || got < latest {
		t.Errorf("SmoothedRTT() after ExpireSmoothedMetrics() = %v, want >= %v and >= %v", got, smoothed, latest)
	}
	if got := s.MeanDeviation(); got < deviation || got < diff {
		t.Errorf("MeanDeviation() after ExpireSmoothedMetrics() = %v, want >= %v and >= %v", got, deviation, diff)
	}

	// The setters reject values that would corrupt the stats.
	mustPanic(t, "SetInitialRTT", func() { s.SetInitialRTT(initial) })
	mustPanic(t, "SetRTOMultiplier", func() { s.SetRTOMultiplier(0) })
	mustPanic(t, "SetRTOMultiplier", func() { s.SetRTOMultiplier(-1) })
}

// TestUpdateRTTConcurrent verifies that concurrent updates and reads are
// serialized and leave the stats inside the range of the fed samples. Run with
// -race.
func TestUpdateRTTConcurrent(t *testing.T) {
	const (
		goroutines = 8
		iterations = 2000
	)
	samples := []time.Duration{
		50 * time.Millisecond,
		120 * time.Millisecond,
		300 * time.Millisecond,
		800 * time.Millisecond,
	}
	minSample, maxSample := samples[0], samples[0]
	for _, sample := range samples {
		if sample < minSample {
			minSample = sample
		}
		if sample > maxSample {
			maxSample = sample
		}
	}

	s := NewRTTStats()
	bad := make([]int, goroutines+1)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				s.UpdateRTT(samples[(g+i)%len(samples)])
			}
		}(g)
	}
	// A concurrent reader must not observe a torn or out of range value. The
	// fallback RTO of 2 seconds also fits in the range checked below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if rto := s.RTO(); rto < minSample || rto > 5*maxSample {
				bad[goroutines]++
			}
		}
	}()
	wg.Wait()

	for g, n := range bad {
		if n != 0 {
			t.Errorf("worker %d observed %d out of range values.", g, n)
		}
	}
	// Every value of the sample set is fed at least once, so the minimum is
	// known exactly.
	if got := s.MinRTT(); got != minSample {
		t.Errorf("MinRTT() = %v, want %v", got, minSample)
	}
	if got := s.LatestRTT(); got < minSample || got > maxSample {
		t.Errorf("LatestRTT() = %v, want in [%v, %v]", got, minSample, maxSample)
	}
	if got := s.SmoothedRTT(); got < minSample || got > maxSample {
		t.Errorf("SmoothedRTT() = %v, want in [%v, %v]", got, minSample, maxSample)
	}
	if got := s.MeanDeviation(); got < 0 || got > maxSample {
		t.Errorf("MeanDeviation() = %v, want in [0, %v]", got, maxSample)
	}
	if got := s.RTO(); got < s.SmoothedRTT() || got > 5*maxSample {
		t.Errorf("RTO() = %v, want in [%v, %v]", got, s.SmoothedRTT(), 5*maxSample)
	}
}
