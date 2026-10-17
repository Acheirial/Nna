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
// smoothing coefficients: every sample is reflected in LatestRTT, the smoothed
// RTT stays inside the range of the samples seen so far, the first valid sample
// seeds the estimators, and an unmeasurable sample changes nothing.
func TestUpdateRTT(t *testing.T) {
	s := NewRTTStats()
	if s.LatestRTT() != 0 || s.SmoothedRTT() != 0 || s.MeanDeviation() != 0 {
		t.Fatalf("new stats are not zeroed: latest=%v smoothed=%v deviation=%v", s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
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
	latestBefore, smoothedBefore, devBefore := s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation()
	for _, invalid := range []time.Duration{0, -1 * time.Millisecond, infDuration} {
		s.UpdateRTT(invalid)
		if s.LatestRTT() != latestBefore || s.SmoothedRTT() != smoothedBefore || s.MeanDeviation() != devBefore {
			t.Errorf("UpdateRTT(%v) changed the stats: latest=%v smoothed=%v deviation=%v", invalid, s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
		}
	}
}

// TestUpdateRTTEstimator verifies the numbers of the estimator of RFC 6298,
// Section 2.3, which updates the estimates with
//
//	SRTT   <- (1 - alpha) * SRTT + alpha * R
//	RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R|
//
// where alpha = 0.125, beta = 0.25 and the first sample seeds SRTT = R and
// RTTVAR = R / 2. The expected values are computed by hand and compared with a
// tolerance of one microsecond, because UpdateRTT keeps each estimate as a whole
// number of microseconds.
func TestUpdateRTTEstimator(t *testing.T) {
	const tolerance = time.Microsecond

	tests := []struct {
		name      string
		samples   []time.Duration
		smoothed  time.Duration
		deviation time.Duration
		rto       time.Duration
	}{
		{
			name:      "first sample seeds the estimators",
			samples:   []time.Duration{300 * time.Millisecond},
			smoothed:  300 * time.Millisecond,
			deviation: 150 * time.Millisecond,
			rto:       900 * time.Millisecond,
		},
		{
			// SRTT = 0.875*300ms + 0.125*100ms = 275ms
			// RTTVAR = 0.75*150ms + 0.25*|300ms-100ms| = 162.5ms
			// RTO = 275ms + 4*162.5ms
			name:      "a smaller sample pulls both estimates down",
			samples:   []time.Duration{300 * time.Millisecond, 100 * time.Millisecond},
			smoothed:  275 * time.Millisecond,
			deviation: 162500 * time.Microsecond,
			rto:       925 * time.Millisecond,
		},
		{
			// SRTT = 0.875*275ms + 0.125*500ms = 303.125ms
			// RTTVAR = 0.75*162.5ms + 0.25*|275ms-500ms| = 178.125ms
			name:      "a bigger sample pushes both estimates up",
			samples:   []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond},
			smoothed:  303125 * time.Microsecond,
			deviation: 178125 * time.Microsecond,
			rto:       1015625 * time.Microsecond,
		},
		{
			// SRTT = 0.875*303.125ms + 0.125*250ms = 296484.375us
			// RTTVAR = 0.75*178.125ms + 0.25*|303.125ms-250ms| = 146.875ms
			name:      "the deviation reacts faster than the average",
			samples:   []time.Duration{300 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond, 250 * time.Millisecond},
			smoothed:  296484375 * time.Nanosecond,
			deviation: 146875 * time.Microsecond,
			rto:       883984 * time.Microsecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewRTTStats()
			for _, sample := range tc.samples {
				s.UpdateRTT(sample)
			}
			if got := s.LatestRTT(); got != tc.samples[len(tc.samples)-1] {
				t.Errorf("LatestRTT() = %v, want %v", got, tc.samples[len(tc.samples)-1])
			}
			if got := s.SmoothedRTT(); got < tc.smoothed-tolerance || got > tc.smoothed+tolerance {
				t.Errorf("SmoothedRTT() = %v, want %v", got, tc.smoothed)
			}
			if got := s.MeanDeviation(); got < tc.deviation-tolerance || got > tc.deviation+tolerance {
				t.Errorf("MeanDeviation() = %v, want %v", got, tc.deviation)
			}
			if got := s.RTO(); got != tc.rto {
				t.Errorf("RTO() = %v, want %v", got, tc.rto)
			}
		})
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
		for range n {
			s.UpdateRTT(sample)
		}
		if got := s.SmoothedRTT(); got != sample {
			t.Errorf("SmoothedRTT() after %d identical samples = %v, want %v", n, got, sample)
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
		for i := range n {
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
	// SmoothedRTT is 279652us and MeanDeviation is 128193us after the sample
	// sequence above, so the RTO is 279652us + 4*128193us + 2s.
	if got, want := s.RTO(), 2792424*time.Microsecond; got != want {
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
	if got, want := noAckDelay.RTO(), 792424*time.Microsecond; got != want {
		t.Errorf("RTO() without ack delay = %v, want %v", got, want)
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
	if s.LatestRTT() != 0 || s.SmoothedRTT() != 0 || s.MeanDeviation() != 0 {
		t.Errorf("stats after Reset() are latest=%v smoothed=%v deviation=%v, want all zero", s.LatestRTT(), s.SmoothedRTT(), s.MeanDeviation())
	}
	if got, want := s.RTO(), 2*defaultInitialRTT; got != want {
		t.Errorf("RTO() after Reset() = %v, want %v", got, want)
	}
}

// TestRTOMinimum verifies that the RTO is clamped to minRTO. The clamp is what
// keeps a short estimate from arming a retransmission timer that fires before a
// lost segment could possibly have been acknowledged.
func TestRTOMinimum(t *testing.T) {
	tests := []struct {
		name        string
		samples     []time.Duration
		maxAckDelay time.Duration
		multiplier  float64
		wantRTO     time.Duration
		wantClamped bool
	}{
		{
			// A single 10ms sample gives 10ms + 4*5ms = 30ms.
			name:        "a short estimate is clamped",
			samples:     []time.Duration{10 * time.Millisecond},
			multiplier:  1,
			wantRTO:     minRTO,
			wantClamped: true,
		},
		{
			// 60ms + 4*30ms = 180ms is just below the bound.
			name:        "an estimate just below the bound is clamped",
			samples:     []time.Duration{60 * time.Millisecond},
			multiplier:  1,
			wantRTO:     minRTO,
			wantClamped: true,
		},
		{
			// The ack delay is part of the value that gets clamped.
			name:        "the ack delay is included before the clamp",
			samples:     []time.Duration{50 * time.Millisecond},
			maxAckDelay: 25 * time.Millisecond,
			multiplier:  1,
			wantRTO:     minRTO,
			wantClamped: true,
		},
		{
			// 100ms + 4*50ms = 300ms.
			name:       "an estimate above the bound is not clamped",
			samples:    []time.Duration{100 * time.Millisecond},
			multiplier: 1,
			wantRTO:    300 * time.Millisecond,
		},
		{
			// The bound is applied after the multiplier, so a small multiplier
			// can't arm a timer below it either.
			name:        "a small multiplier is clamped",
			samples:     []time.Duration{100 * time.Millisecond},
			multiplier:  0.5,
			wantRTO:     minRTO,
			wantClamped: true,
		},
		{
			// 300ms + 4*150ms = 900ms, doubled by the multiplier.
			name:       "a large multiplier scales the value",
			samples:    []time.Duration{300 * time.Millisecond},
			multiplier: 2,
			wantRTO:    1800 * time.Millisecond,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewRTTStats()
			s.SetMaxAckDelay(tc.maxAckDelay)
			for _, sample := range tc.samples {
				s.UpdateRTT(sample)
			}
			s.SetRTOMultiplier(tc.multiplier)
			if got := s.RTO(); got != tc.wantRTO {
				t.Errorf("RTO() = %v, want %v", got, tc.wantRTO)
			}
			if got := s.RTO() == minRTO; got != tc.wantClamped {
				t.Errorf("RTO() == minRTO is %v, want %v", got, tc.wantClamped)
			}
		})
	}
}

// TestRTTStateTransitions verifies SetInitialRTT, the setter guards and the
// reset that a connection migration performs.
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
	// Without a deviation the estimate is 150ms + 10ms, which minRTO clamps up.
	if got := restored.RTO(); got != minRTO {
		t.Errorf("RTO() after SetInitialRTT() = %v, want %v", got, minRTO)
	}

	// The setters reject values that would corrupt the stats.
	const maxAckDelay = 25 * time.Millisecond
	s := NewRTTStats()
	s.SetMaxAckDelay(maxAckDelay)
	s.SetRTOMultiplier(2)
	for _, sample := range rttSamples {
		s.UpdateRTT(sample)
	}
	mustPanic(t, "SetInitialRTT", func() { s.SetInitialRTT(initial) })
	mustPanic(t, "SetRTOMultiplier", func() { s.SetRTOMultiplier(0) })
	mustPanic(t, "SetRTOMultiplier", func() { s.SetRTOMultiplier(-1) })

	// Reset drops the measurement, so the next sample seeds the estimators
	// again instead of blending them with the cleared values, and SetInitialRTT
	// is allowed again. The connection level settings are kept.
	s.Reset()
	s.SetInitialRTT(initial)
	if got := s.SmoothedRTT(); got != initial {
		t.Errorf("SmoothedRTT() after Reset() and SetInitialRTT() = %v, want %v", got, initial)
	}
	s.UpdateRTT(400 * time.Millisecond)
	if got := s.SmoothedRTT(); got != 400*time.Millisecond {
		t.Errorf("SmoothedRTT() after the first sample following Reset() = %v, want %v", got, 400*time.Millisecond)
	}
	if got := s.MeanDeviation(); got != 200*time.Millisecond {
		t.Errorf("MeanDeviation() after the first sample following Reset() = %v, want %v", got, 200*time.Millisecond)
	}
	// 400ms + 4*200ms + maxAckDelay, doubled by the multiplier that survived
	// the reset.
	wantRTO := 2 * (400*time.Millisecond + 4*200*time.Millisecond + maxAckDelay)
	if got := s.RTO(); got != wantRTO {
		t.Errorf("RTO() after Reset() = %v, want %v", got, wantRTO)
	}
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
	for g := range goroutines {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := range iterations {
				s.UpdateRTT(samples[(g+i)%len(samples)])
			}
		}(g)
	}
	// A concurrent reader must not observe a torn or out of range value. The
	// RTO of an estimate that is still being seeded is bounded by the largest
	// sample plus four times the largest deviation.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range iterations {
			if rto := s.RTO(); rto < minRTO || rto > 5*maxSample {
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
