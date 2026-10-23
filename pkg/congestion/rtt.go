// MIT License
//
// Copyright (c) 2016 the quic-go authors & Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package congestion

import (
	"math"
	"sync"
	"time"

	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
)

// The estimator of RFC 6298, Section 2.3: the smoothed RTT is updated with the
// weight alpha and the mean deviation with the weight beta.
const (
	rttAlpha          = 0.125
	oneMinusAlpha     = 1 - rttAlpha
	rttBeta           = 0.25
	oneMinusBeta      = 1 - rttBeta
	defaultInitialRTT = time.Second
	infDuration       = time.Duration(math.MaxInt64)

	// minRTO is the lower bound applied to the retransmission timeout computed
	// by RTO. RFC 6298, Section 2.4 rounds the RTO of TCP up to one second, but
	// that bound exists because TCP traditionally uses coarse grain clocks both
	// to measure the RTT and to run its retransmission timer. The timers here
	// are driven by a microsecond clock and belong to a single connection, so a
	// one second floor would only delay the recovery of a lost segment on the
	// low latency paths these sessions run on. 200 milliseconds stays an order
	// of magnitude above the round trip time of such paths, and above the
	// estimate plus four times its deviation, which is what keeps a spurious
	// retransmission from being armed.
	minRTO = 200 * time.Millisecond
)

// RTTStats provides round-trip statistics
type RTTStats struct {
	// hasMeasurement is true once the first valid RTT sample is recorded.
	// While it is false the estimators hold no measurement: UpdateRTT seeds
	// them with the first sample, and SetInitialRTT is allowed.
	hasMeasurement bool

	latestRTT     time.Duration
	smoothedRTT   time.Duration
	meanDeviation time.Duration

	maxAckDelay   time.Duration
	rtoMultiplier float64

	// mu is required to access the RTT stats.
	mu sync.RWMutex
}

// NewRTTStats makes a properly initialized RTTStats object
func NewRTTStats() *RTTStats {
	return &RTTStats{
		rtoMultiplier: 1.0,
	}
}

// LatestRTT returns the most recent rtt measurement.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) LatestRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latestRTT
}

// SmoothedRTT returns the smoothed RTT for the connection.
// May return Zero if no valid updates have occurred.
func (r *RTTStats) SmoothedRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.smoothedRTT
}

// MeanDeviation gets the mean deviation
func (r *RTTStats) MeanDeviation() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.meanDeviation
}

// MaxAckDelay gets the max_ack_delay advertised by the peer
func (r *RTTStats) MaxAckDelay() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.maxAckDelay
}

// RTO gets the retransmission timeout.
func (r *RTTStats) RTO() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// mu is already held for reading, so the fields are read directly instead
	// of calling the getters, which would acquire the lock again.
	if r.smoothedRTT == 0 {
		// Without a measurement the conservative initial timeout is used. It is
		// above minRTO by construction.
		return 2 * defaultInitialRTT
	}
	rto := r.smoothedRTT + mathext.Max(4*r.meanDeviation, 10*time.Millisecond)
	rto += r.maxAckDelay
	rto = time.Duration(float64(rto) * r.rtoMultiplier)
	// The lower bound is applied last, so that neither a small estimate nor a
	// small multiplier can arm the timer below minRTO.
	if rto < minRTO {
		rto = minRTO
	}
	return rto
}

// UpdateRTT updates the RTT based on a new sample.
func (r *RTTStats) UpdateRTT(sample time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sample == infDuration || sample <= 0 {
		return
	}

	r.latestRTT = sample
	if !r.hasMeasurement {
		r.hasMeasurement = true
		r.smoothedRTT = sample
		r.meanDeviation = sample / 2
	} else {
		r.meanDeviation = time.Duration(oneMinusBeta*float32(r.meanDeviation/time.Microsecond)+rttBeta*float32(mathext.Abs(r.smoothedRTT-sample)/time.Microsecond)) * time.Microsecond
		r.smoothedRTT = time.Duration((float32(r.smoothedRTT/time.Microsecond)*oneMinusAlpha)+(float32(sample/time.Microsecond)*rttAlpha)) * time.Microsecond
	}
}

// SetMaxAckDelay sets the max_ack_delay
func (r *RTTStats) SetMaxAckDelay(mad time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.maxAckDelay = mad
}

// SetRTOMultiplier sets the retransmission timeout multiplier.
func (r *RTTStats) SetRTOMultiplier(n float64) {
	if n <= 0 {
		panic("retransmission timeout multiplier must be greater than 0")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rtoMultiplier = n
}

// SetInitialRTT sets the initial RTT.
// It is used during the 0-RTT handshake when restoring the RTT stats from the session state.
// It may be called as long as no measurement is recorded, which includes the state
// right after Reset. The value is a guess only: the first sample passed to UpdateRTT
// seeds the estimators and replaces it.
func (r *RTTStats) SetInitialRTT(t time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.hasMeasurement {
		panic("initial RTT set after first measurement")
	}
	r.smoothedRTT = t
	r.latestRTT = t
}

// Reset is called when connection migrates and rtt measurement needs to be reset.
// It restores the state of a newly created RTTStats: every RTT estimate is cleared
// and the stats are marked as having no measurement, so that the next valid sample
// seeds the estimators again (smoothed RTT = the sample, mean deviation = the
// sample / 2) instead of being blended with the cleared values.
// The connection level max_ack_delay and the RTO multiplier are preserved, and
// SetInitialRTT may be called again on the reset stats.
func (r *RTTStats) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.hasMeasurement = false
	r.latestRTT = 0
	r.smoothedRTT = 0
	r.meanDeviation = 0
}
