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
	"math"
	"sync"
	"time"
)

type cubicOperationMode int

const (
	cubicSlowStart cubicOperationMode = iota
	cubicNormal
)

// CUBIC parameters defined by RFC 8312.
const (
	// cubicBeta is beta_cubic, the multiplicative decrease factor applied to
	// the congestion window after a congestion event detected by duplicate
	// acknowledgements (RFC 8312, Section 4.5).
	cubicBeta float64 = 0.7
	// cubicC scales the aggressiveness of the window increase function
	// (RFC 8312, Section 4.1, Eq. 1 and Section 5.2).
	cubicC float64 = 0.4
	// cubicAIMDAlpha is the additive increase factor of the AIMD flow that
	// W_est emulates: alpha_aimd = 3*(1-beta_cubic)/(1+beta_cubic)
	// (RFC 8312, Section 4.2, Eq. 3 and Eq. 4).
	cubicAIMDAlpha float64 = 3 * (1 - cubicBeta) / (1 + cubicBeta)
	// timeoutSsthreshDivisor converts the congestion window into the slow start
	// threshold used after a retransmission timeout. RFC 8312, Section 4.7
	// keeps the window reduction of standard TCP (RFC 5681, Section 3.1), which
	// sets ssthresh to max(FlightSize / 2, 2 * SMSS); minWindowSize plays the
	// role of the floor of two maximum sized segments.
	timeoutSsthreshDivisor uint32 = 2
)

// CubicSendAlgorithm implements cubic congestion algorithm.
type CubicSendAlgorithm struct {
	minWindowSize uint32
	maxWindowSize uint32
	mode          cubicOperationMode
	// congestionWindow is cwnd, the number of segments allowed in flight.
	congestionWindow uint32
	// ssthresh is the slow start threshold. RFC 8312, Section 4.8 requires a
	// slow start phase while cwnd <= ssthresh, so growing past it moves the
	// algorithm to congestion avoidance.
	ssthresh uint32
	// windowSizeBeforeLastReduction is W_max of RFC 8312, Section 4.1: the
	// congestion window just before the last congestion event.
	windowSizeBeforeLastReduction uint32
	// epochK is K of RFC 8312, Section 4.1, Eq. 2, precomputed when the current
	// congestion avoidance epoch starts and constant for its lifetime.
	// RFC 8312, Section 4.7 sets K to 0 for the first congestion avoidance
	// period after a timeout, where no W_max is available.
	epochK float64
	// epochStart is the start of the current congestion avoidance epoch, in
	// seconds since the Unix epoch. t of Eq. 1 and Eq. 4 is the time elapsed
	// since this instant.
	epochStart float64
	// lastRTT is the most recent RTT estimate passed to OnAck.
	lastRTT time.Duration
	// now returns the current time. It is a field so that tests can drive the
	// window increase with a deterministic clock.
	now func() time.Time
	mu  sync.RWMutex
}

// NewCubicSendAlgorithm initializes a new CubicSendAlgorithm.
func NewCubicSendAlgorithm(minWindowSize, maxWindowSize uint32) *CubicSendAlgorithm {
	if minWindowSize > maxWindowSize {
		panic("minimum congestion window size is greater than maximum congestion window size")
	}
	return &CubicSendAlgorithm{
		minWindowSize:    minWindowSize,
		maxWindowSize:    maxWindowSize,
		mode:             cubicSlowStart,
		congestionWindow: minWindowSize,
		// No congestion event happened yet, so slow start is only limited by
		// the configured maximum window, which is the capacity of this flow.
		ssthresh: maxWindowSize,
		now:      time.Now,
	}
}

// CongestionWindowSize returns the currect congestion window size.
func (c *CubicSendAlgorithm) CongestionWindowSize() uint32 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.congestionWindow
}

// InSlowStart returns if cubic is in slow start mode.
func (c *CubicSendAlgorithm) InSlowStart() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.mode == cubicSlowStart
}

// OnAck updates the congestion window size from the received acknowledge.
// rtt is the RTT estimate of the connection, the weighted average RTT of
// RFC 8312, Section 4.1. A non-positive value means that no measurement is
// available: the last estimate is reused and defaultInitialRTT is the fallback
// of last resort, so that the TCP-friendly estimate of Eq. 4 stays finite.
func (c *CubicSendAlgorithm) OnAck(rtt time.Duration) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if rtt <= 0 {
		rtt = c.lastRTT
	}
	if rtt <= 0 {
		rtt = defaultInitialRTT
	}
	c.lastRTT = rtt

	if c.mode == cubicSlowStart {
		// RFC 8312, Section 4.8 mandates a slow start phase while the window is
		// at or below the slow start threshold. Standard TCP slow start
		// (RFC 5681, Section 3.1) increases the window by one segment per
		// acknowledged segment.
		c.congestionWindow++
		// The clamp runs before the comparison below, so the epoch described
		// there starts from the window the flow is allowed to use.
		c.inRange()
		if c.congestionWindow > c.ssthresh {
			// The threshold is crossed, so the flow enters congestion
			// avoidance. Its first period starts at the current window and uses
			// K = 0, because no W_max of a congestion event is applicable
			// (RFC 8312, Sections 4.7 and 4.8).
			c.mode = cubicNormal
			c.startEpoch(c.congestionWindow, 0)
		}
		return c.congestionWindow
	}

	// Congestion avoidance: cwnd = max(W_cubic(t), W_est(t)) of RFC 8312,
	// Eq. 1 and Eq. 4. W_est keeps the flow in the TCP-friendly region while
	// CUBIC would grow slower than the AIMD flow of the same average window
	// size (RFC 8312, Section 4.2); W_cubic drives the concave and the convex
	// region otherwise (RFC 8312, Sections 4.3 and 4.4).
	t := c.epochSeconds()
	w := math.Max(math.Max(c.wCubic(t), c.wEst(t, rtt)), 0)
	// The curve is clamped before the conversion, so that a long epoch can't
	// overflow the conversion of the float64 window to uint32.
	w = math.Min(w, float64(c.maxWindowSize))
	c.congestionWindow = uint32(math.Round(w))
	return c.inRange()
}

// OnLoss updates the congestion window size from the packet loss.
func (c *CubicSendAlgorithm) OnLoss() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	// RFC 8312, Section 4.5: save the window size before the reduction, set the
	// slow start threshold to the reduced window, and reduce the window itself
	// by beta_cubic.
	wMax := c.congestionWindow
	c.ssthresh = max(uint32(math.Round(float64(wMax)*cubicBeta)), c.minWindowSize)
	c.congestionWindow = c.ssthresh
	c.mode = cubicNormal
	c.startEpoch(wMax, math.Cbrt(float64(wMax)*(1-cubicBeta)/cubicC))
	return c.inRange()
}

// OnTimeout updates the congestion window size from the connection timeout.
func (c *CubicSendAlgorithm) OnTimeout() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()

	// RFC 8312, Section 4.7 reduces the window on a timeout like standard TCP
	// (RFC 5681, Section 3.1) rather than by beta_cubic: the slow start
	// threshold becomes half of the current window, and the flow restarts slow
	// start from one minimum sized window. OnAck consumes the threshold and
	// leaves slow start as soon as the window grows past it, so the reduction
	// is not lost.
	c.ssthresh = max(c.congestionWindow/timeoutSsthreshDivisor, c.minWindowSize)
	c.congestionWindow = c.minWindowSize
	c.mode = cubicSlowStart
	// The next congestion avoidance epoch starts when slow start has grown the
	// window back to the threshold; it uses W_max of the window at that moment
	// and K = 0 (RFC 8312, Sections 4.7 and 4.8).
	c.windowSizeBeforeLastReduction = 0
	c.epochK = 0
	c.epochStart = 0
	return c.inRange()
}

// startEpoch starts a new congestion avoidance epoch. wMax is W_max of
// RFC 8312, Section 4.1 and k is K of Eq. 2; both stay constant until the next
// congestion event or slow start period.
func (c *CubicSendAlgorithm) startEpoch(wMax uint32, k float64) {
	c.windowSizeBeforeLastReduction = wMax
	c.epochK = k
	c.epochStart = float64(c.now().UnixMicro()) / 1e6
}

// epochSeconds returns t of RFC 8312, Eq. 1 and Eq. 4: the time in seconds
// elapsed since the start of the current congestion avoidance epoch.
func (c *CubicSendAlgorithm) epochSeconds() float64 {
	return float64(c.now().UnixMicro())/1e6 - c.epochStart
}

// wCubic returns W_cubic(t) of RFC 8312, Section 4.1, Eq. 1.
func (c *CubicSendAlgorithm) wCubic(t float64) float64 {
	d := t - c.epochK
	return cubicC*d*d*d + float64(c.windowSizeBeforeLastReduction)
}

// wEst returns W_est(t) of RFC 8312, Section 4.2, Eq. 4: the window size of the
// AIMD(alpha_aimd, beta_cubic) flow whose average window size matches standard
// TCP. rtt must be positive.
func (c *CubicSendAlgorithm) wEst(t float64, rtt time.Duration) float64 {
	return float64(c.windowSizeBeforeLastReduction)*cubicBeta + cubicAIMDAlpha*(t/rtt.Seconds())
}

// inRange makes sure the congestion window is inside the min and max value.
func (c *CubicSendAlgorithm) inRange() uint32 {
	if c.congestionWindow < c.minWindowSize {
		c.congestionWindow = c.minWindowSize
	} else if c.congestionWindow > c.maxWindowSize {
		c.congestionWindow = c.maxWindowSize
	}
	return c.congestionWindow
}
