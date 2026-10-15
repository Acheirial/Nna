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

import "testing"

// The window range used by most tests below is deliberately not degenerate, so
// that slow start growth, clamping and the loss back off are observable.
const (
	cubicTestMinWindow = 2
	cubicTestMaxWindow = 1000
)

// TestCubicSlowStart verifies that the window grows by one for every
// acknowledged packet while the algorithm is in slow start, and that the
// algorithm stays in slow start until a loss or a timeout is reported.
func TestCubicSlowStart(t *testing.T) {
	cubic := NewCubicSendAlgorithm(cubicTestMinWindow, cubicTestMaxWindow)
	if got := cubic.CongestionWindowSize(); got != cubicTestMinWindow {
		t.Fatalf("initial cwnd = %d, want %d", got, cubicTestMinWindow)
	}
	if !cubic.InSlowStart() {
		t.Fatalf("InSlowStart() = false, want true for a new algorithm")
	}

	want := uint32(cubicTestMinWindow)
	for i := 0; i < 100; i++ {
		want++
		if got := cubic.OnAck(); got != want {
			t.Fatalf("OnAck() #%d = %d, want %d", i+1, got, want)
		}
		if !cubic.InSlowStart() {
			t.Fatalf("InSlowStart() = false after %d acks without a loss", i+1)
		}
	}
	if got := cubic.CongestionWindowSize(); got != want {
		t.Errorf("CongestionWindowSize() = %d, want %d", got, want)
	}
}

// TestCubicWindowLimit verifies that the window reaches the configured maximum
// after exactly max-min acknowledged packets and is clamped there for any
// number of further acknowledgements.
func TestCubicWindowLimit(t *testing.T) {
	cubic := NewCubicSendAlgorithm(cubicTestMinWindow, cubicTestMaxWindow)

	for i := 0; i < cubicTestMaxWindow-cubicTestMinWindow; i++ {
		if got := cubic.OnAck(); got > cubicTestMaxWindow {
			t.Fatalf("OnAck() #%d = %d, want <= %d", i+1, got, cubicTestMaxWindow)
		}
	}
	if got := cubic.CongestionWindowSize(); got != cubicTestMaxWindow {
		t.Fatalf("CongestionWindowSize() at the limit = %d, want %d", got, cubicTestMaxWindow)
	}

	for i := 0; i < 2*cubicTestMaxWindow; i++ {
		got := cubic.OnAck()
		if got > cubicTestMaxWindow {
			t.Fatalf("OnAck() #%d = %d, want <= %d", i+1, got, cubicTestMaxWindow)
		}
		if got < cubicTestMinWindow {
			t.Fatalf("OnAck() #%d = %d, want >= %d", i+1, got, cubicTestMinWindow)
		}
	}
	if got := cubic.CongestionWindowSize(); got != cubicTestMaxWindow {
		t.Errorf("CongestionWindowSize() after sustained acks = %d, want %d", got, cubicTestMaxWindow)
	}
	if !cubic.InSlowStart() {
		t.Errorf("InSlowStart() = false, want true because no loss was reported")
	}
}

// TestCubicOnLoss verifies the multiplicative decrease after a loss and that the
// window does not grow back to the pre-loss value in the following acks.
func TestCubicOnLoss(t *testing.T) {
	cubic := NewCubicSendAlgorithm(cubicTestMinWindow, cubicTestMaxWindow)
	for i := 0; i < 2*cubicTestMaxWindow; i++ {
		cubic.OnAck()
	}
	before := cubic.CongestionWindowSize()
	if before != cubicTestMaxWindow {
		t.Fatalf("CongestionWindowSize() before the loss = %d, want %d", before, cubicTestMaxWindow)
	}

	lost := cubic.OnLoss()
	if cubic.InSlowStart() {
		t.Errorf("InSlowStart() = true, want false after a loss")
	}
	if lost >= before {
		t.Errorf("OnLoss() = %d, want < %d (multiplicative decrease)", lost, before)
	}
	if lost < before/2 {
		t.Errorf("OnLoss() = %d, want >= %d", lost, before/2)
	}

	// The cubic window is driven by the time since the loss, not by the number
	// of acks: it recovers monotonically, stays inside [min, max], and needs
	// seconds of elapsed time before it reaches the pre-loss window again. With
	// the few acks below, this test only passes if the loss back off is applied
	// and remembered; a stalled test process would have to hang for about six
	// seconds for the last assertion below to become wrong.
	prev := lost
	for i := 0; i < 200; i++ {
		got := cubic.OnAck()
		if got > cubicTestMaxWindow {
			t.Fatalf("OnAck() #%d after the loss = %d, want <= %d", i+1, got, cubicTestMaxWindow)
		}
		if got < cubicTestMinWindow {
			t.Fatalf("OnAck() #%d after the loss = %d, want >= %d", i+1, got, cubicTestMinWindow)
		}
		if got < prev {
			t.Fatalf("OnAck() #%d after the loss = %d, want >= %d", i+1, got, prev)
		}
		prev = got
	}
	if got := cubic.CongestionWindowSize(); got >= before {
		t.Errorf("CongestionWindowSize() 200 acks after the loss = %d, want < %d", got, before)
	}

	// A second loss without recovery decreases the window again.
	if again := cubic.OnLoss(); again >= prev {
		t.Errorf("second OnLoss() = %d, want < %d", again, prev)
	}
}

// TestCubicLossFloor verifies that a loss never shrinks the window below the
// configured minimum.
func TestCubicLossFloor(t *testing.T) {
	cubic := NewCubicSendAlgorithm(cubicTestMinWindow, cubicTestMaxWindow)
	for i := 0; i < 10; i++ {
		if got := cubic.OnLoss(); got != cubicTestMinWindow {
			t.Fatalf("OnLoss() #%d at the minimum window = %d, want %d", i+1, got, cubicTestMinWindow)
		}
	}
	if cubic.InSlowStart() {
		t.Errorf("InSlowStart() = true, want false after a loss")
	}
}

// TestCubicOnTimeout verifies that a timeout resets the window to the minimum
// and restarts slow start.
func TestCubicOnTimeout(t *testing.T) {
	cubic := NewCubicSendAlgorithm(cubicTestMinWindow, cubicTestMaxWindow)
	for i := 0; i < 100; i++ {
		cubic.OnAck()
	}
	cubic.OnLoss()
	cubic.OnAck()
	if cubic.InSlowStart() {
		t.Fatalf("InSlowStart() = true, want false before the timeout")
	}

	if got := cubic.OnTimeout(); got != cubicTestMinWindow {
		t.Fatalf("OnTimeout() = %d, want %d", got, cubicTestMinWindow)
	}
	if !cubic.InSlowStart() {
		t.Errorf("InSlowStart() = false, want true after a timeout")
	}
	if got := cubic.CongestionWindowSize(); got != cubicTestMinWindow {
		t.Errorf("CongestionWindowSize() after the timeout = %d, want %d", got, cubicTestMinWindow)
	}
	if got := cubic.OnAck(); got != cubicTestMinWindow+1 {
		t.Errorf("OnAck() after the timeout = %d, want %d", got, cubicTestMinWindow+1)
	}
}

// TestInRange verifies the window clamping when the configured range is
// degenerate (min == max): the window is pinned to that value, while the
// operation mode still follows losses and timeouts.
func TestInRange(t *testing.T) {
	const fixedWindow = 16
	cubic := NewCubicSendAlgorithm(fixedWindow, fixedWindow)
	if got := cubic.CongestionWindowSize(); got != fixedWindow {
		t.Fatalf("initial cwnd = %d, want %d", got, fixedWindow)
	}
	if !cubic.InSlowStart() {
		t.Fatalf("InSlowStart() = false, want true for a new algorithm")
	}

	for i := 0; i < 3; i++ {
		if got := cubic.OnAck(); got != fixedWindow {
			t.Errorf("OnAck() #%d = %d, want %d", i+1, got, fixedWindow)
		}
	}
	if got := cubic.OnLoss(); got != fixedWindow {
		t.Errorf("OnLoss() = %d, want %d", got, fixedWindow)
	}
	if cubic.InSlowStart() {
		t.Errorf("InSlowStart() = true, want false after a loss")
	}
	// The cubic formula is not allowed to leave the clamped value either.
	if got := cubic.OnAck(); got != fixedWindow {
		t.Errorf("OnAck() after the loss = %d, want %d", got, fixedWindow)
	}
	if got := cubic.OnTimeout(); got != fixedWindow {
		t.Errorf("OnTimeout() = %d, want %d", got, fixedWindow)
	}
	if !cubic.InSlowStart() {
		t.Errorf("InSlowStart() = false, want true after a timeout")
	}
}

// TestNewCubicSendAlgorithmPanic verifies that an inverted window range is
// rejected.
func TestNewCubicSendAlgorithmPanic(t *testing.T) {
	mustPanic(t, "NewCubicSendAlgorithm", func() {
		NewCubicSendAlgorithm(cubicTestMaxWindow, cubicTestMinWindow)
	})
}
