// Package monoclock converts the CLOCK_MONOTONIC timestamps produced by
// bpf_ktime_get_ns() into wall-clock times suitable for OTLP.
package monoclock

import (
	"time"

	"golang.org/x/sys/unix"
)

// Clock maps monotonic nanoseconds onto wall-clock time using a single offset
// sampled at startup.
//
// The offset is deliberately not refreshed: a span's duration is computed from
// two monotonic readings and is always exact, while re-sampling would make
// consecutive traces jump around whenever NTP steps the realtime clock.
type Clock struct {
	base time.Time // wall-clock instant of monotonic time 0
}

// New samples both clocks and returns the resulting offset.
func New() (Clock, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return Clock{}, err
	}
	wall := time.Now()

	mono := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)

	return Clock{base: wall.Add(-mono)}, nil
}

// Time converts a bpf_ktime_get_ns() reading to wall-clock time.
func (c Clock) Time(ns uint64) time.Time {
	return c.base.Add(time.Duration(ns))
}

// NowNS returns the current CLOCK_MONOTONIC reading in nanoseconds, on the
// same time base the BPF program uses.
func NowNS() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}

	return uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)
}
