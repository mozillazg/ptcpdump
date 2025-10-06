// Package core provides timing and clock functionality for traffic control operations.
//
// IMPORTANT: Before using any timing functions (Duration2TcTime, Time2Tick, etc.),
// you must initialize the clock parameters by calling InitializeClock().
//
// Example usage:
//   import "github.com/florianl/go-tc/core"
//
//   func main() {
//       if err := core.InitializeClock(); err != nil {
//           log.Printf("Warning: failed to initialize clock: %v", err)
//       }
//
//       // Now you can use timing functions
//       ticks := core.Time2Tick(1000)
//   }

package core

import (
	"syscall"
	"time"
)

var (
	tickInUSec  float64
	clockFactor float64

	// isSet indicates whether the clock parameters have been initialized.
	isSet bool
)

const (
	// iproute2/include/utils.h:timeUnitsPerSec
	timeUnitsPerSec = 1000000
)

// InitializeClock initializes the clock parameters by reading from /proc/net/psched on Linux.
// On non-Linux platforms, it sets default values (1.0 for both parameters).
// This function must be called before using any of the timing functions.
// It returns an error if the clock parameters cannot be read on Linux.
func InitializeClock() error {
	isSet = true
	return initializeClock()
}

// SetClockParameters allows manual configuration of the clock parameters.
// This is useful for testing or when custom clock values are needed.
// clockFactor is the clock resolution factor, tickInUSec is the tick to microsecond conversion factor.
func SetClockParameters(newClockFactor, newTickInUSec float64) {
	isSet = true
	clockFactor = newClockFactor
	tickInUSec = newTickInUSec
}

// IsClockInitialized returns true if the clock parameters have been initialized.
func IsClockInitialized() bool {
	return isSet
}

// GetClockFactor returns the current clock factor value.
func GetClockFactor() float64 {
	return clockFactor
}

// GetTickInUSec returns the current tick in microseconds conversion factor.
func GetTickInUSec() float64 {
	return tickInUSec
}

// Duration2TcTime implements iproute2/tc/q_netem.c:get_ticks().
// It converts a given duration into a time value that can be converted to ticks with Time2Tick().
// On error it returns syscall.EINVAL.
func Duration2TcTime(d time.Duration) (uint32, error) {
	v := uint64(int64(d.Microseconds()) * (timeUnitsPerSec / 1000000))
	if (v >> 32) != 0 {
		return 0, syscall.EINVAL
	}
	return uint32(v), nil
}

// Time2Tick implements iproute2/tc/tc_core:tc_core_time2tick().
// It returns the number of CPU ticks for a given time in usec.
func Time2Tick(time uint32) uint32 {
	return uint32(float64(time) * tickInUSec)
}

// Tick2Time implements iproute2/tc/tc_core:tc_core_tick2time().
// It returns a time in usec for a given number of CPU ticks.
func Tick2Time(tick uint32) uint32 {
	return uint32(float64(tick) / tickInUSec)
}

// XmitTime implements iproute2/tc/tc_core:tc_calc_xmittime().
// It returns the time, that is needed to transmit a given size for a given rate.
func XmitTime(rate uint64, size uint32) uint32 {
	return Time2Tick(uint32(timeUnitsPerSec * (float64(size) / float64(rate))))
}

// XmitSize implements iproute2/tc/tc_core:tc_calc_xmitsize().
// It returns the size that can be transmitted at a given rate during a given time.
func XmitSize(rate uint64, ticks uint32) uint32 {
	return uint32(rate*uint64(Tick2Time(ticks))) / timeUnitsPerSec
}

// Time2Ktime implements iproute2/tc/tc_core:tc_core_time2ktime().
func Time2Ktime(time uint32) uint32 {
	return uint32(uint64(time) * uint64(clockFactor))
}

// Ktime2Time implements iproute2/tc/tc_core:tc_core_ktime2time().
func Ktime2Time(ktime uint32) uint32 {
	return uint32(float64(ktime) / clockFactor)
}
