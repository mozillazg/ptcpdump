//go:build !linux
// +build !linux

package core

// initializeClock sets default clock parameters for non-Linux platforms.
func initializeClock() error {
	clockFactor = 1.0
	tickInUSec = 1.0
	return nil
}
