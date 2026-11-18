package sliver

import "time"

// durationSeconds converts a UI-facing second count into the nanosecond
// int64 Sliver implants expect (time.Duration). Zero stays zero so omitted
// reconfigure fields do not overwrite the running value.
func durationSeconds(sec int64) int64 {
	if sec <= 0 {
		return 0
	}
	return sec * int64(time.Second)
}

// durationToSeconds converts a Sliver time.Duration int64 back to seconds
// for the UI. Values smaller than one second are treated as already-seconds
// so a legacy generate that stored "60" (meaning 60ns) still displays as 60.
func durationToSeconds(ns int64) int64 {
	if ns <= 0 {
		return 0
	}
	if ns < int64(time.Second) {
		return ns
	}
	return ns / int64(time.Second)
}
