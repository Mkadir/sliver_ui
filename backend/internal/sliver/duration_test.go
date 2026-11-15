package sliver

import (
	"testing"
	"time"
)

func TestDurationSeconds(t *testing.T) {
	if got := durationSeconds(0); got != 0 {
		t.Fatalf("0 = %d", got)
	}
	if got := durationSeconds(-1); got != 0 {
		t.Fatalf("-1 = %d", got)
	}
	if got := durationSeconds(60); got != 60*int64(time.Second) {
		t.Fatalf("60s = %d", got)
	}
}
