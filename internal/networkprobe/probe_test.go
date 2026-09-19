package networkprobe

import (
	"testing"
	"time"
)

func TestParseTargets(t *testing.T) {
	got := ParseTargets(" 1.1.1.1,8.8.8.8\n1.1.1.1,, 9.9.9.9 ")
	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("targets=%v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("targets=%v, want %v", got, want)
		}
	}
}

func TestMedianMilliseconds(t *testing.T) {
	values := []time.Duration{20 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 20 * time.Millisecond}
	if got := medianMilliseconds(values); got != 20 {
		t.Fatalf("median=%d, want 20", got)
	}
}

func TestStateUsesDefaultsWhenTargetsAreEmpty(t *testing.T) {
	state := NewState(nil)
	if len(state.targets) != len(defaultTargets) {
		t.Fatalf("targets=%v, want defaults=%v", state.targets, defaultTargets)
	}
	for index := range defaultTargets {
		if state.targets[index] != defaultTargets[index] {
			t.Fatalf("targets=%v, want defaults=%v", state.targets, defaultTargets)
		}
	}
}
