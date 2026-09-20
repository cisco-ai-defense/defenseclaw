package config

import "testing"

// The local store is an operational buffer, not the system of record. The
// previous 90-day default let one deployment reach 26 GB across 1.9M events.
func TestObservabilityV8DefaultRetentionIsSevenDays(t *testing.T) {
	if ObservabilityV8DefaultRetentionDays != 7 {
		t.Fatalf("default retention = %d days, want 7", ObservabilityV8DefaultRetentionDays)
	}
}

func TestCompileLocalAppliesSevenDayDefaultWhenUnset(t *testing.T) {
	got, err := compileObservabilityV8Local(ObservabilityV8LocalSource{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got.RetentionDays != 7 {
		t.Errorf("RetentionDays = %d, want 7 when unset", got.RetentionDays)
	}
}

func TestCompileLocalHonoursExplicitOverride(t *testing.T) {
	for _, days := range []int{0, 1, 30, 90, 365} {
		value := days
		got, err := compileObservabilityV8Local(ObservabilityV8LocalSource{RetentionDays: &value})
		if err != nil {
			t.Fatalf("compile(%d): %v", days, err)
		}
		if got.RetentionDays != days {
			t.Errorf("RetentionDays = %d, want %d (explicit operator value must win)", got.RetentionDays, days)
		}
	}
}
