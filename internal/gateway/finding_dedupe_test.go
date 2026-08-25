package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestFindingDedupeSuppressesRepeatsWithinWindow(t *testing.T) {
	c := newFindingDedupeCache(10*time.Minute, 128)
	if !c.admit("hook-rules", "claudecode:PostToolUse", "CMD-SUDO", "sudo rm") {
		t.Fatal("first sighting must be admitted")
	}
	for i := 0; i < 20; i++ {
		if c.admit("hook-rules", "claudecode:PostToolUse", "CMD-SUDO", "sudo rm") {
			t.Fatalf("repeat %d must be suppressed", i)
		}
	}
}

func TestFindingDedupeReadmitsAfterWindow(t *testing.T) {
	c := newFindingDedupeCache(10*time.Minute, 128)
	base := time.Unix(1700000000, 0)
	c.now = func() time.Time { return base }
	if !c.admit("hook-rules", "t", "CMD-SUDO", "e") {
		t.Fatal("first sighting must be admitted")
	}
	c.now = func() time.Time { return base.Add(9 * time.Minute) }
	if c.admit("hook-rules", "t", "CMD-SUDO", "e") {
		t.Error("inside the window must stay suppressed")
	}
	c.now = func() time.Time { return base.Add(11 * time.Minute) }
	if !c.admit("hook-rules", "t", "CMD-SUDO", "e") {
		t.Error("a recurring condition must resurface after the window")
	}
}

func TestFindingDedupeDistinguishesContent(t *testing.T) {
	c := newFindingDedupeCache(10*time.Minute, 128)
	c.admit("hook-rules", "t", "CMD-SUDO", "sudo rm")
	if !c.admit("hook-rules", "t", "CMD-SUDO", "sudo dd") {
		t.Error("different evidence is a different finding")
	}
	if !c.admit("hook-rules", "t", "CMD-MKFS", "sudo rm") {
		t.Error("different rule is a different finding")
	}
	if !c.admit("hook-rules", "other-target", "CMD-SUDO", "sudo rm") {
		t.Error("different target is a different finding")
	}
}

func TestFindingDedupeOverflowFailsOpen(t *testing.T) {
	c := newFindingDedupeCache(10*time.Minute, 2)
	c.admit("s", "t", "R1", "a")
	c.admit("s", "t", "R2", "b")
	c.admit("s", "t", "R3", "c") // triggers reset
	if !c.admit("s", "t", "R1", "a") {
		t.Error("overflow must cost a duplicate, never a missed finding")
	}
}

func TestAdmitNewInspectFindingsFiltersPersistenceOnly(t *testing.T) {
	c := newFindingDedupeCache(10*time.Minute, 128)
	in := []scanner.InspectFinding{
		{RuleID: "CMD-SUDO", Evidence: "sudo rm"},
		{RuleID: "CMD-SUDO", Evidence: "sudo rm"},
		{RuleID: "CMD-MKFS", Evidence: "mkfs /dev/x"},
	}
	out := admitNewInspectFindings(c, "hook-rules", "tgt", in)
	if len(out) != 2 {
		t.Fatalf("len=%d, want 2 (duplicate collapsed)", len(out))
	}
	if again := admitNewInspectFindings(c, "hook-rules", "tgt", in); len(again) != 0 {
		t.Errorf("len=%d, want 0 on immediate rescan", len(again))
	}
}
