//go:build !windows

package gateway

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// SKILLSCAN-B10 (GAP-0980 lead conditions on the managed hold): a held
// folder is refused with a plain message, the hold ends at
// skills.scan.timeout (the fail mode decides), a scanner that dies mid-scan
// releases the folder to the fail mode, a benign slow folder is usable on
// the first post after its scan ends, and the OSS tiers keep no hold.

// b510Scanner ends every scan after d with err (nil: clean); it counts scans.
type b510Scanner struct {
	d   time.Duration
	err error
	n   atomic.Int32
}

func (s *b510Scanner) ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (bool, string, error) {
	s.n.Add(1)
	select {
	case <-time.After(s.d):
		return false, "", s.err
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
}

func b510Post(st *substrateState, uid string, dirs ...string) substrateSkillAnswer {
	return st.substrateSkills(withSkillPostStart(b59Actor(uid)), "claudecode", b59Facts(dirs...))
}

const b510Dir = "/home/agent/.claude/skills/slow"

func TestB510HeldMessagePlain(t *testing.T) {
	got := skillHeldMessage([]SubstrateUnscanned{{Path: b510Dir, FP: "sha256:00"}})
	want := `"slow" is still being scanned; DefenseClaw refuses tool calls until the scan finishes. Try again in a few seconds.`
	if got != want {
		t.Fatalf("held message %q, want %q", got, want)
	}
	for _, internal := range []string{"substrate_", "skill_", "pending_wait", "sha256", "fp", "_"} {
		if strings.Contains(got, internal) {
			t.Fatalf("held message names an internal field (%q): %q", internal, got)
		}
	}
}

// The hold ends at skills.scan.timeout: the next post gets the timeout and
// managed refuses the folder (moved by the kit), with no second scan that
// would hold it again. Red at 39cdfbc4fd (the next post scans again, held).
func TestB510HoldEndsAtScanTimeout(t *testing.T) {
	sc := &b510Scanner{d: 5 * time.Second}
	st := b59State(sc, true, 150*time.Millisecond, 40*time.Millisecond)
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c4a01"
	if a := b510Post(st, uid, b510Dir); len(a.held) != 1 {
		t.Fatalf("first post: %+v", a)
	}
	time.Sleep(220 * time.Millisecond)
	a := b510Post(st, uid, b510Dir)
	if len(a.held) != 0 || len(a.Quarantine) != 1 || a.Quarantine[0].Code != SkillReasonScanTimeout || sc.n.Load() != 1 {
		t.Fatalf("post after scan.timeout: held=%+v quarantine=%+v scans=%d", a.held, a.Quarantine, sc.n.Load())
	}
}

// A scanner killed mid-scan: the folder is released to the managed fail
// mode on the next post (refused, the kit moves it), never held again.
// Red at 39cdfbc4fd.
func TestB510ScannerKilledMidScanReleased(t *testing.T) {
	for name, c := range map[string]struct {
		err  error
		code string
	}{
		"killed":      {errors.New("skill-scanner: read: connection reset by peer (signal: killed)"), SkillReasonScanFailed},
		"unavailable": {ErrSubstrateSkillScannerUnavailable, SkillReasonScannerDown},
	} {
		t.Run(name, func(t *testing.T) {
			sc := &b510Scanner{d: 100 * time.Millisecond, err: c.err}
			st := b59State(sc, true, 2*time.Second, 40*time.Millisecond)
			uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c4a02"
			if a := b510Post(st, uid, b510Dir); len(a.held) != 1 {
				t.Fatalf("first post: %+v", a)
			}
			time.Sleep(160 * time.Millisecond)
			a := b510Post(st, uid, b510Dir)
			if len(a.held) != 0 || len(a.Quarantine) != 1 || a.Quarantine[0].Code != c.code || sc.n.Load() != 1 {
				t.Fatalf("post after the scanner died: held=%+v quarantine=%+v scans=%d", a.held, a.Quarantine, sc.n.Load())
			}
		})
	}
}

// No scan slot (8 per actor): the hold still ends at skills.scan.timeout
// from the first post. Red at 39cdfbc4fd (a fresh full-length scan, held).
func TestB510BusyHoldBounded(t *testing.T) {
	sc := &b510Scanner{d: 5 * time.Second}
	st := b59State(sc, true, 300*time.Millisecond, 40*time.Millisecond)
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c4a03"
	var eight []string
	for _, c := range "abcdefgh" {
		eight = append(eight, "/home/agent/.claude/skills/"+string(c))
	}
	start := time.Now()
	if a := b510Post(st, uid, eight...); len(a.held) != 8 {
		t.Fatalf("eight folders: %+v", a)
	}
	if a := b510Post(st, uid, b510Dir); len(a.held) != 1 {
		t.Fatalf("ninth folder must be held busy: %+v", a)
	}
	time.Sleep(time.Until(start.Add(380 * time.Millisecond)))
	a := b510Post(st, uid, b510Dir)
	if len(a.held) != 0 || len(a.Quarantine) != 1 || a.Quarantine[0].Code != SkillReasonScanTimeout {
		t.Fatalf("busy hold past scan.timeout: held=%+v quarantine=%+v", a.held, a.Quarantine)
	}
}

// A benign slow folder is usable on the first post after its scan ends,
// from the kept outcome (no second scan). Red at 39cdfbc4fd with a
// scanner without a verdict cache (scans again, held again).
func TestB510SlowBenignUsableNextPost(t *testing.T) {
	sc := &b510Scanner{d: 120 * time.Millisecond}
	st := b59State(sc, true, 2*time.Second, 40*time.Millisecond)
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c4a04"
	if a := b510Post(st, uid, b510Dir); len(a.held) != 1 {
		t.Fatalf("first post: %+v", a)
	}
	time.Sleep(160 * time.Millisecond)
	a := b510Post(st, uid, b510Dir)
	if len(a.held) != 0 || len(a.Quarantine) != 0 || len(a.Scanned) != 1 || sc.n.Load() != 1 {
		t.Fatalf("post after the scan ended: held=%+v quarantine=%+v scanned=%d scans=%d", a.held, a.Quarantine, len(a.Scanned), sc.n.Load())
	}
}

// The OSS tiers keep no hold and no kept outcome: a slow folder is pending
// (not held), and the next post scans again, as before this change.
func TestB510OSSNoHoldUnchanged(t *testing.T) {
	sc := &b510Scanner{d: 100 * time.Millisecond, err: ErrSubstrateSkillScannerUnavailable}
	st := b59State(sc, false, 2*time.Second, 40*time.Millisecond)
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c4a05"
	if a := b510Post(st, uid, b510Dir); len(a.held) != 0 || len(a.pending) != 1 || len(a.Quarantine) != 0 {
		t.Fatalf("OSS first post: %+v", a)
	}
	time.Sleep(160 * time.Millisecond)
	if a := b510Post(st, uid, b510Dir); len(a.held) != 0 || len(a.Quarantine) != 0 || sc.n.Load() != 2 || len(st.scanKept) != 0 || len(st.heldSince) != 0 {
		t.Fatalf("OSS next post: %+v scans=%d kept=%d", a, sc.n.Load(), len(st.scanKept))
	}
}
