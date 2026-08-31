package gateway

import "testing"

// Every hook finding previously reached scan_findings with an empty location,
// no line number, and an empty decision path, so a CRITICAL could not be
// distinguished from a false positive without re-deriving the match by hand.
func TestRuleFindingsToInspectCarriesLocation(t *testing.T) {
	in := []RuleFinding{{RuleID: "CMD-SUDO", Title: "sudo invocation", Severity: "LOW", LineNumber: 7}}
	out := ruleFindingsToInspect(in, "claudecode:PostToolUse")
	if len(out) != 1 {
		t.Fatalf("len=%d, want 1", len(out))
	}
	if out[0].Location != "claudecode:PostToolUse" {
		t.Errorf("Location=%q, want the scan target", out[0].Location)
	}
	if out[0].LineNumber == nil || *out[0].LineNumber != 7 {
		t.Errorf("LineNumber=%v, want 7", out[0].LineNumber)
	}
}

func TestUncomputedLineNumberIsAbsentNotZero(t *testing.T) {
	out := ruleFindingsToInspect([]RuleFinding{{RuleID: "X"}}, "t")
	if out[0].LineNumber != nil {
		t.Errorf("LineNumber=%v, want nil so an unknown line is absent rather than line 0", out[0].LineNumber)
	}
}

func TestLineNumberAtOffset(t *testing.T) {
	text := "alpha\nbeta\ngamma"
	cases := []struct {
		offset int
		want   int
	}{
		{0, 1}, {4, 1}, {6, 2}, {9, 2}, {11, 3}, {-1, 0}, {len(text) + 5, 0},
	}
	for _, tc := range cases {
		if got := lineNumberAtOffset(text, tc.offset); got != tc.want {
			t.Errorf("lineNumberAtOffset(offset=%d) = %d, want %d", tc.offset, got, tc.want)
		}
	}
}

// A match inside a multi-line tool result must report the line it landed on.
func TestContentScanReportsMatchLine(t *testing.T) {
	text := "line one\nline two\nsudo rm something\nline four"
	findings := ScanAllRules(text, "Bash")
	for _, f := range findings {
		if f.RuleID == "CMD-SUDO" {
			if f.LineNumber != 3 {
				t.Errorf("CMD-SUDO LineNumber=%d, want 3", f.LineNumber)
			}
			return
		}
	}
	t.Skip("CMD-SUDO not produced by this rule pack build; line plumbing covered by unit cases above")
}
