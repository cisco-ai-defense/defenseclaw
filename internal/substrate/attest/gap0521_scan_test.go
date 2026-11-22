// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// refusedSkillScanner fails as scanner.SkillScanner does on a host that
// refuses the scanner's namespaces (processutil.RunTracked, GAP-0521).
type refusedSkillScanner struct{ fakeSkillScanner }

func (refusedSkillScanner) Scan(ctx context.Context, dir string) (*scanner.ScanResult, error) {
	return nil, fmt.Errorf("scanner: skill-scanner could not complete: %w",
		fmt.Errorf("%w: %w: the scanner's user and PID namespaces: no space left on device", processutil.ErrNotContained, processutil.ErrContainmentUnavailable))
}

// GAP-0521: the template build on a host that refuses the scanner's
// namespaces blocked every skill, clean or not, as "scanner failed", which
// read as a verdict. It must still block (fail closed), and each item must
// say that no scan ran here and why; a scanner that ran and failed keeps its
// own reason.
func TestGAP0521ScannerThatCannotRunHereBlocksWithoutAVerdict(t *testing.T) {
	f := newFixture(t, tarFile{path: "/opt/skills/a/SKILL.md", mode: 0o644, data: "ok"})
	_, err := f.build(t, func(o *BuildOptions) { o.Skill = refusedSkillScanner{} })
	var blocked *BuildBlocked
	if !errors.As(err, &blocked) || !errors.Is(err, ErrScanBlocked) {
		t.Fatalf("a skill scan that cannot run must block the build, got %v", err)
	}
	items := blocked.Report.Summary.Items
	if len(items) != 1 || items[0].Verdict != VerdictBlock {
		t.Fatalf("items = %+v, want one blocked skill", items)
	}
	for _, want := range []string{"no verdict: the skill scanner cannot run on this host", "this host refuses the namespaces containment needs"} {
		if !strings.Contains(items[0].Reason, want) {
			t.Fatalf("reason %q does not say %q", items[0].Reason, want)
		}
	}

	_, err = f.build(t, func(o *BuildOptions) { o.Skill = fakeSkillScanner{fail: true} })
	if !errors.As(err, &blocked) || strings.Contains(blocked.Report.Summary.Items[0].Reason, "no verdict") {
		t.Fatalf("a scanner that ran and failed is not a host without a scanner: %v", err)
	}
}
