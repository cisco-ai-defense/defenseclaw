// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// GAP-0576 item 5, the GAP-0164 ruling (T6): a gateway whose skill-scanner
// is installed but cannot run contained (the pod refuses user namespaces)
// counts as "scanner unavailable" and fails closed: a skill added
// mid-session is refused, not admitted unscanned under the open-source fail
// mode, and the refusal names the real cause and the next step. At
// be3124b688 the decision was Unavailable, which the open-source fail mode
// admits with an alert.
func TestGAP0576ScannerThatCannotBeContainedFailsClosedAtRunTime(t *testing.T) {
	rs := &RuntimeScanner{Skill: refusedSkillScanner{}, Compiled: policy.CompileAdmission(&config.Config{})}
	asset := RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: "notes", Path: "/sandbox/.claude/skills/notes",
		Files: []AttachedFile{{Role: RoleSkillFile, Path: "/sandbox/.claude/skills/notes/SKILL.md", Content: []byte("---\nname: notes\n---\nTake short notes.")}}}
	for i := 0; i < 2; i++ {
		d, err := rs.Scan(context.Background(), asset)
		if err != nil {
			t.Fatal(err)
		}
		if d.Action != "block" || d.Unavailable || d.Cached {
			t.Fatalf("scan %d: action %q unavailable %v cached %v (%q), want a fresh block", i, d.Action, d.Unavailable, d.Cached, d.Reason)
		}
		for _, want := range []string{"skill-scanner is installed", "containment unavailable", "no space left on device", "not admitted unscanned", "user namespaces"} {
			if !strings.Contains(d.Reason, want) {
				t.Errorf("reason %q does not say %q", d.Reason, want)
			}
		}
	}
}
