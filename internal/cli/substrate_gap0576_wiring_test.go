// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// uncontainedSkillScanner fails as scanner.SkillScanner does in a pod that
// refuses the scanner's user namespaces (processutil.RunTracked).
type uncontainedSkillScanner struct{}

func (uncontainedSkillScanner) Name() string               { return "skill-scanner" }
func (uncontainedSkillScanner) Version() string            { return "test" }
func (uncontainedSkillScanner) SupportedTargets() []string { return []string{"skill"} }
func (uncontainedSkillScanner) Scan(context.Context, string) (*scanner.ScanResult, error) {
	return nil, fmt.Errorf("scanner: skill-scanner could not complete: %w", fmt.Errorf("%w: %w: the scanner's user and PID namespaces: operation not permitted",
		processutil.ErrNotContained, processutil.ErrContainmentUnavailable))
}

// GAP-0576 item 5, the GAP-0164 ruling (T6): the gateway's skill folder
// scan refuses a skill when skill-scanner is installed but cannot run
// contained (a quarantine with the cause), instead of reporting "no
// scanner", which the open-source fail mode admitted unscanned.
func TestGAP0576RuntimeSkillScanRefusesWhenTheScannerCannotBeContained(t *testing.T) {
	s := runtimeSkillScanner{rt: &attest.RuntimeScanner{Skill: uncontainedSkillScanner{}, Compiled: policy.CompileAdmission(&config.Config{}),
		Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}}
	blocked, reason, err := s.ScanSkillFolder(context.Background(), "notes", "/sandbox/.claude/skills/notes",
		[]gateway.SubstrateAttachedFile{{Path: "/sandbox/.claude/skills/notes/SKILL.md", Content: []byte("---\nname: notes\n---\nTake short notes.")}})
	if errors.Is(err, gateway.ErrSubstrateSkillScannerUnavailable) || err != nil {
		t.Fatalf("ScanSkillFolder = %v: an installed scanner that cannot be contained is refused, not left to the fail mode", err)
	}
	if !blocked || !strings.Contains(reason, "containment unavailable") || !strings.Contains(reason, "operation not permitted") {
		t.Fatalf("blocked %v reason %q, want a refusal naming containment and its cause", blocked, reason)
	}
}
