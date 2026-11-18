// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// GAP-0576 item 5: substrate doctor names a skill-scanner that is present
// but cannot run contained (warn, the cause and the fix); no scanner and a
// working containment pass.
func TestGAP0576DoctorNamesAScannerThatCannotBeContained(t *testing.T) {
	found := func(string) (string, error) { return "/usr/local/bin/skill-scanner", nil }
	missing := func(string) (string, error) { return "", exec.ErrNotFound }
	refused := func() error {
		return fmt.Errorf("%w: %w: the scanner's user and PID namespaces: operation not permitted (a seccomp profile or sandbox refuses user namespaces)",
			processutil.ErrNotContained, processutil.ErrContainmentUnavailable)
	}
	ran := func() error { return &exec.ExitError{} }
	c := substrateSkillScannerCheck("skill-scanner", found, refused)
	if c.ID != "substrate.skill_scanner" || c.Status != "warn" || !strings.Contains(c.Detail, "skill-scanner present, containment unavailable: the scanner's user and PID namespaces: operation not permitted") ||
		!strings.Contains(c.Detail, "refused unscanned") || !strings.Contains(c.Fix, "user namespaces") {
		t.Fatalf("present, not containable: %+v", c)
	}
	if c := substrateSkillScannerCheck("skill-scanner", missing, func() error { return errors.New("not run") }); c.Status != "pass" || !strings.Contains(c.Detail, "no skill-scanner") {
		t.Fatalf("absent: %+v", c)
	}
	for _, p := range []func() error{func() error { return nil }, ran} {
		if c := substrateSkillScannerCheck("skill-scanner", found, p); c.Status != "pass" || !strings.Contains(c.Detail, "containment works") {
			t.Fatalf("present and containable: %+v", c)
		}
	}
}
