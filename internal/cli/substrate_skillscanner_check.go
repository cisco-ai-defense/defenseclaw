// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// substrateSkillScannerCheckID is the doctor row of the gateway's runtime
// skill scan (GAP-0576 item 5, the GAP-0164 ruling).
const substrateSkillScannerCheckID = "substrate.skill_scanner"

// substrateSkillScannerBinary is the skill-scanner the gateway runs.
func substrateSkillScannerBinary(c *config.Config) string {
	if b := strings.TrimSpace(c.Scanners.SkillScanner.Binary); b != "" {
		return b
	}
	return "skill-scanner"
}

// substrateSkillScannerCheck says whether the gateway can scan a skill
// added mid-session: skill-scanner installed (lookPath) and its containment
// available (probe, a tracked run). Installed but not containable is a
// warning that names the cause and the fix: every such skill is refused
// unscanned.
func substrateSkillScannerCheck(binary string, lookPath func(string) (string, error), probe func() error) gateway.SubstrateCheck {
	out := gateway.SubstrateCheck{ID: substrateSkillScannerCheckID, Status: "pass"}
	if _, err := lookPath(binary); err != nil {
		out.Detail = "no skill-scanner in the gateway: a skill in the attested template is trusted by its digest, one added mid-session follows the fail mode"
		return out
	}
	err := probe()
	switch {
	case errors.Is(err, processutil.ErrContainmentUnavailable):
		out.Status, out.Fix = "warn", attest.ContainmentFix
		out.Detail = "skill-scanner present, containment unavailable: " + attest.ContainmentCause(err) + "; every skill added mid-session is refused unscanned"
	case errors.Is(err, processutil.ErrNotContained):
		out.Status, out.Fix = "warn", attest.ContainmentFix
		out.Detail = "skill-scanner present, but a contained test run failed: " + err.Error() + "; every skill added mid-session is refused unscanned"
	default:
		// The probe ran contained; its own exit status does not matter.
		out.Detail = "skill-scanner present and its containment works: skills added mid-session are scanned"
	}
	return out
}

// substrateContainmentProbe runs this binary under the scanner's
// containment (processutil.RunTracked), as a scan would.
func substrateContainmentProbe() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "--version")
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return processutil.RunTracked(cmd)
}
