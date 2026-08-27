// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// TestSupplyChainStdlibOnly guards the reproducibility-critical
// windows-repro-manifest binary against picking up a third-party
// dependency. See docs/specs/001-windows-deterministic-build/plan.md
// § Security Plan: "The Go helper has no third-party dependencies
// beyond the stdlib."
//
// A third-party dep would:
//   - increase the vendored tree size (bumping against the 300 MB
//     build-kit ceiling in Workstream E REQ-11), and
//   - couple our JSON byte-stability contract to that dep's own
//     versioning cadence, which is exactly the variance we removed
//     by writing this binary in the first place.
//
// The check runs `go list -deps -f '{{.Module}}' ./...` and asserts
// every non-empty module resolves to the defenseclaw module (the
// binary itself) or is blank (the stdlib).
func TestSupplyChainStdlibOnly(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.Module}}", ".")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go list -deps: %v\nstderr: %s", err, stderr.String())
	}
	const allowed = "github.com/defenseclaw/defenseclaw"
	var offenders []string
	for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		line = strings.TrimSpace(line)
		// `go list -f '{{.Module}}'` prints `<nil>` for stdlib packages
		// (Go's format for a nil *Module pointer) and the empty string
		// on Go versions that null-check first. Both mean stdlib.
		if line == "" || line == "<nil>" {
			continue
		}
		// Otherwise the module field is "<path> <version>" for versioned
		// modules and "<path>" for the main module. Match on the module
		// path in the first field.
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == allowed {
			continue
		}
		offenders = append(offenders, line)
	}
	if len(offenders) > 0 {
		t.Fatalf("cmd/windows-repro-manifest must depend only on stdlib + %s\nunexpected deps:\n  %s",
			allowed, strings.Join(offenders, "\n  "))
	}
}
