// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The real machine-facing validator must retain an actionable, safe setting
// diagnostic instead of hiding an expected runtime refusal behind "$".
func TestCommonSandboxValidationDiagnostic(t *testing.T) {
	for _, tc := range []struct {
		name, source, path, reason string
	}{
		{
			"unavailable runtime",
			"sandbox: {enabled: true, runtime: axis, runtimes: {axis: {enabled: true}}}\n",
			"$.sandbox.runtime", "AXIS runtime is not available",
		},
		{
			"explicit policy conflict",
			"openshell: {yolo: false}\nsandbox: {yolo: true}\n",
			"$.sandbox.yolo", "conflicts with explicitly configured openshell.yolo",
		},
		{
			"nested explicit zero conflict",
			"openshell: {workdir: {git_depth: 17}}\nsandbox: {workdir: {git_depth: 0}}\n",
			"$.sandbox.workdir.git_depth", "conflicts with explicitly configured openshell.workdir.git_depth",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := fmt.Sprintf("config_version: 9\ndata_dir: %q\nobservability: {}\n%s", dir, tc.source)
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadConfigV8File(path, dir)
			if err == nil {
				t.Fatal("invalid common sandbox configuration was accepted")
			}
			failure := configV8ValidationFailure(err)
			if failure.Path != tc.path || failure.ConfigVersion != 9 || !strings.Contains(failure.Reason, tc.reason) {
				t.Fatalf("validator diagnostic = %+v; want path %s and reason %q", failure, tc.path, tc.reason)
			}
		})
	}
}
