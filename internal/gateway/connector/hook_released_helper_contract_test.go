// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// GAP-1532: an upgrade writes the new _hardening.sh before it replaces the
// hook scripts, so for a moment a released 1.0.x script runs with the new
// helper. Every helper function a released script calls must still exist (in
// the new helper or in the script itself), or the call errors with "command
// not found" in the middle of the upgrade.
func TestReleasedHookScriptsFindEveryHelperTheyCall(t *testing.T) {
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	defined := regexp.MustCompile(`(?m)^(defenseclaw_[a-z0-9_]+)\(\)`)
	have := map[string]bool{}
	for _, m := range defined.FindAllStringSubmatch(string(helper), -1) {
		have[m[1]] = true
	}
	scripts, err := filepath.Glob(filepath.Join("testdata", "released-hooks", "1.*", "*.sh"))
	if err != nil || len(scripts) == 0 {
		t.Fatalf("released hook scripts: %v %v", scripts, err)
	}
	called := regexp.MustCompile(`\bdefenseclaw_[a-z0-9_]+\b`)
	for _, path := range scripts {
		if filepath.Base(path) == "_hardening.sh" {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		own := map[string]bool{}
		for _, m := range defined.FindAllStringSubmatch(string(raw), -1) {
			own[m[1]] = true
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, name := range called.FindAllString(line, -1) {
				if !have[name] && !own[name] {
					t.Errorf("%s calls %s, which the current _hardening.sh does not define", path, name)
				}
			}
		}
	}
}
