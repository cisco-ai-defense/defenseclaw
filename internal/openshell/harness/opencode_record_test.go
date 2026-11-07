// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestOpenCodeImageUsesOnlyTheV2PackageAndVerifiedNativeBinary(t *testing.T) {
	resolution := connector.ResolveSandboxHookContract("opencode", OpenCode.DefaultVersion)
	if resolution.Status != connector.HookCompatibilityKnown || resolution.Contract.ContractID != "opencode-hooks-v2" {
		t.Fatalf("sandbox pin has no V2 contract: %+v", resolution)
	}
	if resolution := connector.ResolveSandboxHookContract("opencode", "1.18.31"); resolution.Status != connector.HookCompatibilityUnknown {
		t.Fatal("a V1 sandbox image is still admitted")
	}
	steps, err := OpenCode.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 || strings.Contains(steps[0].Run, "@opencode-ai/plugin") {
		t.Fatal("the V2 image must not fabricate a V1 plugin SDK installation")
	}
	// The command must launch the exact binary whose hash was checked, not
	// npm postinstall's separate copy selected by this build host's CPU.
	if !strings.Contains(steps[0].Run, `ln -sfn "$bin" /usr/local/bin/opencode`) {
		t.Fatal("the launch path is not the verified platform binary")
	}
}

func TestOpenCodePinnedVersionDisplay(t *testing.T) {
	sh := binSh(t)
	steps, err := OpenCode.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.LastIndex(steps[0].Run, `h="$(mktemp -d)"`)
	if start < 0 {
		t.Fatal("OpenCode install has no version check")
	}
	bin := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nprintf '%s\\n' \"$VERSION_REPLY\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	check := strings.Replace(steps[0].Run[start:], "/usr/local/bin/opencode --version", shellQuote(bin)+" --version", 1)
	for _, tc := range []struct {
		name, output string
		allow        bool
	}{
		{"version with release marker", "opencode v2.1.4", true},
		{"capitalized display name", "OpenCode v2.1.4", true},
		{"bare version", "2.1.4", true},
		{"different version", "opencode v2.1.5", false},
		{"extra version text", "opencode v2.1.4-extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(sh, "-c", check)
			cmd.Env = append(os.Environ(), "VERSION_REPLY="+tc.output)
			out, err := cmd.CombinedOutput()
			if (err == nil) != tc.allow {
				t.Fatalf("version %q: allowed=%t, want %t: %s", tc.output, err == nil, tc.allow, out)
			}
			if tc.allow {
				matches := OpenCode.Probe().VersionRE.FindStringSubmatch(tc.output)
				if len(matches) != 2 || matches[1] != OpenCode.DefaultVersion {
					t.Fatalf("probe version %q: %v", tc.output, matches)
				}
			}
		})
	}
}
