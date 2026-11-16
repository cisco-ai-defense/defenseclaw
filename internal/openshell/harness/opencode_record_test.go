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
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"mvdan.cc/sh/v3/interp"
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
	steps, err := OpenCode.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.LastIndex(steps[0].Run, `h="$(mktemp -d)"`)
	if start < 0 {
		t.Fatal("OpenCode install has no version check")
	}
	check := steps[0].Run[start:]
	version := OpenCode.DefaultVersion
	// A different but valid three-component release (the next patch). The
	// four-component form below is rejected by the shape check alone; this
	// sample is what proves the check compares the full pinned version.
	parts := strings.Split(version, ".")
	patch, err := strconv.Atoi(parts[len(parts)-1])
	if len(parts) != 3 || err != nil {
		t.Fatalf("pinned OpenCode version %q is not major.minor.patch", version)
	}
	parts[2] = strconv.Itoa(patch + 1)
	nextPatch := strings.Join(parts, ".")
	for _, tc := range []struct {
		name, output string
		allow        bool
	}{
		{"version with release marker", "opencode v" + version, true},
		{"capitalized display name", "OpenCode v" + version, true},
		{"bare version", version, true},
		{"different release", "opencode v" + nextPatch, false},
		{"different release without marker", nextPatch, false},
		{"four-component version", "opencode v" + version + ".1", false},
		{"extra version text", "opencode v" + version + "-extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runPinnedVersionScript(t, check, tc.output, func(ctx context.Context, args []string) error {
				switch {
				case len(args) == 2 && args[0] == "mktemp" && args[1] == "-d":
					_, err := fmt.Fprintln(interp.HandlerCtx(ctx).Stdout, "/tmp/image-version-check")
					return err
				case len(args) == 3 && args[0] == "rm" && args[1] == "-rf" && args[2] == "/tmp/image-version-check":
					return nil
				case len(args) == 2 && args[0] == "/usr/local/bin/opencode" && args[1] == "--version":
					_, err := fmt.Fprintln(interp.HandlerCtx(ctx).Stdout, tc.output)
					return err
				case len(args) == 3 && args[0] == "head" && args[1] == "-n" && args[2] == "1":
					line := bufio.NewScanner(interp.HandlerCtx(ctx).Stdin)
					if line.Scan() {
						_, err := fmt.Fprintln(interp.HandlerCtx(ctx).Stdout, line.Text())
						return err
					}
					return line.Err()
				default:
					return fmt.Errorf("unexpected image command %q", args)
				}
			})
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
