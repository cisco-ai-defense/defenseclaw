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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// slimHookForbidden are packages the hook binary must not link (DESIGN 16.5
// test 1): the gateway command tree, the gateway server, the cloud SDKs, the
// LLM router, the sandbox runtime and the Rego evaluator. Every agent tool
// call starts the hook, so each of them costs start CPU per call.
var slimHookForbidden = []string{
	"github.com/defenseclaw/defenseclaw/internal/audit",
	"github.com/defenseclaw/defenseclaw/internal/audit/",
	"github.com/defenseclaw/defenseclaw/internal/cli",
	"github.com/defenseclaw/defenseclaw/internal/cli/",
	"github.com/defenseclaw/defenseclaw/internal/gateway",
	"github.com/defenseclaw/defenseclaw/internal/gateway/",
	"github.com/defenseclaw/defenseclaw/internal/openshell",
	"github.com/defenseclaw/defenseclaw/internal/openshell/",
	"github.com/defenseclaw/defenseclaw/internal/guardrail",
	"github.com/defenseclaw/defenseclaw/internal/guardrail/",
	"github.com/defenseclaw/defenseclaw/internal/telemetry",
	"github.com/defenseclaw/defenseclaw/internal/telemetry/",
	"github.com/google/cel-go/",
	"go.opentelemetry.io/otel/sdk",
	"google.golang.org/protobuf/",
	"github.com/aws/aws-sdk-go-v2/",
	"github.com/maximhq/bifrost/",
	"github.com/open-policy-agent/opa/v1/rego",
	"github.com/open-policy-agent/opa/v1/topdown",
}

// slimHookAllowed are the light packages under a forbidden prefix the hook
// needs: the connector hook runtime and the bounded readers of the guardrail.
var slimHookAllowed = []string{
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector",
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded",
}

// slimHookKnownHeavy are the heavy packages the hook still links in 1.0.10
// (between the probe-A and probe-B classes of DESIGN 16.2): the outage mode,
// the asset facts and the foreign-hook guard read config.yaml and the
// machine policy through internal/config, which links the observability
// schema, the OPA AST and SQLite. A change that drops one of them shrinks
// the hook further: remove it from this list.
var slimHookKnownHeavy = []string{
	"github.com/defenseclaw/defenseclaw/internal/config",
	"github.com/defenseclaw/defenseclaw/internal/observability",
	"github.com/open-policy-agent/opa/v1/ast",
	"modernc.org/sqlite",
}

// slimHookMaxPackages bounds the package count per OS: 383 to 410 when W1
// landed, against 1213 to 1237 for the full-CLI main.
const slimHookMaxPackages = 450

func goToolOrSkip(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	return path
}

func TestSlimHookLinksNoGatewayPackages(t *testing.T) {
	gotool := goToolOrSkip(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			cmd := exec.Command(gotool, "list", "-deps", ".")
			cmd.Env = append(os.Environ(), "GOOS="+goos, "CGO_ENABLED=0")
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps: %v", err)
			}
			deps := strings.Fields(string(out))
			linked := map[string]bool{}
			for _, dep := range deps {
				linked[dep] = true
				if slimHookAllowedPackage(dep) {
					continue
				}
				for _, bad := range slimHookForbidden {
					if dep == bad || (strings.HasSuffix(bad, "/") && strings.HasPrefix(dep, bad)) {
						t.Errorf("defenseclaw-hook links %s", dep)
					}
				}
			}
			for _, heavy := range slimHookKnownHeavy {
				if !linked[heavy] {
					t.Errorf("defenseclaw-hook no longer links %s: remove it from slimHookKnownHeavy", heavy)
				}
			}
			if len(deps) > slimHookMaxPackages {
				t.Errorf("defenseclaw-hook links %d packages, budget %d", len(deps), slimHookMaxPackages)
			}
			t.Logf("%s: %d packages", goos, len(deps))
		})
	}
}

// slimHookMaxBytes is the size budget of a release-flag build (DESIGN 16.5
// test 2: windows/amd64 at most 45 MB). W1 measured about 41 MB on Windows,
// against 151 MB for the full-CLI main.
const slimHookMaxBytes = 45 << 20

func TestSlimHookSizeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the hook for two platforms")
	}
	if runtime.GOOS != "linux" {
		// One check is enough: the Linux run cross-builds both targets.
		t.Skip("the size budget is checked on Linux, for the Windows and Linux builds")
	}
	gotool := goToolOrSkip(t)
	for _, target := range []struct{ goos, goarch, ldflags string }{
		{"windows", "amd64", "-s -w -H=windowsgui"},
		{"linux", "amd64", "-s -w"},
	} {
		t.Run(target.goos, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "defenseclaw-hook")
			cmd := exec.Command(gotool, "build", "-trimpath", "-buildvcs=false", "-ldflags", target.ldflags, "-o", out, ".")
			cmd.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.goarch, "CGO_ENABLED=0")
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, output)
			}
			info, err := os.Stat(out)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() > slimHookMaxBytes {
				t.Fatalf("%s/%s defenseclaw-hook is %d bytes, budget %d", target.goos, target.goarch, info.Size(), slimHookMaxBytes)
			}
			t.Logf("%s/%s: %d bytes", target.goos, target.goarch, info.Size())
		})
	}
}

func slimHookAllowedPackage(dep string) bool {
	for _, allowed := range slimHookAllowed {
		if dep == allowed || strings.HasPrefix(dep, allowed+"/") {
			return true
		}
	}
	return false
}
