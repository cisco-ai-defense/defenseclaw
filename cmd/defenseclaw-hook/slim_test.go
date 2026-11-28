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
	"sort"
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
	"github.com/defenseclaw/defenseclaw/internal/guardrail/",
	"github.com/defenseclaw/defenseclaw/internal/telemetry",
	"github.com/defenseclaw/defenseclaw/internal/telemetry/",
	"go.opentelemetry.io/otel/sdk",
	"github.com/aws/aws-sdk-go-v2/",
	"github.com/maximhq/bifrost/",
	"github.com/open-policy-agent/opa/v1/rego",
	"github.com/open-policy-agent/opa/v1/topdown",
	// The JSON Schema library compiles its meta-schemas at package init
	// (1.7 ms and 1 MB per hook start), and its two users here: the OpenClaw
	// plugin config check of connector Setup, which the hook never runs (the
	// gateway and the CLI register it), and the v8 config schema check, which
	// the hook never reaches (every other program that links internal/config
	// registers it: TestEveryConfigProgramLinksTheFullConfig).
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/openclawschema",
	"github.com/defenseclaw/defenseclaw/internal/config/v8schema",
	"github.com/santhosh-tekuri/jsonschema/",
	// The v8 to v9 config migration's Rego parser and the SQLite driver it
	// opens the audit store with: the hook never migrates a config, and
	// internal/config/fullconfig links them where a migration can run. The
	// IDE inventory's state.vscdb reader, which the hook links on Windows
	// and never runs, opens the same driver by name
	// (TestEveryIDEInventoryProgramLinksTheSQLiteDriver).
	"github.com/defenseclaw/defenseclaw/internal/config/fullconfig",
	"github.com/defenseclaw/defenseclaw/internal/policy/regodata",
	"github.com/open-policy-agent/opa/",
	"modernc.org/",
}

// slimHookAllowed are the packages under a forbidden prefix the hook needs:
// the connector hook runtime, and the sandbox profile pack check its config
// load runs (openshell/packs and its egress rules, rel-1-0-10:GAP-0603), not
// the sandbox runtime.
var slimHookAllowed = []string{
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector",
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs",
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress",
	// The rule loader verdict on a custom pack (GAP-0603) and what it uses.
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded",
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic",
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb",
	// The tier column of a pack (tiers.yaml, DET111 D1): the rule loader
	// parses and checks it with the decide table (internal/guardrail
	// compose.go and rulepack.go; the outage fail mode reads its column).
	// decide links only the standard library and yaml.v3, which the hook
	// already links.
	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide",
}

// slimHookKnownHeavy are the heavy packages the hook links in 1.0.10 (the
// probe-A class of DESIGN 16.2): the outage mode, the asset facts and the
// foreign-hook guard read config.yaml and the machine policy through
// internal/config (the observability schema, the OPA AST, SQLite), and that
// load runs the checks the gateway runs, the rule loader verdict on a custom
// pack among them (internal/guardrail and its CEL compiler, GAP-0603). A
// change that drops one shrinks the hook: remove it from this list, and keep
// TestOutageModeGoldenMatchesTheFullCLIHook passing.
var slimHookKnownHeavy = []string{
	"github.com/defenseclaw/defenseclaw/internal/config",
	"github.com/defenseclaw/defenseclaw/internal/observability",
	"github.com/defenseclaw/defenseclaw/internal/guardrail",
	"github.com/google/cel-go/cel",
}

// slimHookMaxPackages bounds the package count per OS: 478 to 502 when W1
// landed, against 1213 to 1237 for the full-CLI main.
const slimHookMaxPackages = 540

// goToolOrSkip is the go tool for a go list of this package, or a skip
// where there is none: no go on PATH, or no module source around the test
// (a test binary copied to another host, as the native Windows gates run
// it, where go list failed and both link-set tests read as reds; INT
// accepted rows TestOutageGoldenSeesTheLinkSetOfTheMain and
// TestSlimHookLinksNoGatewayPackages). The Linux gates and CI run them
// from the source tree.
func goToolOrSkip(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	out, err := exec.Command(path, "env", "GOMOD").Output()
	if gomod := strings.TrimSpace(string(out)); err != nil || gomod == "" || gomod == os.DevNull {
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			// CI runs from the source tree; a missing module there is a red.
			t.Fatalf("go env GOMOD = %q, %v in CI", gomod, err)
		}
		t.Skipf("no module source here for go list (go env GOMOD = %q, %v)", gomod, err)
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
				if bad := slimHookForbiddenEntry(dep); bad != "" {
					t.Errorf("defenseclaw-hook links %s (forbidden: %s)", dep, bad)
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

// TestOpenClawPluginConfigCheckLinkedWhereSetupRuns pins the other half of
// the split above: every program that links a package running connector
// Setup (one that calls a connector's Setup, found in the source) links
// the package that registers the OpenClaw plugin config check
// (internal/gateway/openclaw_schema_link.go). Without it, Setup refuses an
// openclaw.json that carries a plugin config. The hook links
// internal/enterprisehooks but never runs Setup (enterprisehooks.Install is
// not in the hook binary). The callers and the programs, tagged mains among
// them, are discovered (GAP-1862: a fixed list of three packages before).
func TestOpenClawPluginConfigCheckLinkedWhereSetupRuns(t *testing.T) {
	gotool := goToolOrSkip(t)
	const (
		check = linkTestModule + "/internal/gateway/connector/openclawschema"
		hook  = linkTestModule + "/cmd/defenseclaw-hook"
	)
	files := moduleGoFiles(t)
	callers := connectorSetupCallers(t, files)
	// The two callers at the split: the gateway (and the CLI through it) and
	// enterprisehooks.Install, which the CLI calls.
	for _, want := range []string{"/internal/gateway", "/internal/enterprisehooks"} {
		if !callers[linkTestModule+want] {
			t.Errorf("connector Setup callers %v miss %s: the discovery is broken", callers, want)
		}
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		programs := 0
		for _, main := range mainPackages(t, gotool, goos, files) {
			if main.importPath == hook {
				continue
			}
			var runs []string
			for caller := range callers {
				if main.deps[caller] || main.importPath == caller {
					runs = append(runs, caller)
				}
			}
			if len(runs) == 0 {
				continue
			}
			programs++
			if !main.deps[check] {
				sort.Strings(runs)
				t.Errorf("%s: %s runs connector Setup (%s) but does not link %s", goos, main.importPath, strings.Join(runs, ", "), check)
			}
		}
		if programs == 0 {
			t.Errorf("%s: no program runs connector Setup: the discovery is broken", goos)
		}
		t.Logf("%s: %d programs run connector Setup", goos, programs)
	}
}

// TestEveryConfigProgramLinksTheFullConfig pins the other half of the
// config split: internal/config checks a v8 document and migrates a config
// with what internal/config/fullconfig registers or links (the v8 schema
// check, the SQLite driver, the Rego module check), and fails where it is not
// linked. Every main package that links internal/config, on every OS, links
// it too, as each linked those libraries before the split; the hook is the
// one program that does not, and it never checks a v8 document or migrates.
func TestEveryConfigProgramLinksTheFullConfig(t *testing.T) {
	gotool := goToolOrSkip(t)
	const (
		module = "github.com/defenseclaw/defenseclaw"
		cfg    = module + "/internal/config"
		check  = module + "/internal/config/fullconfig"
		hook   = module + "/cmd/defenseclaw-hook"
	)
	files := moduleGoFiles(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		programs := 0
		// Tagged mains too (GAP-1862: benchmarks/cmd/s7bench builds only
		// with -tags s7bench and was covered only through internal/gateway).
		for _, main := range mainPackages(t, gotool, goos, files) {
			deps := main.deps
			if !deps[cfg] {
				continue
			}
			programs++
			if main.importPath == hook {
				if deps[check] {
					t.Errorf("%s: %s links %s", goos, hook, check)
				}
				continue
			}
			if !deps[check] {
				t.Errorf("%s: %s links internal/config but not %s", goos, main.importPath, check)
			}
		}
		// 13 programs linked internal/config on each OS at the split.
		if programs < 13 {
			t.Errorf("%s: go list found %d programs that link internal/config, want at least 13", goos, programs)
		}
		t.Logf("%s: %d programs link internal/config", goos, programs)
	}
}

// TestEveryIDEInventoryProgramLinksTheSQLiteDriver pins the driver that
// internal/inventory/ideplugins opens state.vscdb with and does not import
// (vscdb.go): every main package that links the IDE inventory, on every OS,
// links modernc.org/sqlite, except the hook, which never scans.
func TestEveryIDEInventoryProgramLinksTheSQLiteDriver(t *testing.T) {
	gotool := goToolOrSkip(t)
	const (
		module    = "github.com/defenseclaw/defenseclaw"
		inventory = module + "/internal/inventory/ideplugins"
		driver    = "modernc.org/sqlite"
		hook      = module + "/cmd/defenseclaw-hook"
	)
	files := moduleGoFiles(t)
	for _, goos := range []string{"linux", "darwin", "windows"} {
		programs := 0
		for _, main := range mainPackages(t, gotool, goos, files) {
			if main.importPath == hook || !main.deps[inventory] {
				continue
			}
			programs++
			if !main.deps[driver] {
				t.Errorf("%s: %s links %s but not %s", goos, main.importPath, inventory, driver)
			}
		}
		if programs == 0 {
			t.Errorf("%s: go list found no program that links %s", goos, inventory)
		}
		t.Logf("%s: %d programs link the IDE inventory", goos, programs)
	}
}

// slimHookMaxBytes is the size budget of a release-flag build, the larger
// Windows build plus 2 MiB of room. DESIGN 16.5 test 2 named 45 MB for
// windows/amd64; W1 measured 47.7 MiB on Windows and the budget was 50 MiB
// through 1.0.11, when the hook stopped linking the JSON Schema library, the
// config migration's SQLite driver and Rego parser (internal/config/fullconfig):
// 40.8 MiB (42,789,888 bytes) on Windows and 36.7 MiB on Linux with the
// OpenShell SDK at github.com/ai-openshell/sdk-go v0.1.9 (rel-1-0-10:GAP-1773),
// against 144-151 MB for the full-CLI main. The CEL compiler of the rule loader stays:
// the hook links it so that a pinned custom pack sets the outage mode exactly
// as the gateway reads it (rel-1-0-10:GAP-0603). A change that needs more
// than the room left here adds a heavy library to every agent tool call.
//
// 1.0.11 DET111 (DET111 ruling a, 2026-11-24): the effects frontends of the
// one-read redesign grew the Windows hook to 45,191,680 bytes at T23c
// 08e285b2a6 and 45,381,632 at T23d (Linux 40,972,450), past 43 MiB. The
// budget is 44 MiB for 1.0.11; hook p99 (DET111 bar piece d) stays the
// latency gate, and the diet of what DET111 added is rel-1-0-10:GAP-2169.
const slimHookMaxBytes = 44 << 20

func TestSlimHookSizeBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the hook for two platforms")
	}
	if runtime.GOOS == "windows" {
		// A native Windows run has no go tool or module source, so it cannot
		// build the hook: it measures the defenseclaw-hook.exe the native build
		// shipped next to the test binaries (built with the release flags, as
		// the Linux run cross-builds it). Without one it skips, as at
		// 1.0.10: no native build ships the executable yet (the INT native
		// zip and the GitHub windows-native job both lack it), and the Linux
		// run still checks the Windows build's size.
		slimHookPrebuiltWindowsBudget(t)
		return
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

// slimHookPrebuiltExeEnv names the prebuilt Windows hook executable a native
// run measures. Without it the run looks for defenseclaw-hook.exe in the folders
// above the test's own, where the native build zip carries it (its root).
const slimHookPrebuiltExeEnv = "DEFENSECLAW_SLIM_HOOK_EXE"

func slimHookPrebuiltWindowsBudget(t *testing.T) {
	t.Helper()
	exe := os.Getenv(slimHookPrebuiltExeEnv)
	if exe == "" {
		dir, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 8 && exe == ""; i++ {
			candidate := filepath.Join(dir, "defenseclaw-hook.exe")
			if _, err := os.Stat(candidate); err == nil {
				exe = candidate
			}
			dir = filepath.Dir(dir)
		}
	}
	if exe == "" {
		t.Skipf("no prebuilt defenseclaw-hook.exe: set %s, or have the native build ship it at the root of its zip", slimHookPrebuiltExeEnv)
	}
	info, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > slimHookMaxBytes {
		t.Fatalf("windows/amd64 defenseclaw-hook is %d bytes, budget %d", info.Size(), slimHookMaxBytes)
	}
	t.Logf("windows/amd64: %d bytes", info.Size())
}

// slimHookForbiddenEntry returns the slimHookForbidden entry dep matches,
// or "" when none does or an allowed entry covers dep more specifically. The
// connector hook runtime is allowed below internal/gateway/, but a forbidden
// entry that names a package below it (the OpenClaw plugin config check,
// internal/gateway/connector/openclawschema) still wins (GAP-1862: the
// allowed prefix used to exempt it).
func slimHookForbiddenEntry(dep string) string {
	allowed := slimHookAllowedEntry(dep)
	for _, bad := range slimHookForbidden {
		matches := dep == bad || (strings.HasSuffix(bad, "/") && strings.HasPrefix(dep, bad))
		if matches && len(strings.TrimSuffix(bad, "/")) > len(allowed) {
			return bad
		}
	}
	return ""
}

// slimHookAllowedEntry returns the longest slimHookAllowed entry that
// covers dep: the package itself, or a package below it (only the exact
// package for the guardrail entries), or "" for none.
func slimHookAllowedEntry(dep string) string {
	best := ""
	for _, allowed := range slimHookAllowed {
		if (dep == allowed || (!strings.Contains(allowed, "/guardrail/") && strings.HasPrefix(dep, allowed+"/"))) && len(allowed) > len(best) {
			best = allowed
		}
	}
	return best
}

func TestSlimHookForbiddenEntryWinsOverABroaderAllow(t *testing.T) {
	for dep, want := range map[string]bool{
		linkTestModule + "/internal/gateway/connector/openclawschema": true,
		linkTestModule + "/internal/gateway/connector":                false,
		linkTestModule + "/internal/gateway/connector/hookproto":      false,
		linkTestModule + "/internal/gateway":                          true,
		linkTestModule + "/internal/gateway/router":                   true,
		linkTestModule + "/internal/guardrail/bounded":                false,
		linkTestModule + "/internal/guardrail/bounded/x":              true,
		"github.com/santhosh-tekuri/jsonschema/v6":                    true,
	} {
		if got := slimHookForbiddenEntry(dep) != ""; got != want {
			t.Errorf("slimHookForbiddenEntry(%s) forbidden = %v, want %v", dep, got, want)
		}
	}
}
