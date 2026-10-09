// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const codexRequirements = "/etc/codex/requirements.toml"

var claudeDropIn = "/etc/claude-code/managed-settings.d/" + enterprisepolicy.DefenseClawDropInName

func machinePolicyConfig(t *testing.T, h *testHost, connectors ...string) string {
	t.Helper()
	body := string(DefaultConfig(h.env.Layout)) + "  connectors:\n"
	for _, name := range connectors {
		body += "    " + name + ": {}\n"
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

func descriptorConnectors(t *testing.T, h *testHost) []string {
	t.Helper()
	descriptor, err := managed.ParseRuntimeDescriptor([]byte(h.read(h.env.Layout.DescriptorPath)))
	if err != nil {
		t.Fatal(err)
	}
	return descriptor.MachinePolicyConnectors
}

func TestHookBinaryIsTheMachinePolicyCommand(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := path.Join(layout.BinDir, binHook), enterprisepolicy.HookBinaryPath(layout); got != want {
			t.Fatalf("%s: lifecycle installs %s, machine policy invokes %s", goos, got, want)
		}
		if !contains(requiredBinaries, binHook) {
			t.Fatalf("%s: the hook binary is not a required payload binary", goos)
		}
	}
}

func TestInstallPublishesMachinePolicyAndRecordsIt(t *testing.T) {
	h := newTestHost(t, "linux")
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode", "antigravity")})
	requireOK(t, r)
	hook := enterprisepolicy.HookBinaryPath(h.env.Layout)
	if !strings.Contains(h.read(codexRequirements), hook) {
		t.Fatalf("Codex requirements do not invoke %s:\n%s", hook, h.read(codexRequirements))
	}
	if !strings.Contains(h.read(claudeDropIn), hook) {
		t.Fatalf("Claude drop-in does not invoke %s", hook)
	}
	if got := descriptorConnectors(t, h); !reflect.DeepEqual(got, []string{"claudecode", "codex"}) {
		t.Fatalf("descriptor machine policy connectors %v", got)
	}
	record, _ := h.env.loadDeployment()
	if !reflect.DeepEqual(record.MachinePolicyConnectors, []string{"claudecode", "codex"}) {
		t.Fatalf("record machine policy connectors %v", record.MachinePolicyConnectors)
	}
	if _, ok := r.MachinePolicy["codex"]; !ok {
		t.Fatalf("result lacks the codex machine policy state: %+v", r.MachinePolicy)
	}
	if hasWarning(r, codeMachinePolicyIncomplete) {
		t.Fatalf("unexpected incomplete warning: %+v", r.Warnings)
	}
	if !exists(h.env.P(filepath.Join(h.env.Layout.ConfigDir, enterprisepolicy.PublicPolicyFileName))) {
		t.Fatal("the public foreign-hook guard summary was not written")
	}

	// A second ensure is a no-op; removing DefenseClaw's Codex entry is
	// drift that ensure repairs.
	noop := h.run(Options{Action: ActionEnsure})
	requireOK(t, noop)
	if !noop.Noop {
		t.Fatalf("ensure after install should be a no-op: %+v", noop.Warnings)
	}
	if err := os.Remove(h.env.P(codexRequirements)); err != nil {
		t.Fatal(err)
	}
	repaired := h.run(Options{Action: ActionEnsure})
	requireOK(t, repaired)
	if repaired.Noop {
		t.Fatal("ensure ignored removed machine policy")
	}
	if !strings.Contains(h.read(codexRequirements), hook) {
		t.Fatal("ensure did not restore the Codex machine policy")
	}
}

func TestUninstallRemovesOnlyDefenseClawMachinePolicy(t *testing.T) {
	h := newTestHost(t, "linux")
	admin := "# administrator requirements\nallowed_approval_policies = [\"on-request\"]\n"
	if err := os.MkdirAll(h.env.P("/etc/codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(codexRequirements), []byte(admin), 0o644); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode")}))
	if got := h.read(codexRequirements); got == admin || !strings.Contains(got, "allowed_approval_policies") {
		t.Fatalf("install must merge into the administrator's requirements:\n%s", got)
	}
	r := h.run(Options{Action: ActionUninstall})
	requireOK(t, r)
	if got := h.read(codexRequirements); got != admin {
		t.Fatalf("uninstall changed the administrator's requirements:\n%q\nwant\n%q", got, admin)
	}
	if exists(h.env.P(claudeDropIn)) {
		t.Fatal("uninstall kept DefenseClaw's Claude drop-in")
	}
}

func TestFailedFirstInstallRemovesMachinePolicy(t *testing.T) {
	h := newTestHost(t, "linux")
	h.services.failStart[unitGateway] = errors.New("boom")
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode")})
	requireError(t, r, codeActivate)
	if exists(h.env.P(claudeDropIn)) || exists(h.env.P(codexRequirements)) {
		t.Fatal("a failed first install left DefenseClaw machine policy behind")
	}
}

// partialPolicy publishes through the real writers but refuses one
// connector, as a vendor file DefenseClaw cannot merge into would.
type partialPolicy struct {
	real    MachinePolicyManager
	refused string
}

func (p *partialPolicy) Intended(cfg *config.Config) ([]string, error) { return p.real.Intended(cfg) }
func (p *partialPolicy) RemoveAll() (enterprisepolicy.Result, error)   { return p.real.RemoveAll() }
func (p *partialPolicy) Verify(cfg *config.Config) (enterprisepolicy.Result, error) {
	return p.filter(p.real.Verify(cfg))
}
func (p *partialPolicy) Publish(cfg *config.Config) (enterprisepolicy.Result, error) {
	result, err := p.real.Publish(cfg)
	result, _ = p.filter(result, err)
	return result, errors.Join(err, errors.New(p.refused+": vendor file refused the entry"))
}

func (p *partialPolicy) filter(result enterprisepolicy.Result, err error) (enterprisepolicy.Result, error) {
	kept := []string{}
	for _, name := range result.MachinePolicyConnectors {
		if name != p.refused {
			kept = append(kept, name)
		}
	}
	result.MachinePolicyConnectors = kept
	return result, err
}

func TestPartiallyPublishedMachinePolicyIsReportedAndSettles(t *testing.T) {
	h := newTestHost(t, "linux")
	h.env.MachinePolicy = &partialPolicy{real: &policyManager{env: h.env, skipTrust: true}, refused: "codex"}
	r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode")})
	requireOK(t, r)
	if !hasWarning(r, codeMachinePolicyIncomplete) {
		t.Fatalf("a refused connector must be reported: %+v", r.Warnings)
	}
	if got := descriptorConnectors(t, h); !reflect.DeepEqual(got, []string{"claudecode"}) {
		t.Fatalf("descriptor must name only covered connectors, got %v", got)
	}
	record, _ := h.env.loadDeployment()
	if !reflect.DeepEqual(record.MachinePolicyConnectors, []string{"claudecode"}) {
		t.Fatalf("record machine policy connectors %v", record.MachinePolicyConnectors)
	}
	if problems := (&lifecycle{env: h.env, opts: Options{}, result: r}).verifyInstalled(t.Context(), record, false); len(problems) > 0 {
		t.Fatalf("the rewritten descriptor must match the record: %v", problems)
	}
	// The same config does not make ensure re-apply (and restart) forever.
	calls := len(h.services.calls)
	again := h.run(Options{Action: ActionEnsure})
	requireOK(t, again)
	if !again.Noop || len(h.services.calls) != calls {
		t.Fatalf("ensure with a persistently refused connector must settle: noop=%v calls %d -> %d", again.Noop, calls, len(h.services.calls))
	}
}

// heldRetirePolicy publishes through the real writers, except that a
// connector leaving machine policy cannot be retired: its vendor file is held
// by another tool (chattr +i), so its entries stay.
type heldRetirePolicy struct {
	MachinePolicyManager
	held string
}

func (p *heldRetirePolicy) Publish(cfg *config.Config) (enterprisepolicy.Result, error) {
	intended, err := p.Intended(cfg)
	if err != nil || contains(intended, p.held) {
		return p.MachinePolicyManager.Publish(cfg)
	}
	result, err := p.Verify(cfg)
	return result, errors.Join(err, &enterprisepolicy.RetireError{Connector: p.held, Err: errors.New("remove " + claudeDropIn + ": operation not permitted")})
}

// GAP-0743: removing claudecode from guardrail.connectors while another tool
// held 90-defenseclaw.json returned ok and committed the config; the hooks
// stayed and the gateway refused every Claude Code prompt while status and
// verify were green. The run now fails with machine_policy_failed, rolls back
// and keeps the previous config, which still serves Claude Code.
func TestRetiringAConnectorWhoseVendorFileIsHeldRollsBack(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex", "claudecode")}))
	before, _ := h.env.loadDeployment()
	h.env.MachinePolicy = &heldRetirePolicy{MachinePolicyManager: h.env.MachinePolicy, held: enterprisepolicy.ConnectorClaudeCode}
	r := h.run(Options{Action: ActionEnsure, ConfigFile: machinePolicyConfig(t, h, "codex")})
	requireError(t, r, codeMachinePolicy)
	if r.ExitCode != 1 || !hasWarning(r, codeRolledBack) {
		t.Fatalf("a held vendor file must fail and roll back the run: exit %d warnings %+v", r.ExitCode, r.Warnings)
	}
	after, _ := h.env.loadDeployment()
	if after.ConfigSHA256 != before.ConfigSHA256 || !reflect.DeepEqual(descriptorConnectors(t, h), []string{"claudecode", "codex"}) {
		t.Fatalf("the previous config must stay in force: config %s -> %s, descriptor %v", before.ConfigSHA256, after.ConfigSHA256, descriptorConnectors(t, h))
	}
}

func TestVerifyReportsMissingMachinePolicy(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	data, _ := json.Marshal(map[string]any{"version": 1, "updated_at": h.env.Now().UTC().Format("2006-01-02T15:04:05Z"), "ok": true})
	h.publishLedger(data)
	requireOK(t, h.run(Options{Action: ActionVerify}))
	if err := os.Remove(h.env.P(claudeDropIn)); err != nil {
		t.Fatal(err)
	}
	requireError(t, h.run(Options{Action: ActionVerify}), codeVerify)
	reconciled := h.run(Options{Action: ActionReconcile})
	requireOK(t, reconciled)
	if !exists(h.env.P(claudeDropIn)) {
		t.Fatal("reconcile did not restore the Claude drop-in")
	}
	requireOK(t, h.run(Options{Action: ActionVerify}))
}

// A DefenseClaw entry removed from vendor machine policy was reported twice
// with a generic "vendor machine policy changed since the last transaction;
// run ensure" that named neither the connector nor the file, while the
// lifecycle help offers repair for it. It is reported once, names both, and
// the command it names restores the entry.
func TestVerifyNamesTheConnectorAndFileOfMachinePolicyDrift(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	writeFreshLedger(t, h)
	if err := os.Remove(h.env.P(claudeDropIn)); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	var about []string
	for _, e := range verify.Errors {
		if strings.Contains(e.Message, "machine policy") {
			about = append(about, e.Message)
		}
	}
	if len(about) != 1 {
		t.Fatalf("want one machine-policy problem, got %d: %q", len(about), about)
	}
	repair := "/opt/defenseclaw/bin/defenseclaw-gateway enterprise linux repair"
	if !strings.Contains(about[0], "claudecode (") || !strings.Contains(about[0], claudeDropIn) || !strings.Contains(about[0], "`"+repair+"`") {
		t.Fatalf("the problem does not name the connector, file and repair: %q", about[0])
	}
	// status agrees: the agent runs without hooks (GAP-0529).
	if status := h.run(Options{Action: ActionStatus}); status.OK || status.SecurityComplete {
		t.Fatalf("status with the drop-in gone: ok=%v security_complete=%v", status.OK, status.SecurityComplete)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if !exists(h.env.P(claudeDropIn)) {
		t.Fatal("repair did not restore the Claude drop-in")
	}
	requireOK(t, h.run(Options{Action: ActionVerify}))
}

// GAP-0957: a skill default deny or registry_required with runtime_detection
// left at its default has no enforcement point on a managed Linux or macOS
// host, which runs no install watcher for skills. ensure and status say so,
// and runtime_detection on clears the warning.
func TestLifecycleWarnsWhenSkillDefaultDenyHasNoEnforcementPoint(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			config := func(extra string) string {
				body := string(DefaultConfig(h.env.Layout)) + "  connectors:\n    claudecode: {}\n" +
					"asset_policy:\n  enabled: true\n  mode: action\n  skill:\n    default: deny\n" +
					"    registry:\n      - name: acme-review\n" + extra
				file := filepath.Join(t.TempDir(), "config.yaml")
				if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				return file
			}
			r := h.run(Options{Action: ActionEnsure, ConfigFile: config("")})
			if got := messagesOf(r.Warnings, "asset_policy_not_enforced"); !strings.Contains(got, "asset_policy.skill default: deny is not enforced") {
				t.Fatalf("ensure does not warn that the skill default deny is inert: %+v", r.Warnings)
			}
			if r := h.run(Options{Action: ActionStatus}); !hasWarning(r, "asset_policy_not_enforced") {
				t.Fatalf("status does not warn that the skill default deny is inert: %+v", r.Warnings)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: config("    runtime_detection:\n      enabled: true\n")}))
			if r := h.run(Options{Action: ActionStatus}); hasWarning(r, "asset_policy_not_enforced") {
				t.Fatalf("the warning stays with runtime_detection on: %+v", r.Warnings)
			}
		})
	}
}

// With the documented standalone config (no guardrail.connectors block) the
// enumerator found eligible users but published no target, and status and
// verify still reported coverage and security complete with 0 targets. verify
// now fails on it (GAP-0221).
func TestStatusWarnsWhenNoConnectorIsEnabledForEligibleUsers(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			eligible := filepath.Join(filepath.Dir(h.env.Layout.ManifestPath), "eligible-accounts.json")
			writeHostFile(t, h, eligible, `{"version": 1, "accounts": [{"user": "alice", "uid": 501}, {"user": "bob", "uid": 502}]}`)
			for _, action := range []string{ActionStatus, ActionVerify} {
				r := h.run(Options{Action: action})
				if got := messagesOf(r.Warnings, "no_connectors_enabled"); !strings.Contains(got, "found 2 eligible users") || !strings.Contains(got, "guardrail.connectors") {
					t.Fatalf("%s does not warn that no connector is enabled: %+v", action, r.Warnings)
				}
				if r.SecurityComplete {
					t.Fatalf("%s reports security_complete with no connector enabled", action)
				}
				if action == ActionVerify && !strings.Contains(messagesOf(r.Errors, codeVerify), "enables no connector the managed deployment protects") {
					t.Fatalf("verify passes with no connector enabled: %+v", r.Errors)
				}
			}
			// ensure warns too, as on Windows (GAP-0266), and an explicit
			// disable beats the singular guardrail.connector (GAP-0263).
			disabled := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(disabled, append(DefaultConfig(h.env.Layout), "  connector: claudecode\n  connectors:\n    claudecode:\n      enabled: false\n    openclaw: {}\n"...), 0o600); err != nil {
				t.Fatal(err)
			}
			r := h.run(Options{Action: ActionEnsure, ConfigFile: disabled})
			if !hasWarning(r, "no_connectors_enabled") || r.SecurityComplete {
				t.Fatalf("ensure does not warn that no connector is enabled: %+v", r.Warnings)
			}
			// The warning names the entries it ignored (GAP-0272)...
			if got := messagesOf(r.Warnings, "no_connectors_enabled"); !strings.Contains(got, "(ignored: claudecode (enabled: false), openclaw (not supported") {
				t.Fatalf("the warning does not name the ignored entries: %q", got)
			}
			// ...and ensure publishes no machine policy for the disabled connector

			// either (GAP-0267).
			if _, published := r.MachinePolicy["claudecode"]; published || (goos == "linux" && exists(h.env.P(claudeDropIn))) {
				t.Fatalf("ensure published machine policy for a disabled connector: %+v", r.MachinePolicy)
			}

			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
			if r := h.run(Options{Action: ActionStatus}); hasWarning(r, "no_connectors_enabled") {
				t.Fatalf("the warning stays with a connector enabled: %+v", r.Warnings)
			}
			// The singular guardrail.connector (the shape the per-user CLI
			// writes) enrols the connector too, so verify passes (GAP-0263).
			single := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(single, append(DefaultConfig(h.env.Layout), "  connector: claudecode\n"...), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: single}))
			requireOK(t, h.run(Options{Action: ActionVerify}))
			if goos == "linux" && !strings.Contains(h.read("/etc/systemd/system/"+unitGuardian+".d/"+dropinPaths), "ReadWritePaths=-/etc/claude-code") {
				t.Fatal("the guardian sandbox does not allow the Claude Code machine-policy folder for guardrail.connector")
			}
		})
	}
}

func TestDarwinInstallPublishesMachinePolicy(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	dropIn := "/Library/Application Support/ClaudeCode/managed-settings.d/" + enterprisepolicy.DefenseClawDropInName
	if !strings.Contains(h.read(dropIn), enterprisepolicy.HookBinaryPath(h.env.Layout)) {
		t.Fatalf("macOS Claude drop-in does not invoke the standalone hook binary")
	}
	if got := descriptorConnectors(t, h); !reflect.DeepEqual(got, []string{"claudecode"}) {
		t.Fatalf("descriptor machine policy connectors %v", got)
	}
}

// The payload ships the managed OpenCode plugin on Linux and macOS: the
// lifecycle renders it into the install root, and the first install already
// publishes OpenCode through machine policy and records it in the
// descriptor (before this, OpenCode fell back to per-user hooks on every
// host because nothing installed the plugin).
func TestInstallShipsTheManagedOpenCodePlugin(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "opencode", "claudecode")})
			requireOK(t, r)
			plugin := enterprisepolicy.OpenCodeManagedPluginPath(h.env.Layout)
			if got := h.read(plugin); got != string(enterprisepolicy.OpenCodeManagedPlugin()) {
				t.Fatalf("%s does not hold the shipped managed plugin", plugin)
			}
			if got := h.mode(plugin); got != 0o644 {
				t.Fatalf("managed plugin mode %04o, want 0644", got)
			}
			if got := h.mode(filepath.Dir(plugin)); got != 0o755 {
				t.Fatalf("managed plugin directory mode %04o, want 0755", got)
			}
			config := "/etc/opencode/opencode.json"
			if goos == "darwin" {
				config = "/Library/Application Support/opencode/opencode.json"
			}
			if !strings.Contains(h.read(config), `"`+plugin+`"`) {
				t.Fatalf("OpenCode managed config does not name %s:\n%s", plugin, h.read(config))
			}
			if got := descriptorConnectors(t, h); !reflect.DeepEqual(got, []string{"claudecode", "opencode"}) {
				t.Fatalf("the first install must record OpenCode as machine policy, got %v", got)
			}
			if state, ok := r.MachinePolicy["opencode"]; !ok || len(state.Conflicts) != 0 {
				t.Fatalf("OpenCode machine policy state: %+v (present %v)", state, ok)
			}
			if hasWarning(r, codeMachinePolicyIncomplete) {
				t.Fatalf("unexpected incomplete warning: %+v", r.Warnings)
			}
			record, _ := h.env.loadDeployment()
			if _, ok := record.Files[plugin]; !ok {
				t.Fatalf("the managed plugin is not a recorded deployment file")
			}

			noop := h.run(Options{Action: ActionEnsure})
			requireOK(t, noop)
			if !noop.Noop {
				t.Fatalf("ensure after install should be a no-op: %+v", noop.Warnings)
			}
			if err := os.WriteFile(h.env.P(plugin), []byte("export default {}"), 0o644); err != nil {
				t.Fatal(err)
			}
			if problems := (&lifecycle{env: h.env, opts: Options{}, result: r}).verifyInstalled(t.Context(), record, false); !strings.Contains(strings.Join(problems, "\n"), plugin+" was modified after install") {
				t.Fatalf("verify must report the edited plugin: %v", problems)
			}
			repaired := h.run(Options{Action: ActionEnsure})
			requireOK(t, repaired)
			if repaired.Noop || h.read(plugin) != string(enterprisepolicy.OpenCodeManagedPlugin()) {
				t.Fatal("ensure did not restore the managed plugin")
			}

			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if exists(h.env.P(plugin)) || exists(h.env.P(filepath.Dir(plugin))) {
				t.Fatal("uninstall left the managed plugin behind")
			}
			if exists(h.env.P(config)) && strings.Contains(h.read(config), plugin) {
				t.Fatalf("uninstall left DefenseClaw's OpenCode entry:\n%s", h.read(config))
			}
		})
	}
}

// With OpenCode's machine policy ownership off the lifecycle still renders
// the managed plugin file but leaves OpenCode on the per-user route (no
// managed config entry, not in the descriptor). The guard summary must say
// per-user too: on machine policy the per-user plugin's own foreign-plugin
// check would deny every OpenCode tool call on DefenseClaw's own plugin.
func TestOpenCodeOwnershipOffKeepsTheGuardSummaryPerUser(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			cfg := machinePolicyConfig(t, h, "opencode", "claudecode")
			body, err := os.ReadFile(cfg)
			if err != nil {
				t.Fatal(err)
			}
			off := strings.Replace(string(body), "enterprise:\n  profile: standalone\n",
				"enterprise:\n  profile: standalone\n  machine_policy:\n    connectors:\n      opencode:\n        ownership: \"off\"\n", 1)
			if off == string(body) {
				t.Fatal("test config has no enterprise block to extend")
			}
			if err := os.WriteFile(cfg, []byte(off), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: cfg}))
			if !exists(h.env.P(enterprisepolicy.OpenCodeManagedPluginPath(h.env.Layout))) {
				t.Fatal("the payload still renders the managed plugin")
			}
			if got := descriptorConnectors(t, h); !reflect.DeepEqual(got, []string{"claudecode"}) {
				t.Fatalf("ownership off must keep OpenCode out of the descriptor, got %v", got)
			}
			summary, err := enterprisepolicy.ParsePublicPolicy([]byte(h.read(filepath.Join(h.env.Layout.ConfigDir, enterprisepolicy.PublicPolicyFileName))))
			if err != nil {
				t.Fatal(err)
			}
			if got := summary.Connectors["opencode"]; got.Route != enterprisepolicy.RoutePerUser || !got.Guard {
				t.Fatalf("summary OpenCode entry %+v, want the guarded per-user route", got)
			}
		})
	}
}

// envRunner records the environment the lifecycle passes to the gateway CLI.
type envRunner struct {
	*fakeRunner
	envs map[string][]string
}

func (r *envRunner) RunEnv(ctx context.Context, env []string, name string, args ...string) (CommandResult, error) {
	r.envs[strings.Join(args, " ")] = env
	return r.fakeRunner.Run(ctx, name, args...)
}

func TestUninstallRemovesPerUserHooksWithTheServiceEnvironment(t *testing.T) {
	h := newTestHost(t, "linux")
	runner := &envRunner{fakeRunner: h.runner, envs: map[string][]string{}}
	h.env.Runner = runner
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "devin")}))
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	key := "enterprise hooks remove-all --manifest " + h.env.Layout.ManifestPath + " --json"
	env, ok := runner.envs[key]
	if !ok {
		t.Fatalf("uninstall did not remove per-user hooks; calls: %v", h.runner.calls)
	}
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"DEFENSECLAW_CONFIG=" + h.env.Layout.ConfigPath,
		managed.EnterpriseProfileEnv + "=" + managed.ProfileStandalone,
		managed.DeploymentModeEnv + "=" + managed.DeploymentModeManagedEnterprise,
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("service environment lacks %s:\n%s", want, joined)
		}
	}
}

// The Copilot VS Code Local hook file is the guardian's (WIN-R1-25, #1055):
// status and verify fail while an enrolled user's copy is missing or
// edited, and pass once the guardian has rewritten it.
func TestVerifyFailsWhileTheCopilotLocalHookFileIsMissing(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "copilot")}))
	writeFreshLedger(t, h)
	eligible := filepath.Join(filepath.Dir(h.env.Layout.ManifestPath), "eligible-accounts.json")
	writeHostFile(t, h, eligible, `{"version": 1, "accounts": [{"user": "alice", "uid": 501, "home": "/home/alice"}]}`)
	if err := os.Chmod(h.env.P(eligible), 0o600); err != nil { // as the guardian writes it
		t.Fatal(err)
	}
	hookFile := enterprisepolicy.CopilotVSCodeLocalHookFilePath("/home/alice")
	if err := os.MkdirAll(h.env.P("/home/alice"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Before the guardian's first pass for alice the file is pending: a
	// warning, not a failure (GAP-1267).
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := h.run(Options{Action: action})
		requireOK(t, got)
		if !strings.Contains(messagesOf(got.Warnings, codeGuardianUserFilePending), hookFile) {
			t.Fatalf("%s must warn that the Local hook file is pending: %+v", action, got.Warnings)
		}
	}
	// The guardian records alice in its data directory, where it writes
	// the record (GAP-1761).
	writeHostFile(t, h, filepath.Join(h.env.Layout.GuardianAuthDir, "copilot-vscode-accounts.json"),
		`{"version": 1, "accounts": [{"user": "alice", "uid": 501, "home": "/home/alice"}]}`)
	if err := os.Chmod(h.env.P(filepath.Join(h.env.Layout.GuardianAuthDir, "copilot-vscode-accounts.json")), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := h.run(Options{Action: action})
		requireError(t, got, codeVerify)
		if !strings.Contains(messagesOf(got.Errors, codeVerify), hookFile) || got.SecurityComplete {
			t.Fatalf("%s must fail naming the missing Local hook file: %+v", action, got.Errors)
		}
	}
	hooks, err := enterprisepolicy.RenderCopilotVSCodeLocalHooks("linux", enterprisepolicy.HookBinaryPath(h.env.Layout))
	if err != nil {
		t.Fatal(err)
	}
	writeHostFile(t, h, hookFile, string(hooks))
	requireOK(t, h.run(Options{Action: ActionStatus}))
	requireOK(t, h.run(Options{Action: ActionVerify}))
	// A deleted account's home is gone: nothing to rewrite, no failure
	// (GAP-1209).
	if err := os.RemoveAll(h.env.P("/home/alice")); err != nil {
		t.Fatal(err)
	}
	if got := h.run(Options{Action: ActionStatus}); hasWarning(got, codeGuardianUserFilePending) {
		t.Fatalf("a removed home is reported pending: %+v", got.Warnings)
	} else {
		requireOK(t, got)
	}
}

// outrankedPolicy reports one connector the way enterprise policy verify sees
// a higher-precedence managed-preferences profile without DefenseClaw hooks:
// the entries are in place, but the connector is not covered.
type outrankedPolicy struct {
	MachinePolicyManager
	connector string
}

func (p *outrankedPolicy) Verify(cfg *config.Config) (enterprisepolicy.Result, error) {
	result, err := p.MachinePolicyManager.Verify(cfg)
	for index := range result.States {
		if state := &result.States[index]; state.Connector == p.connector {
			state.Covered = false
			state.HigherPrecedence = []string{"/Library/Managed Preferences/com.anthropic.claudecode.plist"}
			state.Conflicts = append(state.Conflicts, "/Library/Managed Preferences/com.anthropic.claudecode.plist has higher precedence than file-based managed settings and does not include DefenseClaw's hooks")
		}
	}
	return result, err
}

// enterprise policy verify failed on such a profile while status and verify
// stayed green, and Claude Code ran without enforcement (GAP-0534).
func TestStatusAndVerifyFailWhenAHigherPrecedenceSourceOutranksTheHooks(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	writeFreshLedger(t, h)
	h.env.MachinePolicy = &outrankedPolicy{MachinePolicyManager: h.env.MachinePolicy, connector: "claudecode"}
	verify := h.run(Options{Action: ActionVerify})
	requireError(t, verify, codeVerify)
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, "com.anthropic.claudecode.plist has higher precedence") {
		t.Fatalf("verify does not name the outranking profile: %s", got)
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasWarning(status, codeMachinePolicyIncomplete) {
		t.Fatalf("status reads complete while the hooks are outranked: %+v", status.Warnings)
	}
}

// An administrator line outside DefenseClaw's block that does not parse made
// verify say "run repair", while repair exited 0 and changed nothing
// (GAP-0531). repair now fails and names the line to fix.
func TestRepairFailsOnAnUnparseableCodexRequirementsLine(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex")}))
	path := h.env.P(codexRequirements)
	lines := strings.Count(h.read(codexRequirements), "\n")
	if err := os.WriteFile(path, []byte(h.read(codexRequirements)+"this is not toml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repair := h.run(Options{Action: ActionRepair})
	requireError(t, repair, codeMachinePolicyIncomplete)
	if got := messagesOf(repair.Errors, codeMachinePolicyIncomplete); !strings.Contains(got, fmt.Sprintf("line %d", lines+1)) {
		t.Fatalf("repair does not name the line to fix: %s", got)
	}
}

// Under ownership verify_only a deleted requirements.toml was reported as
// "run repair", which never writes it, and the exported file deployed by hand
// stayed unused until a repair (GAP-0536).
func TestVerifyOnlyCodexNamesTheExportAndEnsureAppliesItsReturn(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "codex")}))
	exported := h.read(codexRequirements)
	verifyOnly := strings.Replace(h.read(h.env.Layout.ConfigPath), "  profile: standalone\n",
		"  profile: standalone\n  machine_policy:\n    connectors:\n      codex:\n        ownership: verify_only\n", 1)
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(verifyOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: file}))
	writeFreshLedger(t, h)
	if err := os.Remove(h.env.P(codexRequirements)); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, "missing_defenseclaw_hooks") || !strings.Contains(got, "policy export --connector codex") {
		t.Fatalf("verify does not name the export: %s", got)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if exists(h.env.P(codexRequirements)) {
		t.Fatal("repair wrote a verify_only file")
	}
	if err := os.WriteFile(h.env.P(codexRequirements), []byte(exported), 0o644); err != nil {
		t.Fatal(err)
	}
	if status := h.run(Options{Action: ActionStatus}); !strings.Contains(messagesOf(status.Warnings, codeMachinePolicyIncomplete), "does not use them yet") {
		t.Fatalf("status does not say the returned hooks need ensure: %+v", status.Warnings)
	}
	if applied := h.run(Options{Action: ActionEnsure}); applied.Noop {
		t.Fatal("ensure ignored the returned hooks")
	}
	if record, _ := h.env.loadDeployment(); !contains(record.MachinePolicyConnectors, "codex") {
		t.Fatalf("record machine policy connectors %v", record.MachinePolicyConnectors)
	}
}

// A CIS-style chmod 0700 of managed-settings.d made Claude Code skip every
// managed setting while policy verify, verify, status and repair all said the
// deployment was healthy (GAP-0913).
func TestVerifyFailsAndRepairRestoresAnUnreadableClaudeDropInDirectory(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	writeFreshLedger(t, h)
	dir := h.env.P(path.Dir(claudeDropIn))
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	verify := h.run(Options{Action: ActionVerify})
	if got := messagesOf(verify.Errors, codeVerify); !strings.Contains(got, "users cannot read") {
		t.Fatalf("verify does not report the unreadable directory: %s", got)
	}
	if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasWarning(status, codeMachinePolicyIncomplete) {
		t.Fatalf("status reads complete with the drop-in directory unreadable: %+v", status.Warnings)
	}
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("repair left %s at %v (%v)", dir, info.Mode(), err)
	}
	requireOK(t, h.run(Options{Action: ActionVerify}))
}

// A company drop-in that sets disableAllHooks (or a Codex requirements file
// that turns the lock off) made enterprise policy verify fail while
// enterprise linux verify exited 0 and status read security_complete true,
// and the marker prompt was answered (GAP-0909, GAP-0912).
func TestStatusAndVerifyFailWhenCompanyPolicyTurnsDefenseClawHooksOff(t *testing.T) {
	for name, override := range map[string]func(h *testHost) error{
		"claude disableAllHooks drop-in": func(h *testHost) error {
			return os.WriteFile(h.env.P(path.Dir(claudeDropIn)+"/96-company-disableall.json"), []byte(`{"disableAllHooks": true}`), 0o644)
		},
		"codex lock off": func(h *testHost) error {
			return os.WriteFile(h.env.P(codexRequirements), []byte(strings.Replace(h.read(codexRequirements),
				"allow_managed_hooks_only = true", "allow_managed_hooks_only = false", 1)), 0o644)
		},
	} {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode", "codex")}))
		writeFreshLedger(t, h)
		if err := override(h); err != nil {
			t.Fatal(err)
		}
		requireError(t, h.run(Options{Action: ActionVerify}), codeVerify)
		if status := h.run(Options{Action: ActionStatus}); status.SecurityComplete || !hasWarning(status, codeMachinePolicyIncomplete) {
			t.Fatalf("%s: status reads complete: %+v", name, status.Warnings)
		}
	}
}

// ownership: off for an enabled connector left status and verify green with
// no note while its sessions ran without DefenseClaw's hooks (GAP-0922).
func TestStatusWarnsForAnEnabledConnectorWithMachinePolicyOwnershipOff(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: machinePolicyConfig(t, h, "claudecode")}))
	off := strings.Replace(h.read(h.env.Layout.ConfigPath), "  profile: standalone\n",
		"  profile: standalone\n  machine_policy:\n    connectors:\n      claudecode:\n        ownership: \"off\"\n", 1)
	file := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(file, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: file}))
	writeFreshLedger(t, h)
	verify := h.run(Options{Action: ActionVerify})
	if !strings.Contains(messagesOf(verify.Warnings, codeMachinePolicyOff), "claudecode sessions run without DefenseClaw's hooks") {
		t.Fatalf("verify does not warn about ownership off: %+v", verify.Warnings)
	}
}
