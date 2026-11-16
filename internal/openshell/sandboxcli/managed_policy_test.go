// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// managedFixture is a managed computer's view of the caller's own policy.
func managedExplainFixture() *sandboxapi.ManagedExplain {
	return &sandboxapi.ManagedExplain{
		Profile: "contractors", Description: "Contractors. Coding agents only in a sandbox.", Match: "group", MatchedGroup: `CORP\Contractors`,
		Allowed: true, RequiredFor: []string{"claudecode", "codex"}, WhenUnavailable: "refuse",
		EgressAllowOnly: []string{"api.example.net", "*.corp.example", "pypi.org"}, EgressBlock: []string{"evil.example", "bad.example"},
		UserApprovals: "session", AllowUnblock: false,
		MCPIncluded: []string{"docs", "tickets"}, MCPBlocked: []sandboxapi.ManagedMCP{{Name: "files", Reason: "organization_block"}},
		WorkdirMode: "copy", OnSilence: "alert", MaxSilenceAfter: "10m",
		PolicyDigest: "sha256:7f3a" + strings.Repeat("0", 60), UpdatedAt: time.Date(2026, 9, 27, 11, 58, 0, 0, time.UTC),
		RequestAccess: "it-security@example.com",
		Sources: map[string]string{"required_for": sandboxapi.ExplainSourceProfile, "egress_allow_only": sandboxapi.ExplainSourceOrganization,
			"egress_block": sandboxapi.ExplainSourceProfile, "user_approvals": sandboxapi.ExplainSourceProfile},
	}
}

func managedStatusFixture() *sandboxapi.ManagedStatus {
	return &sandboxapi.ManagedStatus{Profile: "contractors", Description: "Contractors. Coding agents only in a sandbox.",
		Allowed:         true,
		EffectiveDigest: "sha256:7f3a" + strings.Repeat("0", 60), UpdatedAt: time.Date(2026, 9, 27, 11, 58, 0, 0, time.UTC),
		RequestAccess: "it-security@example.com", InstallMode: "setup", Driver: "docker", OpenShellVersion: "0.1.3"}
}

// An older managed daemon omits managed.allowed while it keeps an account's
// running sandbox during an upgrade. The doctor asks its existing explain
// endpoint about the harnesses this CLI is configured to run, or, with
// none configured, about the harness the daemon's own managed
// configuration runs (an explain that names none: the daemon's first
// harness, else claudecode), never about the CLI's setup defaults; an
// explicit denial of one of those still fails.
func TestManagedDoctorUsesLegacyDaemonPolicyExplanation(t *testing.T) {
	withManagedHost(t)
	const daemonDefault = "(daemon)"
	for _, tc := range []struct {
		name string
		// configured is this CLI's openshell.harnesses; daemon the first
		// harness of the daemon's own managed configuration ("" = none).
		configured []string
		daemon     string
		// permitted are the harnesses the organization's profiles allow
		// (nil = every one); listed a profile's allowed_harnesses.
		permitted []string
		listed    []string
		want      openshell.CheckStatus
		asked     []string
		named     string
	}{
		{name: "permitted", want: openshell.StatusPass, asked: []string{daemonDefault}},
		{name: "daemon default denied", permitted: []string{"codex"}, want: openshell.StatusFail, asked: []string{daemonDefault},
			named: "the agent your sandbox service is configured to run"},
		{name: "codex only, daemon runs codex", daemon: "codex", permitted: []string{"codex"}, want: openshell.StatusPass,
			asked: []string{daemonDefault}},
		{name: "codex only, daemon runs claudecode", daemon: "claudecode", permitted: []string{"codex"}, want: openshell.StatusFail,
			asked: []string{daemonDefault}, named: "the agent your sandbox service is configured to run"},
		{name: "unconfigured harness denied", permitted: []string{"claudecode"}, want: openshell.StatusPass, asked: []string{daemonDefault}},
		{name: "a profile listing codex", daemon: "codex", listed: []string{"codex"}, want: openshell.StatusPass, asked: []string{daemonDefault}},
		{name: "codex only, CLI runs codex", configured: []string{"codex"}, permitted: []string{"codex"}, want: openshell.StatusPass,
			asked: []string{"codex"}},
		{name: "configured harness denied", configured: []string{"claudecode", "codex"}, permitted: []string{"claudecode"},
			want: openshell.StatusFail, asked: []string{"claudecode", "codex"}, named: "codex"},
		{name: "only a configured harness denied", configured: []string{"codex"}, permitted: []string{"claudecode"},
			want: openshell.StatusFail, asked: []string{"codex"}, named: "codex"},
		{name: "configured harness not listed", configured: []string{"claudecode"}, listed: []string{"codex"},
			want: openshell.StatusFail, asked: []string{"claudecode"}, named: "claudecode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.Cfg.OpenShell.Harnesses = tc.configured
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.statusWithoutAllowed = true
			var asked []string
			ta.daemon.onExplain = func(req sandboxapi.ExplainRequest, ex *sandboxapi.Explain) {
				who, judged := req.Harness, req.Harness
				if who == "" {
					// The older daemon judges its own configured harness.
					who, judged = daemonDefault, tc.daemon
					if judged == "" {
						judged = "claudecode"
					}
				}
				if !slices.Contains(asked, who) {
					asked = append(asked, who)
				}
				ex.Managed = &sandboxapi.ManagedExplain{Allowed: tc.permitted == nil || slices.Contains(tc.permitted, judged),
					AllowedHarnesses: tc.listed}
			}
			rep := ta.runDoctor(bg)
			if !slices.Equal(asked, tc.asked) {
				t.Fatalf("legacy daemon was asked about %v, want %v", asked, tc.asked)
			}
			row := rep.Get(CheckIDAdmin)
			if row == nil || row.Status != tc.want {
				t.Fatalf("organization policy for legacy daemon = %+v", row)
			}
			if tc.want == openshell.StatusPass && !rep.OK() {
				t.Fatalf("permitted running account was reported unready: %+v", rep.Checks)
			}
			if tc.want == openshell.StatusFail && (rep.OK() || !strings.Contains(row.Detail, "doesn't allow sandboxes for "+tc.named)) {
				t.Fatalf("denial did not name %s or left doctor ready: %+v", tc.named, row)
			}
		})
	}
}

func TestManagedDoctorLegacyPolicyExplanationFailureIsNotReady(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.statusWithoutAllowed = true
	ta.daemon.explainErr = func(sandboxapi.ExplainRequest) *sandboxapi.Error {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "policy service unavailable")
	}
	rep := ta.runDoctor(bg)
	if row := rep.Get(CheckIDAdmin); row == nil || row.Status != openshell.StatusFail ||
		!strings.Contains(row.Detail, "older sandbox service did not report authorization") || rep.OK() {
		t.Fatalf("unconfirmed legacy authorization = %+v", row)
	}
}

// GAP-0720: the optional running-sandbox note must not make a read-only
// policy explain wait for a kept sandbox's unavailable account gateway.
func TestPolicyExplainDoesNotWaitForManagedSandboxList(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain.Managed = managedExplainFixture()
	ta.daemon.status.Enabled = false
	var listed atomic.Bool
	ta.daemon.onList = func(ctx context.Context) { listed.Store(true); <-ctx.Done() }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	ta.ok(t, ta.PolicyExplain(ctx, PolicyOptions{}))
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("read-only policy explain waited %s for the sandbox list", elapsed)
	}
	has(t, ta.output(), "Your sandbox policy on this computer")
	if listed.Load() {
		t.Fatal("policy explain queried the disabled sandbox gateway")
	}
}

func TestPolicyExplainIncludesSlowHealthyManagedList(t *testing.T) {
	sb := sampleSandbox("kept")
	sb.Phase = "ready"
	ta := newTestApp(t, "", sb)
	ta.daemon.explain.Managed = managedExplainFixture()
	ta.daemon.onList = func(context.Context) { time.Sleep(400 * time.Millisecond) }
	ta.ok(t, ta.PolicyExplain(context.Background(), PolicyOptions{}))
	has(t, ta.output(), "running: kept")
}

func TestManagedDeleteWhenSandboxesOffNamesRecovery(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "", sampleSandbox("kept"))
	ta.daemon.status.Enabled = false
	ta.daemon.status.Available = false
	ta.daemon.status.Reason = "the administrator turned sandboxes off"
	err := ta.Delete(context.Background(), DeleteOptions{Names: []string{"kept"}, Yes: true})
	if err == nil || !strings.Contains(err.Error(), "openshell.enabled") || strings.Contains(err.Error(), "enterprise.openshell.enabled") || !strings.Contains(err.Error(), "sandbox delete kept") {
		t.Fatalf("disabled managed delete = %v", err)
	}
	if got := len(ta.daemon.callsTo("DELETE", "kept")); got != 0 {
		t.Fatalf("disabled delete reached the unavailable gateway %d times", got)
	}
}

// withManagedHost makes the CLI treat this computer as a managed one.
func withManagedHost(t *testing.T) {
	t.Helper()
	prev := onManagedHost
	onManagedHost = func() bool { return true }
	t.Cleanup(func() { onManagedHost = prev })
}

func TestManagedPromptReasonUsesTheSandboxPolicy(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	off := false
	ta.Cfg.OpenShell.Admin.AllowYolo = &off
	sb := &sandboxapi.Sandbox{Launch: sandboxapi.Launch{Yolo: false}}
	if got := ta.promptsKept(sb); got != "harness prompts kept" {
		t.Fatalf("base floor overrode the sandbox's managed policy: %q", got)
	}
	sb.Violations = []sandboxapi.Violation{{Key: "yolo", Admin: true, Constraint: "openshell.admin.allow_yolo"}}
	if got := ta.promptsKept(sb); got != "your organization disables skip-permissions" {
		t.Fatalf("sandbox policy reason = %q", got)
	}
}

func TestManagedPolicyEditRefusesBeforeReadingTheLocalFloor(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin.EgressAllowOnly = []string{"other.example"}
	err := ta.PolicyEdit(context.Background(), "allow", []string{"example.org"})
	if err == nil || !strings.Contains(err.Error(), "administrator-owned") {
		t.Fatalf("managed policy edit = %v", err)
	}
}

// On a managed computer the doctor reads the administrator's rendered
// gateway configuration, never the account's own gateway files (GAP-0254).
func TestDefaultDoctorReadsTheRenderedGatewayOnAManagedComputer(t *testing.T) {
	paths := &openshell.RenderedPaths{TOML: "/etc/defenseclaw/openshell/gateway.toml", Env: "/etc/defenseclaw/openshell/gateway.env"}
	prev := managedRenderedGateway
	managedRenderedGateway = func() *openshell.RenderedPaths { return paths }
	t.Cleanup(func() { managedRenderedGateway = prev })

	app := &App{}
	app.defaults()
	if d := app.defaultDoctor(); d.Rendered != nil {
		t.Fatalf("an unmanaged computer reads %+v", d.Rendered)
	}
	withManagedHost(t)
	if d := app.defaultDoctor(); d.Rendered != paths {
		t.Fatalf("managed doctor reads %+v", d.Rendered)
	}
}

func TestManagedExplainRowsFollowThePlan(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	var text strings.Builder
	for _, r := range managedExplainRows(managedExplainFixture(), now) {
		text.WriteString(r.label + " | " + r.text + "\n")
	}
	has(t, text.String(),
		`Organization profile | contractors   matched: your group CORP\Contractors`,
		"Required | claude and codex run only in a sandbox on this computer",
		"Egress | only 3 hosts are reachable (api.example.net, *.corp.example, pypi.org); 2 hosts are always blocked (evil.example, bad.example)",
		"Approvals | you may approve asks for this session only; you can't unblock destinations",
		"MCP | 2 of your servers included; 1 blocked by your organization",
		"Workspace | copy mode; no mounts; no host ports; skip-permissions off",
		"Hooks | claude and codex: an alert after 10m of agent work without hooks",
		"Policy id | sha256:7f3a",
		"(yours), updated 2 min ago; access: it-security@example.com")
}

func TestManagedExplainRowsOtherShapes(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	join := func(m *sandboxapi.ManagedExplain) string {
		var b strings.Builder
		for _, r := range managedExplainRows(m, now) {
			b.WriteString(r.label + " | " + r.text + "\n")
		}
		return b.String()
	}
	has(t, join(&sandboxapi.ManagedExplain{Match: "default_lookup_failed", Provisional: true, Allowed: true, AllowMount: true, AllowHostPorts: true, AllowYolo: true, AllowUnblock: true, PolicyDigest: "sha256:abc"}),
		"(your organization's floor)   matched: the default (your directory couldn't be reached; no assignment needs the missing facts); provisional until your directory answers",
		"Required | no agent has to run in a sandbox", "your organization limits no hosts",
		"you may approve asks for a session or for good", "access: contact your IT help desk")
	has(t, join(&sandboxapi.ManagedExplain{Match: "none", Allowed: false}), "Sandboxes | your organization doesn't allow sandboxes for you")
	has(t, join(&sandboxapi.ManagedExplain{Match: "user", Allowed: true, AllowedCredentials: []string{"none"}, UserApprovals: "none",
		RequiredFor: []string{"codex"}, WhenUnavailable: "alert", DeleteStoppedAfter: "30d", ProcessTree: true}),
		"Credentials | no credentials go into a sandbox", "you can't approve asks; they are refused",
		"allowed and your administrators are alerted", "Cleanup | a stopped sandbox is deleted after 30d", "the process tree is watched")
}

// An administrator's text is made safe to print: a profile description or a
// contact with a terminal escape never reaches the user's terminal raw.
func TestPolicyExplainManagedPrintsSafely(t *testing.T) {
	ta := newTestApp(t, "")
	m := managedExplainFixture()
	m.Description = "Hello \x1b]52;c;ZXZpbA==\x07 world"
	m.RequestAccess = "help\x1b[2Jdesk"
	ta.daemon.explain.Managed = m
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{}))
	lacks(t, ta.output(), "\x1b]52", "\x1b[2J", "\x07")
}

func TestPolicyExplainManagedUsesTheDaemonNotTheLocalConfig(t *testing.T) {
	ta := newTestApp(t, "")
	ta.Cfg.OpenShell.Admin.RequiredPack = "local-secret-pack"
	ta.daemon.explain.Managed = managedExplainFixture()
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Sources: true}))
	out := ta.output()
	has(t, out, "Your sandbox policy on this computer", `matched: your group CORP\Contractors`,
		"[from your organization (everyone), your organization profile]", "[from your organization profile]", "SETTING")
	lacks(t, out, "local-secret-pack", "Organization constraints", "organization:")
	if q := ta.daemon.callsTo("GET", sandboxapi.PathPolicyExplain); len(q) != 1 || !strings.Contains(q[0].Query, "sources=true") {
		t.Fatalf("explain did not ask for sources: %+v", q)
	}

	// Without --sources no source is named.
	ta.fresh()
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{}))
	lacks(t, ta.output(), "[from ")

	// -o json is the golden schema's document.
	ta.fresh()
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Output: OutputJSON}))
	var doc struct {
		Managed map[string]any `json:"managed"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &doc); err != nil || doc.Managed["profile"] != "contractors" {
		t.Fatalf("json explain = %v, %v\n%s", doc, err, ta.output())
	}

	ta.fresh()
	ta.ok(t, ta.PolicyShow(bg, PolicyOptions{}))
	has(t, ta.output(), "Your sandbox policy on this computer", "policy explain --sources")
	lacks(t, ta.output(), "local-secret-pack")
}

func TestPolicyExplainManagedKeepsIdentityAfterLongSettings(t *testing.T) {
	ta := newTestApp(t, "")
	ta.IO.Width = 80
	ta.daemon.explain.Managed = managedExplainFixture()
	for i := range 36 {
		ta.daemon.explain.Settings = append(ta.daemon.explain.Settings, sandboxapi.Setting{
			Key: fmt.Sprintf("setting.%02d", i), Value: "enabled", Source: "pack", Origin: "pack contractors",
		})
	}
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Harness: "codex", Sources: true}))
	lines := strings.Split(strings.TrimSpace(ta.output()), "\n")
	lastPage := strings.Join(lines[max(0, len(lines)-24):], "\n")
	has(t, lastPage, "Policy at a glance", "Organization profile: contractors", `matched: your group CORP\Contractors`, "Agent: codex")
	has(t, ta.output(), "SETTING", "setting.35", "[from your organization profile]")
}

func TestPolicyExplainManagedFooterNamesTheSelection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		given PolicyOptions
		want  string
	}{
		{"default agent", PolicyOptions{}, "Agent: default agent (add --harness NAME for another)"},
		{"running sandbox", PolicyOptions{Sandbox: "bob-codex"}, "Agent: agent in sandbox bob-codex"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			m := managedExplainFixture()
			m.Provisional = true
			ta.daemon.explain.Managed = m
			ta.ok(t, ta.PolicyExplain(bg, tc.given))
			output := ta.output()
			has(t, output, "Policy at a glance", tc.want, "Organization profile: contractors",
				"matched: your group CORP\\Contractors", "provisional until your directory answers")
			lacks(t, output, "Agent: default agent (Claude Code)")
		})
	}
}

// GAP-0179/GAP-0550: the floor's source map identifies who supplied each
// constraint, even though the posture calls every floor setting admin.
func TestManagedExplainConstraintProvenance(t *testing.T) {
	for _, tc := range []struct {
		key, floor, source, origin string
	}{
		{"pack", "required_pack", "profile", "guardrail.profiles.contractors.sandbox.required_pack"},
		{"hooks.silence_after", "max_silence_after", "profile", "guardrail.profiles.contractors.sandbox.max_silence_after"},
		{"hooks.silence_after", "max_silence_after", "organization", "openshell.admin.max_silence_after"},
	} {
		t.Run(tc.key+"/"+tc.source, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.explain = sandboxapi.Explain{Pack: "contractors", PackSource: "organization", Settings: []sandboxapi.Setting{
				{Key: tc.key, Value: "10m", Source: "admin", Origin: "openshell.admin." + tc.floor},
			}, Managed: &sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true, Sources: map[string]string{tc.floor: tc.source}}}
			// The gateway only supplies provenance when the request asks for it,
			// including when the user runs the plain explain command.
			ta.daemon.onExplain = func(req sandboxapi.ExplainRequest, ex *sandboxapi.Explain) {
				m := *ex.Managed
				if !req.Sources {
					m.Sources = nil
				}
				ex.Managed = &m
			}
			ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Output: OutputJSON}))
			var got sandboxapi.Explain
			if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			if s := got.Settings[0]; s.Source != tc.source || s.Origin != tc.origin {
				t.Fatalf("setting = %+v; want %s from %s", s, tc.source, tc.origin)
			}
			if tc.key == "pack" && got.PackSource != tc.source {
				t.Fatalf("pack source = %q; want %q", got.PackSource, tc.source)
			}
			ta.fresh()
			ta.IO.Width = 60
			ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{}))
			has(t, ta.output(), tc.source)
			lacks(t, ta.output(), "[from ")
			if tc.source == "profile" {
				has(t, strings.Join(strings.Fields(ta.output()), " "), "sandbox."+tc.floor, "organization profile contractors")
				lacks(t, ta.output(), "openshell.admin."+tc.floor)
			}
		})
	}
}

func TestManagedExplainSummaryUsesRepresentedSourcesAndRules(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain = sandboxapi.Explain{Pack: "contractors", NetworkMode: "allowlist", Approvals: "manual", Settings: []sandboxapi.Setting{
		{Key: "pack", Value: "contractors", Source: "admin", Origin: "openshell.admin.required_pack"},
		{Key: "profile", Value: "balanced", Source: "pack", Origin: "pack contractors"},
		{Key: "egress.admin_block", Value: "blocked.example, *.blocked.example", Source: "admin", Origin: "openshell.admin.egress_block"},
	}, Managed: &sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true, RequiredFor: []string{"claudecode"},
		WhenUnavailable: "refuse", EgressBlock: []string{"blocked.example"}, Sources: map[string]string{
			"required_for": "profile", "when_unavailable": "organization", "required_pack": "profile", "min_profile": "organization", "egress_block": "organization",
		}}}
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Sources: true}))
	out := ta.output()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Required ") || strings.Contains(line, "Pack ") {
			has(t, line, "your organization profile")
			lacks(t, line, "your organization (everyone)")
		}
	}
	has(t, out, "contractors (required)", "2 host patterns are always blocked")
}

func TestManagedExplainNamesForeignSandboxActionAndSource(t *testing.T) {
	for _, tc := range []struct{ action, source, want string }{
		{"stop", "profile", "sandboxes outside DefenseClaw are stopped"},
		{"alert", "organization", "sandboxes outside DefenseClaw are reported to your administrators"},
	} {
		ta := newTestApp(t, "")
		ta.daemon.explain = sandboxapi.Explain{Managed: &sandboxapi.ManagedExplain{
			Profile: "contractors", Allowed: true, ForeignSandboxes: tc.action,
			Sources: map[string]string{"foreign_sandboxes": tc.source},
		}}
		ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Sources: true}))
		has(t, ta.output(), tc.want, explainSourceText(tc.source))
	}
}

// GAP-0568: a required pack's effective hook settings apply even when the
// organization's floor has no silence interval of its own.
func TestManagedHooksSummaryUsesEffectivePackSettings(t *testing.T) {
	for _, tc := range []struct {
		harness, action, interval, source, want string
	}{
		{"claude", "alert", "10m", "pack", "claude: an alert after 10m of agent work without hooks"},
		{"opencode", "stop", "5m", "profile", "opencode: a stop after 5m of agent work without hooks"},
	} {
		t.Run(tc.harness, func(t *testing.T) {
			ta := newTestApp(t, "")
			ta.daemon.explain = sandboxapi.Explain{Pack: "contractors", Settings: []sandboxapi.Setting{
				{Key: "hooks.on_silence", Value: tc.action, Source: tc.source},
				{Key: "hooks.silence_after", Value: tc.interval, Source: tc.source},
			}, Managed: &sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true, ProcessTree: true,
				Sources: map[string]string{"on_silence": "organization", "max_silence_after": "organization", "process_tree": "profile"}}}
			ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Harness: tc.harness, Sources: true}))
			has(t, ta.output(), tc.want, "the process tree is watched")
			for _, line := range strings.Split(ta.output(), "\n") {
				if strings.Contains(line, "Hooks ") {
					lacks(t, line, "your organization (everyone)")
				}
			}
		})
	}
}

// GAP-0571: the organization assignment and the network posture are
// separate profiles. These checks cover the views owned by this batch.
func TestOwnedPolicyViewsDistinguishProfiles(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.explain = sandboxapi.Explain{Pack: "balanced", Profile: "strict", Settings: []sandboxapi.Setting{
		{Key: "profile", Value: "strict", Source: "admin", Origin: "openshell.admin.min_profile"},
		{Key: "network.mode", Value: "deny", Source: "pack", Origin: "profile strict"},
	}, Managed: &sandboxapi.ManagedExplain{Profile: "engineering", Allowed: true}}
	ta.ok(t, ta.PolicyExplain(bg, PolicyOptions{Sources: true}))
	has(t, ta.output(), "Organization profile", "network profile strict", "strict network profile")
	ta.fresh()
	ta.printStatus(&sandboxapi.Status{Managed: &sandboxapi.ManagedStatus{Profile: "engineering"}})
	has(t, ta.output(), "Your policy", "organization profile engineering")
}

// #1199 (rel GAP-0168, GAP-0607): `sandbox status NAME` named the pack
// alone, so after a regroup nothing said which organization profile the
// sandbox now runs under; and a stop the organization's policy made had no
// reason there.
func TestSandboxStatusNamesTheCurrentProfileAndThePolicyStop(t *testing.T) {
	ta := newTestApp(t, "")
	sb := &sandboxapi.Sandbox{Name: "dc-a", Harness: "claudecode", Phase: "ready", Pack: "contractors", Profile: "balanced",
		NetworkMode: "allowlist", Approvals: "triage", WorkdirMode: "copy", OrganizationProfile: "engineering",
		PolicyDigest: "sha256:41a7a6cf0123456789abcdef"}
	ta.printSandbox(sb)
	out := ta.output()
	has(t, out, "Your policy", "organization profile engineering", "(yours)", "policy explain", "pack contractors")
	if strings.Contains(out, "Stopped") {
		t.Fatalf("a running sandbox shows a stop:\n%s", out)
	}
	ta.fresh()
	sb.Phase, sb.OrganizationProfile, sb.PolicyDigest = "stopped", "", ""
	sb.StopReason = sandboxapi.ProfileStop("host ports", "claudecode", "it-help@example.com")
	ta.printSandbox(sb)
	has(t, ta.output(), "Stopped", "your profile no longer allows host ports")
	if strings.Contains(ta.output(), "Your policy") {
		t.Fatalf("a revoked sandbox names a current profile:\n%s", ta.output())
	}
}

// GAP-0080: `sandbox status NAME` asks the daemon to confirm the running
// sandbox's policy with the organization's gateway first; the other reads of
// a sandbox do not.
func TestSandboxStatusAsksForTheConfirmedPolicy(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.add(sandboxapi.Sandbox{Name: "dc-a", Harness: "claudecode", Phase: "ready", Pack: "balanced",
		Profile: "balanced", NetworkMode: "allowlist", Approvals: "triage", WorkdirMode: "copy", OrganizationProfile: "contractors"})
	if err := ta.Status(context.Background(), "dc-a", OutputText); err != nil {
		t.Fatal(err)
	}
	calls := ta.daemon.callsTo(http.MethodGet, sandboxapi.PathSandboxes+"/dc-a")
	if len(calls) == 0 || calls[0].Query != sandboxapi.QueryConfirm+"="+sandboxapi.ConfirmPolicy {
		t.Fatalf("status reads = %+v, want the confirmed policy asked for", calls)
	}
	has(t, ta.output(), "organization profile contractors")
	ta.fresh()
	if _, err := ta.daemon.client().Get(context.Background(), "dc-a"); err != nil {
		t.Fatal(err)
	}
	all := ta.daemon.callsTo(http.MethodGet, sandboxapi.PathSandboxes+"/dc-a")
	if last := all[len(all)-1]; last.Query != "" {
		t.Fatalf("a plain read asked for the confirmed policy: %+v", last)
	}
}

func TestBannerShowsTheManagedPolicyLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    *sandboxapi.ManagedStatus
		want string
	}{
		{"matched", &sandboxapi.ManagedStatus{Profile: "contractors", Description: "Contractors. Coding agents only in a sandbox."},
			"Policy    contractors: Contractors. Coding agents only in a sandbox. Details: defenseclaw sandbox policy explain"},
		{"provisional", &sandboxapi.ManagedStatus{Profile: "offline-floor", Provisional: true},
			"Policy    offline-floor (provisional): your directory couldn't be reached; your organization's default applies. Details: defenseclaw sandbox policy explain"},
		{"no description", &sandboxapi.ManagedStatus{Profile: "staff"}, "Policy    staff. Details: defenseclaw sandbox policy explain"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := newTestApp(t, "")
			sb := sampleSandbox("box")
			ta.banner(&sb, bannerInfo{managed: tc.m})
			has(t, ta.output(), tc.want)
		})
	}
	// OSS: no policy line from a managed policy.
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	ta.banner(&sb, bannerInfo{})
	lacks(t, ta.output(), "Details: defenseclaw sandbox policy explain")
	// A repository policy keeps its own, distinct, label next to the managed line.
	ta = newTestApp(t, "")
	ta.banner(&sb, bannerInfo{managed: &sandboxapi.ManagedStatus{Profile: "staff"}, repo: &sandboxapi.RepoPolicy{Path: "/p/.defenseclaw/sandbox.yaml", Digest: "sha256:abc"}})
	has(t, ta.output(), "Policy    staff.", "Repository")
}

func TestStatusOnAManagedComputerIsNeutralAboutOtherAccounts(t *testing.T) {
	ta := newTestApp(t, "")
	// An older or compromised answer that carries another account's details.
	ta.daemon.status.Enabled = false
	ta.daemon.status.GatewayElsewhere = "127.0.0.1:17670 is held by PID 4242 of another account (uid 1999, alice)"
	ta.daemon.status.Managed = managedStatusFixture()
	ta.ok(t, ta.Status(bg, "", OutputText))
	out := ta.output()
	has(t, out, "another account is using them", "Your policy", "contractors", "(yours)", "OpenShell 0.1.3, setup install",
		"it-security@example.com")
	lacks(t, out, "alice", "4242", "1999", "defenseclaw sandbox setup", "hand")

	// The JSON carries the flag, not the other account's details.
	ta.fresh()
	ta.ok(t, ta.Status(bg, "", OutputJSON))
	out = ta.output()
	has(t, out, `"gateway_elsewhere": "another account"`)
	lacks(t, out, "alice", "4242", "1999", "held by")

	ta = newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.PendingRestart = true
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "Sandboxes       on", "Pending")
}

func TestPolicyTestOnAManagedComputerGoesThroughTheDaemon(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	var asked sandboxapi.PolicyTestRequest
	ta.daemon.policyTest = func(req sandboxapi.PolicyTestRequest) *sandboxapi.PolicyTestResult {
		asked = req
		return &sandboxapi.PolicyTestResult{Pack: "balanced", Profile: "standard", NetworkMode: "restricted", Decisions: []sandboxapi.PolicyDecision{
			{PolicyCheck: req.Checks[0], Allowed: false, Rule: "admin_allow_only", Source: "your organization"}}}
	}
	ta.ok(t, ta.PolicyTest(bg, PolicyTestOptions{Host: "x.example.org", Port: 443}))
	if asked.Sandbox != "" || len(asked.Checks) != 1 || asked.Checks[0].Host != "x.example.org" || asked.Project == "" {
		t.Fatalf("daemon asked %+v", asked)
	}
	has(t, ta.output(), "blocked", "admin_allow_only")

	// An agent picks the caller's own policy for it (GAP-0228).
	ta.ok(t, ta.PolicyTest(bg, PolicyTestOptions{Host: "x.example.org", Harness: "codex"}))
	if asked.Harness != "codex" || asked.Sandbox != "" {
		t.Fatalf("daemon asked %+v", asked)
	}

	// Packs and profiles are the policy's, not the user's, to choose here.
	err := ta.PolicyTest(bg, PolicyTestOptions{Host: "x.example.org", Pack: "open"})
	wantErr(t, err, "leave out --pack and --profile")

	// Elsewhere (no runtime descriptor) it resolves locally, with no daemon call.
	onManagedHost = func() bool { return false }
	ta = newTestApp(t, "")
	ta.ok(t, ta.PolicyTest(bg, PolicyTestOptions{Host: "x.example.org", Port: 443}))
	if n := len(ta.daemon.callsTo("POST", sandboxapi.PathPolicyTest)); n != 0 {
		t.Errorf("OSS policy test called the daemon %d times", n)
	}
}

// packAPI adds the managed pack routes to the fake daemon's client.
type packAPI struct {
	API
	list []sandboxapi.ManagedPack
}

func (p packAPI) ListManagedPacks(context.Context) ([]sandboxapi.ManagedPack, error) {
	return p.list, nil
}
func (p packAPI) GetManagedPack(_ context.Context, name string) (*sandboxapi.ManagedPack, error) {
	for _, pk := range p.list {
		if pk.Name == name {
			c := pk
			return &c, nil
		}
	}
	return nil, &sandboxapi.Error{Code: sandboxapi.CodeNotFound, Message: "pack " + name + " not found"}
}

func TestPackCommandsOnAManagedComputerShowOnlyTheCallersChain(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.API = packAPI{API: ta.API, list: []sandboxapi.ManagedPack{
		{Name: "contractors", Source: "organization", Digest: "sha256:aa", Extends: "balanced", Content: "name: contractors\n"},
		{Name: "balanced", Source: "built-in", Digest: "sha256:bb"}}}
	ta.ok(t, ta.PackList(PackOptions{}))
	has(t, ta.output(), "contractors", "balanced", "organization", "your own policy uses")
	ta.fresh()
	ta.ok(t, ta.PackShow("contractors", PackOptions{}))
	has(t, ta.output(), "# pack contractors (organization)", "# extends balanced", "name: contractors")
	// Another profile's pack is simply not there.
	wantErr(t, ta.PackShow("finance-only", PackOptions{}), "not found")
	ta.fresh()
	ta.ok(t, ta.PackList(PackOptions{Output: OutputJSON}))
	has(t, ta.output(), `"packs"`, `"contractors"`)
}

// downPackAPI is a daemon client whose pack routes fail, as with the daemon
// down.
type downPackAPI struct{ API }

func (downPackAPI) ListManagedPacks(context.Context) ([]sandboxapi.ManagedPack, error) {
	return nil, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the sandbox service is not running"}
}
func (downPackAPI) GetManagedPack(context.Context, string) (*sandboxapi.ManagedPack, error) {
	return nil, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the sandbox service is not running"}
}

// A managed computer never answers from the local configuration or the
// user's own pack directory: with the daemon down the user gets the error,
// not a verdict or a pack list that the organization may contradict.
func TestManagedComputerNeverFallsBackToLocalResolutionWhenTheDaemonIsDown(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.errors = map[string]*sandboxapi.Error{
		"POST " + sandboxapi.PathPolicyTest: {Code: sandboxapi.CodeUnavailable, Message: "the sandbox service is not running"},
	}
	err := ta.PolicyTest(bg, PolicyTestOptions{Host: "x.example.org", Port: 443})
	if err == nil {
		t.Fatalf("policy test with the daemon down answered: %s", ta.output())
	}
	lacks(t, ta.output(), "allowed", "blocked", "decided by")

	// A pack directory the user can read must not be listed or shown either.
	ta = newTestApp(t, "")
	ta.API = downPackAPI{API: ta.API}
	ta.Cfg.OpenShell.PackDir = t.TempDir()
	wantErr(t, ta.PackList(PackOptions{}), "not running")
	lacks(t, ta.output(), "balanced", "built-in")
	wantErr(t, ta.PackShow("balanced", PackOptions{}), "not running")
	lacks(t, ta.output(), "# pack balanced")

	// A client that cannot list managed packs is an error too, not the local list.
	ta = newTestApp(t, "")
	ta.API = struct{ API }{ta.API}
	wantErr(t, ta.PackList(PackOptions{}), "can't list your packs")
	lacks(t, ta.output(), "built-in")
}

func TestSuggestionDiffOnAManagedComputerNamesWhatTheFloorBlocks(t *testing.T) {
	s := &suggestion{byHost: map[string]*suggestedHost{}, ports: map[string][]int{}}
	for _, h := range []string{"api.example.net", "evil.example", "other.example.org"} {
		s.byHost[h] = &suggestedHost{Requests: 3}
		s.order = append(s.order, h)
	}
	ex := &sandboxapi.Explain{Pack: "balanced", Managed: managedExplainFixture()}
	d := managedSuggestionDiff("the policy a run in this folder gets", ex, s)
	var blocked []string
	for _, b := range d.Blocked {
		blocked = append(blocked, b.Host+" "+b.Rule)
	}
	want := []string{"evil.example admin_block", "other.example.org admin_allow_only"}
	if strings.Join(blocked, ",") != strings.Join(want, ",") {
		t.Fatalf("blocked = %v, want %v", blocked, want)
	}
	if !strings.Contains(d.Against, "your organization's policy applies on top of any pack") {
		t.Errorf("against = %q", d.Against)
	}
}

func TestDoctorRowsOnAManagedComputer(t *testing.T) {
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.Provisional = true
	ta.daemon.status.Managed.PendingRestart = true
	ta.Cfg.OpenShell.Admin.RequiredPack = "local-secret-pack"
	rep := ta.runDoctor(bg)
	policy, runtime := rep.Get(CheckIDAdmin), rep.Get("managed-runtime")
	if policy == nil || runtime == nil {
		t.Fatalf("missing managed rows: %+v", rep.Checks)
	}
	has(t, policy.Detail, "profile contractors", "directory couldn't be reached")
	if policy.Status != openshell.StatusWarn || runtime.Status != openshell.StatusWarn {
		t.Errorf("statuses = %v, %v", policy.Status, runtime.Status)
	}
	has(t, runtime.Detail, "OpenShell 0.1.3", "driver docker", "setup install", "an update waits")
	for _, c := range rep.Checks {
		lacks(t, c.Detail+c.Title, "local-secret-pack")
	}
	// GAP-0175: before the first sandbox no profile is known; the row
	// names the policy, never "profile your organization's policy".
	if c := ta.managedPolicyCheck(bg, &sandboxapi.ManagedStatus{}); c.Status != openshell.StatusFail ||
		!strings.HasPrefix(c.Detail, "your organization's policy: sandbox authorization could not be confirmed") {
		t.Errorf("unnamed policy row = %+v", c)
	}
}

// A managed computer's doctor reports what the account's daemon reports,
// the facts the administrator's verify reads, and no host check that reads
// other accounts' files, OpenShell's default port, or an unmanaged
// install's fixes (GAP-0173, GAP-0174, GAP-0215, GAP-0367).
func TestManagedDoctorUsesTheDaemonsFacts(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.InstallMode, ta.daemon.status.Managed.Driver, ta.daemon.status.Managed.GatewayPort = "prerequisite", "vm", 17691
	var asked *openshell.Doctor
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		asked = d
		return hostReport(nil)(bg, d)
	}
	rep := ta.runDoctor(bg)
	if asked == nil || !asked.Managed {
		t.Fatalf("the host checks ran unmanaged: %+v", asked)
	}
	if rep.Driver != openshell.DriverVM {
		t.Errorf("driver = %q, want the daemon's vm", rep.Driver)
	}
	rt := rep.Get(CheckIDManagedRuntime)
	if rt == nil || rt.Status != openshell.StatusPass {
		t.Fatalf("runtime row = %+v", rt)
	}
	has(t, rt.Detail, "driver vm", "prerequisite install", "gateway port 17691")

	// Without the daemon's answer: the service's own error, the way on is
	// IT, and no policy row from a configuration this account lacks.
	ta = newTestApp(t, "")
	ta.daemon.errors["GET "+sandboxapi.PathStatus] = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the DefenseClaw daemon is not reachable",
		Detail: `Get "http://sandbox-daemon/api/v1/sandbox/status": sandbox daemon socket directory is not yours alone`}
	ta.HostDoctor = func(context.Context, *openshell.Doctor) *openshell.DoctorReport { return &openshell.DoctorReport{} }
	rep = ta.runDoctor(bg)
	d := rep.Get(CheckIDDaemon)
	if d == nil || d.Status != openshell.StatusFail || d.Fix == nil || d.Fix.Command != "" {
		t.Fatalf("daemon row = %+v", d)
	}
	has(t, d.Detail, "your sandbox service does not answer", "not yours alone")
	lacks(t, d.Detail, "http://")
	has(t, d.Fix.Summary, sandboxapi.RequestAccessFallback)
	for _, id := range []string{CheckIDAdmin, CheckIDManagedRuntime} {
		if c := rep.Get(id); c == nil || c.Status != openshell.StatusSkip || !strings.Contains(c.Detail, "did not answer") {
			t.Errorf("%s = %+v", id, c)
		}
	}
	wantErr(t, ta.Setup(bg, SetupOptions{Yes: true}), "set up by your organization")
}

// Before the first sandbox the account's OpenShell gateway is not running
// (and in setup mode OpenShell is not installed yet): the doctor's daemon
// row failed with "no gateway registration found" and the verdict read
// not ready (GAP-0439). It says what the first run does.
func TestManagedDoctorBeforeTheFirstRunIsNotAFailure(t *testing.T) {
	withManagedHost(t)
	for _, c := range []struct {
		mode      string
		installed bool
		want      string
	}{
		{"setup", false, "OpenShell isn't installed for your account yet: your first `defenseclaw sandbox run` installs OpenShell"},
		{"setup", true, "your OpenShell gateway starts with your next `defenseclaw sandbox run`"},
		{"prerequisite", false, "your OpenShell gateway starts with your next `defenseclaw sandbox run`"},
	} {
		ta := newTestApp(t, "")
		ta.daemon.status.Managed = managedStatusFixture()
		ta.daemon.status.Managed.InstallMode = c.mode
		ta.daemon.status.Available, ta.daemon.status.Running = false, 0
		ta.daemon.status.Reason = "the OpenShell gateway is not available: openshell: no gateway registration found"
		installed := c.installed
		// The daemon installs the account's OpenShell CLI (OpenShellCLI).
		ta.OpenShellCLI = func() string {
			if installed {
				return ta.home + "/.local/bin/openshell"
			}
			return ""
		}
		d := ta.runDoctor(bg).Get(CheckIDDaemon)
		if d == nil || d.Status != openshell.StatusPass {
			t.Fatalf("%s: daemon row = %+v", c.mode, d)
		}
		has(t, d.Detail, c.want)
		lacks(t, d.Detail, "registration")
	}
	// A running sandbox whose gateway went away still fails.
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Available, ta.daemon.status.Running = false, 1
	if d := ta.runDoctor(bg).Get(CheckIDDaemon); d == nil || d.Status != openshell.StatusFail {
		t.Fatalf("daemon row with a sandbox running = %+v", d)
	}
}

// A daemon that started before its user joined the docker group cannot build
// the first run's image. Before the first sandbox the doctor still called it
// ready, and told the user of a managed computer to restart a command they
// do not have (GAP-0556): the row fails and says to sign in again.
func TestManagedDoctorFailsADaemonWithoutTheDockerGroupBeforeTheFirstRun(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Available, ta.daemon.status.Running = false, 0
	ta.daemon.status.DockerGroupMissing = true
	rep := ta.runDoctor(bg)
	d := rep.Get(CheckIDDaemon)
	if d == nil || d.Status != openshell.StatusFail || d.Fix == nil || d.Fix.Command != "" {
		t.Fatalf("daemon row = %+v", d)
	}
	has(t, d.Detail, "started before you joined the docker group")
	has(t, d.Fix.Summary, "sign out of every session of this account and sign in again")
	lacks(t, d.Fix.Summary, "defenseclaw-gateway")
	if rep.OK() {
		t.Fatalf("the doctor reports ready: %+v", rep.Checks)
	}
}

// A gateway the account started besides the organization's shares the
// MicroVM state and stopped a running managed sandbox: status and the doctor
// say it runs, and what it does (GAP-0610).
func TestManagedStatusAndDoctorNameAnotherGatewayOfTheAccount(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.ok(t, ta.Status(bg, "", OutputText))
	lacks(t, ta.output(), "Other gateway")
	if c := ta.runDoctor(bg).Get("other-gateway"); c != nil {
		t.Fatalf("a row without another gateway: %+v", c)
	}

	ta.daemon.status.Managed.OtherGateways = []string{"pid 520: /home/bob/.local/bin/openshell-gateway --config /home/bob/private.toml"}
	ta.out.Reset()
	ta.ok(t, ta.fresh().Status(bg, "", OutputText))
	has(t, ta.output(), "Other gateway", "pid 520: /home/bob/.local/bin/openshell-gateway", "can stop your sandboxes' VMs")
	c := ta.runDoctor(bg).Get("other-gateway")
	if c == nil || c.Status != openshell.StatusWarn || c.Fix == nil {
		t.Fatalf("doctor row = %+v", c)
	}
	has(t, c.Detail, "another OpenShell gateway runs in your account", "pid 520")
}

func TestManagedStatusAndDoctorReportEditedGatewayRender(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.RenderedConfigDrift = true
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "Settings drift", "OpenShell gateway configuration changed outside DefenseClaw")
	rep := ta.runDoctor(bg)
	row := rep.Get(CheckIDManagedRuntime)
	if row == nil || row.Status != openshell.StatusFail || row.Fix == nil || rep.OK() {
		t.Fatalf("edited render doctor = %+v, report OK=%t", row, rep.OK())
	}
	has(t, row.Detail, "configuration changed outside DefenseClaw")
}

// An account sandboxes can't run for (not in the docker group) was told to
// build the harness images now, which could only fail (GAP-0460).
func TestManagedDoctorBuildsNoImagesWhileSandboxesAreUnavailable(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.images.missing = map[string]bool{"claudecode": true}
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.Unavailable = "your account isn't in the docker group"
	rep := ta.runDoctor(bg)
	img := rep.Get(CheckIDImages)
	if img == nil || img.Fix != nil || img.Status == openshell.StatusWarn {
		t.Fatalf("images row = %+v", img)
	}
	has(t, img.Detail, "not built yet", "built once sandboxes are available for your account")
	if rt := rep.Get(CheckIDManagedRuntime); rt == nil || rt.Status != openshell.StatusFail {
		t.Fatalf("runtime row = %+v", rt)
	}
	// Where sandboxes run, the build stays offered.
	ta = newTestApp(t, "")
	ta.images.missing = map[string]bool{"claudecode": true}
	ta.daemon.status.Managed = managedStatusFixture()
	if img := ta.runDoctor(bg).Get(CheckIDImages); img == nil || img.Fix == nil {
		t.Fatalf("images row = %+v", img)
	}
}

// The doctor's Shell wrappers row told a user the organization requires to
// run Claude Code in a sandbox that DEFENSECLAW_NO_SANDBOX=1 bypasses its
// wrapper, a host run the hooks refuse there (GAP-0489). On a managed
// computer it names the bypass only for the agents that may run on the host.
func TestManagedDoctorOffersNoBypassOfARequiredSandbox(t *testing.T) {
	ta := newTestApp(t, "")
	writeConfig(t, ta, "")
	bin := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	ta.Executable = func() (string, error) { return bin, nil }
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "claude", Shell: "bash"}))
	ta.ok(t, ta.Enable(WrapperOptions{Harness: "opencode", Shell: "bash"}))
	ta.daemon.explain.Managed = managedExplainFixture() // requires claudecode and codex
	got := ta.wrappersCheck(bg, true).Detail
	has(t, got, "claude, opencode in ~/.bashrc", "(DEFENSECLAW_NO_SANDBOX=1 runs opencode on the host)")
	lacks(t, got, "bypasses", "runs claude")

	ta.daemon.explain.Managed.RequiredFor = []string{"claudecode", "opencode"}
	lacks(t, ta.wrappersCheck(bg, true).Detail, "DEFENSECLAW_NO_SANDBOX")
	ta.daemon.errors["GET "+sandboxapi.PathPolicyExplain] = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "not reachable"}
	lacks(t, ta.wrappersCheck(bg, true).Detail, "DEFENSECLAW_NO_SANDBOX")
	// Elsewhere the bypass stays documented.
	has(t, ta.wrappersCheck(bg, false).Detail, "(DEFENSECLAW_NO_SANDBOX=1 bypasses)")
}

func TestAgoText(t *testing.T) {
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{10 * time.Second: "just now", 2 * time.Minute: "2 min ago", 3 * time.Hour: "3 h ago", 72 * time.Hour: "3 days ago"} {
		if got := agoText(now.Add(-d), now); got != want {
			t.Errorf("agoText(-%v) = %q, want %q", d, got, want)
		}
	}
	if agoText(time.Time{}, now) != "" {
		t.Error("a zero time has no age")
	}
}

// On a managed computer a run the preflight would refuse asks the managed
// gateway at create, before anything is staged: its refusal is the one the
// user reads, and a create it lets through is deleted again (GAP-0197).
func TestManagedRunRefusalComesFromTheCreate(t *testing.T) {
	refused := func(ta *testApp, constraint, message string) {
		ta.daemon.explain.Managed = &sandboxapi.ManagedExplain{Profile: "contractors", Allowed: true}
		ta.daemon.explain.Violations = []sandboxapi.Violation{{Key: "sandbox", Fatal: true, Admin: true, Constraint: constraint, Message: message}}
	}
	ta := newTestApp(t, "")
	refused(ta, "openshell.admin.allowed", "blocked by your organization's DefenseClaw policy: sandbox")
	ta.daemon.refuseCreate = func(req sandboxapi.CreateRequest) *sandboxapi.Error {
		if !req.Copy || req.Harness != "claudecode" {
			t.Errorf("create = %+v", req)
		}
		return &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: "Your organization doesn't allow sandboxes for your account."}
	}
	err := ta.Run(bg, RunOptions{Harness: "claude"})
	wantErr(t, err, "Your organization doesn't allow sandboxes for your account.")
	lacks(t, err.Error(), "openshell.admin.allowed")
	if ta.creates() != 1 || len(ta.copy.steps) != 0 {
		t.Fatalf("creates %d, copy steps %v", ta.creates(), ta.copy.steps)
	}

	ta = newTestApp(t, "")
	refused(ta, "openshell.admin.allowed_harnesses", "claude is not an allowed harness")
	err = ta.Run(bg, RunOptions{Harness: "claude"})
	wantErr(t, err, "claude is not an allowed harness")
	// The delete forgets the CLI's state of the sandbox (its staged copy,
	// which there is none of, included): nothing was staged.
	if ta.creates() != 1 || slices.ContainsFunc(ta.copy.steps, func(s string) bool { return !strings.HasPrefix(s, "discard ") }) ||
		len(ta.daemon.calls) == 0 || !ta.deletedOne() {
		t.Fatalf("a create the gateway let through was kept: creates %d, copy steps %v", ta.creates(), ta.copy.steps)
	}
}

// deletedOne reports a DELETE of a sandbox.
func (ta *testApp) deletedOne() bool {
	ta.daemon.mu.Lock()
	defer ta.daemon.mu.Unlock()
	for _, c := range ta.daemon.calls {
		if c.Method == "DELETE" && strings.HasPrefix(c.Path, sandboxapi.PathSandboxes+"/") {
			return true
		}
	}
	return false
}

// #1200: the MCP row counts the servers the project defines, and says
// whether the pack lets them start.
func TestManagedExplainRowCountsProjectMCPServers(t *testing.T) {
	m := managedExplainFixture()
	m.MCPIncluded, m.MCPBlocked = nil, nil
	m.MCPProjectCount, m.MCPProjectBlocked = 1, true
	row := func() string {
		for _, r := range managedExplainRows(m, time.Now()) {
			if r.label == "MCP" {
				return r.text
			}
		}
		return ""
	}
	if got := row(); got != "0 of your servers included; the project's 1 server doesn't start (the pack blocks project servers)" {
		t.Fatalf("MCP row = %q", got)
	}
	m.MCPProjectCount, m.MCPProjectBlocked = 2, false
	if got := row(); !strings.HasSuffix(got, "the project's 2 servers start (the pack allows project servers)") {
		t.Fatalf("MCP row = %q", got)
	}
}

// A doctor in the request-limit window names the limit, not a failed
// policy, and a policy read that failed for another reason says why
// (GAP-2203).
func TestDoctorNamesTheRequestLimitNotAFailedPolicy(t *testing.T) {
	ta := newTestApp(t, "")
	limited := &sandboxapi.ManagedStatus{PolicyLimited: true,
		PolicyUnread: "DefenseClaw is limiting the hook requests of this account; retry shortly"}
	c := ta.managedPolicyCheck(bg, limited)
	if c.Status != openshell.StatusWarn {
		t.Errorf("limited row status = %v, want warn: %+v", c.Status, c)
	}
	has(t, c.Detail, "your organization's policy", "a burst of sandbox commands reached that limit", "in a few seconds")
	lacks(t, c.Detail, "could not be confirmed", "hook")
	if c.Fix == nil || !strings.Contains(c.Fix.Summary, "doctor again") {
		t.Errorf("limited row fix = %+v", c.Fix)
	}
	unread := ta.managedPolicyCheck(bg, &sandboxapi.ManagedStatus{PolicyUnread: "the managed DefenseClaw gateway is not reachable"})
	if unread.Status != openshell.StatusFail {
		t.Errorf("unread row status = %v", unread.Status)
	}
	has(t, unread.Detail, "could not be confirmed for your account: the managed DefenseClaw gateway is not reachable")
	// A denial stays a failure even when another harness was limited.
	denied := ta.managedPolicyCheck(bg, &sandboxapi.ManagedStatus{DeniedHarnesses: []string{"codex"}, PolicyLimited: true, PolicyUnread: "limited"})
	if denied.Status != openshell.StatusFail || !strings.Contains(denied.Detail, "doesn't allow sandboxes for codex") {
		t.Errorf("denied row = %+v", denied)
	}
}
