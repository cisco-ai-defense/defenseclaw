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

package sandboxcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// This file is the user-facing side of the managed sandbox policy (plan
// section 7.1): the "Policy" lines of the launch banner, `policy explain`
// and `status`, and the commands that go through the daemon instead of the
// local configuration on a managed computer, where a user cannot read the
// administrator's config.yaml. Everything shown here is the caller's own
// policy as the managed gateway resolved it (sandboxapi.ManagedStatus and
// ManagedExplain carry no field about another account); texts a person
// wrote (profile description, request-access contact) are made safe to
// print by the terminal writers.

// onManagedHost reports whether this computer is a standalone managed
// deployment, where the CLI asks the daemon for the user's own policy
// instead of resolving it from a configuration the user cannot read. It is
// false wherever the runtime descriptor is absent (every OSS computer), so
// the extra daemon call below never happens there. Replaceable in tests.
var onManagedHost = managed.IsStandaloneManagedHost

// managedRenderedGateway is where the administrator's lifecycle renders the
// OpenShell gateway configuration the account's managed gateway runs on
// (<config dir>/openshell); nil when the layout is unknown. Replaceable in
// tests.
var managedRenderedGateway = func() *openshell.RenderedPaths {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return nil
	}
	dir := filepath.Join(layout.ConfigDir, "openshell")
	return &openshell.RenderedPaths{TOML: filepath.Join(dir, openshell.GatewayTOMLFile), Env: filepath.Join(dir, openshell.GatewayEnvFile)}
}

// managedPolicyLine is the launch banner's Policy line: the caller's profile
// and its description, or that the organization's default applies while the
// directory could not be reached, and where the details are.
func managedPolicyLine(m *sandboxapi.ManagedStatus) string {
	if m == nil {
		return ""
	}
	name := sandboxapi.DisplayText(m.Profile)
	if name == "" {
		name = "your organization's policy"
	}
	text := name
	switch {
	case m.Provisional:
		text += " (provisional): your directory couldn't be reached; your organization's default applies"
	case strings.TrimSpace(m.Description) != "":
		text += ": " + strings.TrimSpace(sandboxapi.DisplayText(m.Description))
	}
	if !strings.HasSuffix(text, ".") {
		text += "."
	}
	if m.HostRunGate == "exempt" {
		text += " Your account is exempt from enrollment; required_for does not apply and a host run is allowed."
	}
	return text + " Details: defenseclaw sandbox policy explain"
}

// managedDriverLine is the launch banner's Driver line on a managed
// computer: the sandbox's compute driver and why, such as "docker
// (fallback: KVM not available on this computer)". "" off managed hosts.
func managedDriverLine(sb *sandboxapi.Sandbox, m *sandboxapi.ManagedStatus) string {
	if m == nil || sb == nil {
		return ""
	}
	return sandboxapi.DisplayText(openshell.DriverChoiceText(sb.Driver, sb.DriverReason))
}

// managedDriverText is how status and doctor name the caller's driver and
// its fallback: "docker (fallback: KVM not available on this computer)",
// "vm (KVM is available on this computer); docker where KVM is not".
func managedDriverText(driver, reason, fallback string) string {
	text := sandboxapi.DisplayText(openshell.DriverChoiceText(driver, reason))
	if text == "" {
		return ""
	}
	if openshell.IsFallbackReason(reason) {
		return text
	}
	switch fallback {
	case config.EnterpriseOpenShellFallbackDocker:
		text += "; docker where KVM is not available"
	case config.EnterpriseOpenShellFallbackNone:
		text += "; MicroVM required (no docker fallback)"
	}
	return text
}

// managedStatusOfExplain is the banner's view of a sandbox's managed explain
// (the connect banner has the explain, not the status).
func managedStatusOfExplain(m *sandboxapi.ManagedExplain) *sandboxapi.ManagedStatus {
	if m == nil {
		return nil
	}
	return &sandboxapi.ManagedStatus{Profile: m.Profile, Description: m.Description, Allowed: m.Allowed, HostRunGate: m.HostRunGate, Provisional: m.Provisional,
		EffectiveDigest: m.PolicyDigest, UpdatedAt: m.UpdatedAt, RequestAccess: m.RequestAccess,
		Driver: m.Driver, DriverReason: m.DriverReason, DriverFallback: m.DriverFallback}
}

// agoText is how long ago t was, for "updated 2 min ago".
func agoText(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case t.IsZero():
		return ""
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d days ago", int(d/(24*time.Hour)))
	}
}

// commandNames shows connector names the way a person types them
// ("claudecode" is "claude").
func commandNames(connectors []string) []string {
	out := make([]string, len(connectors))
	for i, c := range connectors {
		out[i] = c
		if spec, ok := harness.Get(c); ok && spec.Command != "" {
			out[i] = spec.Command
		}
	}
	return out
}

// andList joins words as "a", "a and b", "a, b and c".
func andList(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// matchText is how the caller's profile matched, in the caller's words.
func matchText(m *sandboxapi.ManagedExplain) string {
	switch m.Match {
	case "agent":
		return "your agent is assigned to it"
	case "user":
		return "you are assigned to it"
	case "group":
		if m.MatchedGroup != "" {
			return "your group " + sandboxapi.DisplayText(m.MatchedGroup)
		}
		return "one of your groups"
	case "connector":
		return "this agent is assigned to it"
	case "default":
		return "the default for everyone"
	case "default_unverified":
		return "the default (your identity could not be verified)"
	case "default_lookup_failed":
		return "the default (your directory couldn't be reached; no assignment needs the missing facts)"
	case "none":
		return "no organization profile applies; your organization's floor does"
	}
	return sandboxapi.DisplayText(m.Match)
}

// explainSourceText names a value's source as the user should read it: the
// organization's rule for everyone, or the user's own profile; never another
// profile's name (Q7).
func explainSourceText(source string) string {
	switch source {
	case sandboxapi.ExplainSourceOrganization:
		return "your organization (everyone)"
	case sandboxapi.ExplainSourceProfile:
		return "your organization profile"
	case sandboxapi.ExplainSourcePack:
		return "the pack"
	case sandboxapi.ExplainSourceRepo:
		return "this repository's policy"
	case sandboxapi.ExplainSourceFlag:
		return "your command line"
	}
	return sandboxapi.DisplayText(source)
}

// managedExplainProvenance replaces the posture's generic admin label with
// the source the gateway resolved for this caller. Pack locations describe
// storage; a required pack's selection instead comes from its floor setting.
func managedExplainProvenance(ex *sandboxapi.Explain) {
	if ex.Managed == nil {
		return
	}
	m := ex.Managed
	for i := range ex.Settings {
		s := &ex.Settings[i]
		if key := managedFloorKey(*s); key != "" {
			switch source := m.Sources[key]; source {
			case sandboxapi.ExplainSourceOrganization:
				s.Source, s.Origin = source, "openshell.admin."+key
			case sandboxapi.ExplainSourceProfile:
				if m.Profile != "" {
					s.Source, s.Origin = source, "guardrail.profiles."+m.Profile+".sandbox."+key
				}
			}
			if s.Key == "pack" && key == "required_pack" {
				if s.Source == sandboxapi.ExplainSourceOrganization || s.Source == sandboxapi.ExplainSourceProfile {
					ex.PackSource = s.Source
				}
			}
		}
	}
}

// managedFloorKey is the setting a floor constraint actually names, which
// may differ from the effective key (max_silence_after vs hooks.silence_after).
func managedFloorKey(s sandboxapi.Setting) string {
	if key, ok := strings.CutPrefix(s.Origin, "openshell.admin."); ok {
		return key
	}
	if strings.HasPrefix(s.Origin, "guardrail.profiles.") {
		_, key, ok := strings.Cut(s.Origin, ".sandbox.")
		if ok {
			return key
		}
	}
	return ""
}

// managedSettingOrigin keeps the real key visible in narrow terminals.
// The profile named here is always the caller's own matched profile.
func managedSettingOrigin(ex *sandboxapi.Explain, s sandboxapi.Setting) string {
	if m := ex.Managed; m != nil {
		if key, ok := strings.CutPrefix(s.Origin, "guardrail.profiles."+m.Profile+".sandbox."); ok {
			return "sandbox." + key + " (organization profile " + sandboxapi.DisplayText(m.Profile) + ")"
		}
	}
	if name, ok := strings.CutPrefix(s.Origin, "profile "); ok {
		return "network profile " + name
	}
	return s.Origin
}

// managedRow is one line of the managed explain: its label, its text, and
// the explained keys whose sources `--sources` shows for it.
type managedRow struct {
	label, text string
	keys        []string
}

// managedExplainRows renders the caller's own policy (plan section 7.1).
// Rows with nothing to say are left out; the text is plain words.
func managedExplainRows(m *sandboxapi.ManagedExplain, now time.Time) []managedRow {
	return managedExplainRowsFor(m, nil, "", now)
}

func managedProfileIdentity(m *sandboxapi.ManagedExplain) string {
	profile := sandboxapi.DisplayText(m.Profile)
	if profile == "" {
		profile = "(your organization's floor)"
	}
	text := profile + "   matched: " + matchText(m)
	if m.Provisional {
		text += "; provisional until your directory answers"
	}
	return text
}

// managedExplainRowsFor is managedExplainRows with the explained run's
// posture (ex: its pack and modes, nil when unknown) and the agent the
// explain names ("" none).
func managedExplainRowsFor(m *sandboxapi.ManagedExplain, ex *sandboxapi.Explain, harnessName string, now time.Time) []managedRow {
	var rows []managedRow
	add := func(label, text string, keys ...string) { rows = append(rows, managedRow{label, text, keys}) }

	add("Organization profile", managedProfileIdentity(m))
	if d := strings.TrimSpace(m.Description); d != "" {
		add("", sandboxapi.DisplayText(d))
	}

	switch {
	case !m.Allowed:
		add("Sandboxes", "your organization doesn't allow sandboxes for you", "allowed")
		if len(m.RequiredFor) > 0 && m.HostRunGate == "exempt" {
			add("Required", "your account is exempt from enrollment (enterprise.enrollment.exempt_users), so required_for doesn't apply to you: "+
				andList(commandNames(m.RequiredFor))+" may run on this computer outside a sandbox, where their calls are still inspected and logged", "required_for")
		}
	case len(m.RequiredFor) > 0 && m.HostRunGate == "exempt":
		// The managed gateway's host-run gate allows this account's runs;
		// required_for alone would give a false protected status (GAP-0555).
		add("Required", "your account is exempt from enrollment (enterprise.enrollment.exempt_users), so required_for doesn't apply to you: "+
			andList(commandNames(m.RequiredFor))+" may also run on this computer outside a sandbox, where their calls are still inspected and logged",
			"required_for")
	case len(m.RequiredFor) > 0:
		text := andList(commandNames(m.RequiredFor)) + " run only in a sandbox on this computer"
		keys := []string{"required_for"}
		if m.WhenUnavailable == "alert" {
			text += "; where sandboxes can't run they are allowed and your administrators are alerted"
			keys = append(keys, "when_unavailable")
		}
		add("Required", text, keys...)
	default:
		add("Required", "no agent has to run in a sandbox", "required_for")
	}
	if len(m.AllowedHarnesses) > 0 {
		add("Agents", "only "+andList(commandNames(m.AllowedHarnesses))+" may run in a sandbox", "allowed_harnesses")
	}
	if text := managedPackText(ex); text != "" {
		add("Pack", text, "setting:pack", "setting:profile", "setting:network.mode", "setting:approvals.mode")
	}
	if len(m.AllowedCredentials) > 0 {
		if len(m.AllowedCredentials) == 1 && m.AllowedCredentials[0] == "none" {
			add("Credentials", "no credentials go into a sandbox", "allowed_credentials")
		} else {
			add("Credentials", "only "+andList(m.AllowedCredentials)+" may go into a sandbox", "allowed_credentials")
		}
	}

	var egress []string
	if n := len(m.EgressAllowOnly); n > 0 {
		egress = append(egress, fmt.Sprintf("only %s reachable (%s)", plural(int64(n), "host is", "hosts are"),
			listFit(strings.Join(m.EgressAllowOnly, ", "), 56)))
	}
	blocks := m.EgressBlock
	blockKey, singular, multiple := "egress_block", "host is", "hosts are"
	if ex != nil {
		if value := settingValue(ex.Settings, "egress.admin_block"); value != "" {
			blocks = splitList(value)
			blockKey, singular, multiple = "setting:egress.admin_block", "host pattern is", "host patterns are"
		}
	}
	if n := len(blocks); n > 0 {
		egress = append(egress, fmt.Sprintf("%s always blocked (%s)", plural(int64(n), singular, multiple),
			listFit(strings.Join(blocks, ", "), 56)))
	}
	if len(egress) == 0 {
		egress = []string{"your organization limits no hosts; the pack's network rules apply"}
	}
	var egressKeys []string
	if len(m.EgressAllowOnly) > 0 {
		egressKeys = append(egressKeys, "egress_allow_only")
	}
	if len(blocks) > 0 {
		egressKeys = append(egressKeys, blockKey)
	}
	add("Egress", strings.Join(egress, "; "), egressKeys...)

	// What the managed gateway's check of each answer allows
	// (sandboxreg.CheckApprovals): under allow_unblock: false an answer is
	// kept for this session only, and `approve --always` is refused; the
	// row said "for good" there (#1200).
	var approvals string
	switch {
	case m.UserApprovals == "none":
		approvals = "you can't approve asks; they are refused"
	case m.UserApprovals == "session" || !m.AllowUnblock:
		approvals = "you may approve asks for this session only"
	default:
		approvals = "you may approve asks for a session or for good"
	}
	if !m.AllowUnblock {
		approvals += "; you can't unblock destinations"
	}
	add("Approvals", approvals, "user_approvals", "allow_unblock")
	foreign := "stopped"
	if m.ForeignSandboxes == config.OpenShellForeignSandboxesAlert {
		foreign = "reported to your administrators"
	}
	add("Other sandboxes", "sandboxes outside DefenseClaw are "+foreign, "foreign_sandboxes")

	if len(m.MCPIncluded) > 0 || len(m.MCPBlocked) > 0 || m.MCPProjectCount > 0 {
		var org, asset int
		for _, b := range m.MCPBlocked {
			if b.Reason == "asset_policy" {
				asset++
			} else {
				org++
			}
		}
		text := fmt.Sprintf("%d of your servers included", len(m.MCPIncluded))
		if org > 0 {
			text += fmt.Sprintf("; %d blocked by your organization", org)
		}
		if asset > 0 {
			text += fmt.Sprintf("; %d left out by your organization's asset policy", asset)
		}
		if n := m.MCPProjectCount; n > 0 {
			verb, why := "don't start", "the pack blocks project servers"
			if !m.MCPProjectBlocked {
				verb, why = "start", "the pack allows project servers"
			}
			if n == 1 {
				verb = map[string]string{"don't start": "doesn't start", "start": "starts"}[verb]
			}
			text += "; the project's " + plural(int64(n), "server", "servers") + " " + verb + " (" + why + ")"
		}
		add("MCP", text, "mcp_included", "mcp_blocked")
	}

	workspace := []string{"copy mode"}
	if m.WorkdirMode != "" && m.WorkdirMode != "copy" {
		workspace = []string{m.WorkdirMode + " mode"}
	}
	if !m.AllowMount {
		workspace = append(workspace, "no mounts")
	}
	if !m.AllowHostPorts {
		workspace = append(workspace, "no host ports")
	}
	if !m.AllowYolo {
		workspace = append(workspace, "skip-permissions off")
	}
	add("Workspace", strings.Join(workspace, "; "), "workdir_mode", "allow_mount", "allow_host_ports", "allow_yolo")
	if text := managedDriverText(m.Driver, m.DriverReason, m.DriverFallback); text != "" {
		add("Driver", text, "driver_fallback")
	} else if m.DriverFallback == config.EnterpriseOpenShellFallbackNone {
		add("Driver", "MicroVM required (no docker fallback where KVM is not available)", "driver_fallback")
	}

	// The resolved pack may supply the silence action and interval when
	// neither is set in the caller's organization floor.
	onSilence, after := m.OnSilence, m.MaxSilenceAfter
	actionKey, intervalKey := "on_silence", "max_silence_after"
	if ex != nil {
		if value := settingValue(ex.Settings, "hooks.on_silence"); value != "" {
			onSilence, actionKey = value, "setting:hooks.on_silence"
		}
		if value := settingValue(ex.Settings, "hooks.silence_after"); value != "" {
			after, intervalKey = value, "setting:hooks.silence_after"
		}
	}
	var hooks, hookKeys []string
	if onSilence != "" || after != "" {
		who := m.AllowedHarnesses
		if len(who) == 0 {
			who = m.RequiredFor
		}
		if harnessName != "" {
			if spec, err := ResolveHarness(harnessName); err == nil {
				who = []string{spec.Name}
			}
		}
		hooks = append(hooks, silenceTexts(onSilence, after, who)...)
		if onSilence != "" {
			hookKeys = append(hookKeys, actionKey)
		}
		if after != "" {
			hookKeys = append(hookKeys, intervalKey)
		}
	}
	if m.ProcessTree {
		hooks = append(hooks, "the process tree is watched")
		hookKeys = append(hookKeys, "process_tree")
	}
	if len(hooks) > 0 {
		add("Hooks", strings.Join(hooks, "; "), hookKeys...)
	}
	if m.DeleteStoppedAfter != "" {
		add("Cleanup", "a stopped sandbox is deleted after "+sandboxapi.DisplayText(m.DeleteStoppedAfter), "delete_stopped_after")
	}

	id := firstNonEmpty(strings.TrimPrefix(shortDigest(m.PolicyDigest), "("), m.PolicyDigest)
	id = strings.TrimSuffix(id, ")")
	if id == "" {
		id = "(none)"
	}
	id += " (yours)"
	if ago := agoText(m.UpdatedAt, now); ago != "" {
		id += ", updated " + ago
	}
	id += "; access: " + sandboxapi.RequestAccessText(m.RequestAccess)
	add("Policy id", id)
	return rows
}

// managedPackText is the Pack row of a managed explain: the pack the
// explained run uses, its network and approval modes, and what of the
// organization's floor decides them (a required pack, a profile minimum),
// as the managed gateway resolved them (GAP-0179, GAP-0438).
func managedPackText(ex *sandboxapi.Explain) string {
	if ex == nil || ex.Pack == "" {
		return ""
	}
	text := sandboxapi.DisplayText(ex.Pack)
	for _, s := range ex.Settings {
		if s.Key == "pack" && managedFloorKey(s) == "required_pack" {
			text += " (required)"
		}
	}
	text += "; network " + sandboxapi.DisplayText(ex.NetworkMode) + ", approvals " + sandboxapi.DisplayText(ex.Approvals)
	for _, s := range ex.Settings {
		if s.Key == "profile" && managedFloorKey(s) == "min_profile" {
			who := "your organization"
			if s.Source == sandboxapi.ExplainSourceProfile {
				who = "your organization profile"
			}
			text += " (" + who + " requires at least the " + sandboxapi.DisplayText(s.Value) + " network profile)"
		}
	}
	return text
}

// silenceTexts say what happens when an agent's hooks fall silent for
// after: the floor's on_silence for the agents whose hooks a user can
// change (the user tier), and only an alert for the agents whose hooks are
// managed, whatever the floor says (the managed sandbox's silence response;
// GAP-0477). who are the agents the explain is about (none: every agent).
func silenceTexts(onSilence, after string, who []string) []string {
	if after == "" {
		after = "a while"
	}
	suffix := " after " + after + " of agent work without hooks"
	if onSilence != "stop" {
		if len(who) == 0 {
			return []string{"an alert" + suffix}
		}
		return []string{andList(commandNames(who)) + ": an alert" + suffix}
	}
	if len(who) == 0 {
		return []string{"a stop" + suffix + " (an alert for agents whose hooks are managed)"}
	}
	var user, managedTier []string
	for _, c := range who {
		if spec, ok := harness.Get(c); ok && spec.TamperTier != connector.SandboxTamperTierUser {
			managedTier = append(managedTier, c)
		} else {
			user = append(user, c)
		}
	}
	var out []string
	if len(user) > 0 {
		out = append(out, andList(commandNames(user))+": a stop"+suffix)
	}
	if len(managedTier) > 0 {
		out = append(out, andList(commandNames(managedTier))+": an alert"+suffix+" (managed hooks)")
	}
	return out
}

// printManagedExplainFor prints the caller's own policy, the explained
// run's posture and agent; with sources each row names its actual sources.
func (a *App) printManagedExplainFor(m *sandboxapi.ManagedExplain, ex *sandboxapi.Explain, harnessName string, sources bool) {
	a.line(a.bold("Your sandbox policy on this computer"))
	width := 0
	rows := managedExplainRowsFor(m, ex, harnessName, a.Now())
	for _, r := range rows {
		width = max(width, len(r.label))
	}
	for _, r := range rows {
		tag := ""
		if sources {
			if s := managedRowSources(m, ex, r.keys); s != "" {
				tag = a.dim("   [from " + s + "]")
			}
		}
		a.labelled("  ", r.label, width, r.text, tag)
	}
}

// managedRowSources is the distinct sources of a row's keys, in the plan's
// order (everyone's rule first).
func managedRowSources(m *sandboxapi.ManagedExplain, ex *sandboxapi.Explain, keys []string) string {
	seen := map[string]bool{}
	for _, k := range keys {
		if key, ok := strings.CutPrefix(k, "setting:"); ok {
			if ex != nil {
				for _, s := range ex.Settings {
					if s.Key == key && s.Source != "" {
						seen[s.Source] = true
					}
				}
			}
			continue
		}
		if s := m.Sources[k]; s != "" {
			seen[s] = true
		}
	}
	var out []string
	for _, s := range []string{sandboxapi.ExplainSourceOrganization, sandboxapi.ExplainSourceProfile, sandboxapi.ExplainSourcePack,
		sandboxapi.ExplainSourceRepo, sandboxapi.ExplainSourceFlag} {
		if seen[s] {
			out = append(out, explainSourceText(s))
			delete(seen, s)
		}
	}
	var other []string
	for s := range seen {
		other = append(other, explainSourceText(s))
	}
	sort.Strings(other)
	return strings.Join(append(out, other...), ", ")
}

// ManagedPackAPI is what the daemon's client offers on a managed computer:
// the packs of the caller's own effective chain, nothing else
// (*sandboxapi.Client implements it).
type ManagedPackAPI interface {
	ListManagedPacks(ctx context.Context) ([]sandboxapi.ManagedPack, error)
	GetManagedPack(ctx context.Context, name string) (*sandboxapi.ManagedPack, error)
}

// managedPackAPI is the pack API on a managed computer, nil (and no error)
// elsewhere: there the packs come from the daemon, not from a directory the
// user may not read. On a managed computer it never falls back to the local
// pack directory: when the daemon cannot be reached or cannot list packs the
// caller gets that error, not packs that are not the caller's own chain.
func (a *App) managedPackAPI() (ManagedPackAPI, error) {
	if !onManagedHost() {
		return nil, nil
	}
	api, err := a.api()
	if err != nil {
		return nil, err
	}
	packs, ok := api.(ManagedPackAPI)
	if !ok {
		return nil, errors.New("the sandbox service on this computer can't list your packs; ask your administrator")
	}
	return packs, nil
}

// managedPackList is `pack list` on a managed computer.
func (a *App) managedPackList(ctx context.Context, api ManagedPackAPI, o PackOptions) error {
	list, err := api.ListManagedPacks(ctx)
	if err != nil {
		return apiError(err)
	}
	if o.Output == OutputJSON {
		if list == nil {
			list = []sandboxapi.ManagedPack{}
		}
		return writeJSON(a.IO.Out, map[string]any{"packs": list})
	}
	if len(list) == 0 {
		a.note("your policy uses no pack")
		return nil
	}
	rows := make([][]string, 0, len(list))
	for _, p := range list {
		rows = append(rows, []string{p.Name, firstNonEmpty(p.Source, "-"), firstNonEmpty(p.Extends, "-"), firstNonEmpty(p.Digest, "-")})
	}
	a.table([]string{"NAME", "SOURCE", "EXTENDS", "DIGEST"}, rows)
	a.note("these are the packs your own policy uses")
	return nil
}

// managedPackShow is `pack show` on a managed computer: a pack outside the
// caller's own chain is "not found", as for any other account's.
func (a *App) managedPackShow(ctx context.Context, api ManagedPackAPI, ref string, o PackOptions) error {
	p, err := api.GetManagedPack(ctx, ref)
	if err != nil {
		return apiError(err)
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, p)
	}
	a.println("# pack " + sandboxapi.DisplayText(p.Name) + " (" + sandboxapi.DisplayText(firstNonEmpty(p.Source, "your policy")) + ")")
	a.println("# digest " + sandboxapi.DisplayText(p.Digest))
	if p.Extends != "" {
		a.println("# extends " + sandboxapi.DisplayText(p.Extends))
	}
	_, err = io.WriteString(a.IO.Out, terminalText(p.Content))
	if err == nil && !strings.HasSuffix(p.Content, "\n") {
		_, err = io.WriteString(a.IO.Out, "\n")
	}
	return err
}

// firstManaged is the first managed policy that is set.
func firstManaged(list ...*sandboxapi.ManagedStatus) *sandboxapi.ManagedStatus {
	for _, m := range list {
		if m != nil {
			return m
		}
	}
	return nil
}

// managedOffState is the Sandboxes row of `status` while sandboxes are off
// for a user on a managed computer: what the user may know, without another
// account's name, uid or PID, and no advice to run setup (the organization
// manages the setting).
func managedOffState(st *sandboxapi.Status) string {
	switch {
	case st.GatewayElsewhere != "":
		return "not available for your account right now: another account is using them"
	case st.Managed.Unavailable != "":
		return "not available on this computer: " + sandboxapi.DisplayText(st.Managed.Unavailable)
	}
	return "off on this computer; your organization manages this setting"
}

// managedAccountBusyText is the OpenShell row of a managed computer whose
// one gateway port another account's sandboxes hold now (GAP-0461).
const managedAccountBusyText = "not available for your account right now: another account is using sandboxes on this computer " +
	"(one account at a time); it clears when that account has no sandbox running"

// busyContact is who to ask while another account uses the sandboxes: the
// organization's request-access contact, else the IT help desk.
func busyContact(contact string) string {
	if text := sandboxapi.RequestAccessText(contact); text != sandboxapi.RequestAccessFallback {
		return "for help, contact " + text
	}
	return "for help, " + sandboxapi.RequestAccessFallback
}

// managedFirstRunText says what the next sandbox run does with the
// account's OpenShell on a managed computer whose organization runs
// sandboxes here and whose gateway is not running (GAP-0437, GAP-0441,
// GAP-0439): in setup mode, before the daemon installed OpenShell for the
// account, the first run installs it; after that, and in prerequisite mode,
// a run starts the gateway the daemon stops whenever no sandbox of the
// account runs (GAP-0465). It reads both as the status row and after the
// doctor's "running; ".
func (a *App) managedFirstRunText(m *sandboxapi.ManagedStatus) string {
	if a.managedInstallPending(m) {
		return strings.TrimSpace("OpenShell isn't installed for your account yet: your first `"+CommandName+" run` installs OpenShell "+
			m.OpenShellVersion) + " and starts its gateway"
	}
	return "your OpenShell gateway starts with your next `" + CommandName + " run`"
}

// managedInstallPending reports a setup-mode computer whose daemon has not
// installed the account's OpenShell yet.
func (a *App) managedInstallPending(m *sandboxapi.ManagedStatus) bool {
	return m.InstallMode == config.EnterpriseOpenShellInstallSetup && (a.OpenShellCLI == nil || a.OpenShellCLI() == "")
}

// neutralStatus is the status as the CLI prints it as JSON. On a managed
// computer a daemon's gateway_elsewhere (which could name another account's
// process) is reduced to the fact that another account holds the gateway: the
// field stays a non-empty flag for the consumers that read it (the TUI), with
// nothing about whose it is.
func neutralStatus(st *sandboxapi.Status) *sandboxapi.Status {
	if st == nil || st.Managed == nil || st.GatewayElsewhere == "" {
		return st
	}
	out := *st
	out.GatewayElsewhere = "another account"
	return &out
}

// organizationPolicyText is the "Your policy" row's value without its
// pointer to `policy explain`: the organization profile of the caller's
// match, whether it is provisional, and the digest of the effective policy
// of that same match.
func organizationPolicyText(profile string, provisional bool, digest string) string {
	policy := firstNonEmpty(sandboxapi.DisplayText(profile), "your organization's policy")
	if profile != "" {
		policy = "organization profile " + policy
	}
	if provisional {
		policy += " (provisional: your directory couldn't be reached; your organization's default applies)"
	}
	if id := shortDigest(digest); id != "" {
		policy += " " + id + " (yours)"
	}
	return policy
}

// managedStatusRows are the rows `status` adds on a managed computer: the
// caller's own policy and the daemon's OpenShell.
func managedStatusRows(m *sandboxapi.ManagedStatus, now time.Time) [][2]string {
	policy := organizationPolicyText(m.Profile, m.Provisional, m.EffectiveDigest)
	if ago := agoText(m.UpdatedAt, now); ago != "" {
		policy += ", updated " + ago
	}
	rows := [][2]string{{"Your policy", policy + " — " + CommandName + " policy explain"}}
	var openshell []string
	if m.OpenShellVersion != "" {
		openshell = append(openshell, "OpenShell "+sandboxapi.DisplayText(m.OpenShellVersion))
	}
	if m.InstallMode != "" {
		openshell = append(openshell, sandboxapi.DisplayText(m.InstallMode)+" install")
	}
	if len(openshell) > 0 {
		rows = append(rows, [2]string{"Runtime", strings.Join(openshell, ", ")})
	}
	if text := managedDriverText(m.Driver, m.DriverReason, m.DriverFallback); text != "" {
		rows = append(rows, [2]string{"Driver", text})
	}
	if m.PendingRestart {
		rows = append(rows, [2]string{"Pending", "an update of the sandbox service waits until your sandboxes stop"})
	}
	if m.RenderedConfigDrift {
		rows = append(rows, [2]string{"Settings drift", "your organization's OpenShell gateway configuration changed outside DefenseClaw; ask IT to repair it"})
	}
	if text := otherGatewaysText(m.OtherGateways); text != "" {
		rows = append(rows, [2]string{"Other gateway", text})
	}
	return append(rows, [2]string{"Access", sandboxapi.RequestAccessText(m.RequestAccess)})
}

// otherGatewaysText says that the account runs an OpenShell gateway besides
// the organization's, and what it does to the sandboxes ("" when it does
// not). Two gateways of one account share its MicroVM state: the second
// sweeps the first's sandboxes and stops them, and their unflushed work is
// lost (GAP-0610).
func otherGatewaysText(others []string) string {
	if len(others) == 0 {
		return ""
	}
	shown := others
	if len(shown) > 3 {
		shown = shown[:3]
	}
	text := "another OpenShell gateway runs in your account (" + sandboxapi.DisplayText(strings.Join(shown, "; ")) + "). It shares the MicroVM state " +
		"of your organization's gateway and can stop your sandboxes' VMs, losing what they have not written back: stop it before you rely on your sandboxes"
	if len(others) > len(shown) {
		text += fmt.Sprintf(" (%d more run)", len(others)-len(shown))
	}
	return text
}

// otherGatewaysCheck is the doctor's row for a gateway the account runs
// besides the organization's (nil when it runs none).
func otherGatewaysCheck(m *sandboxapi.ManagedStatus) *openshell.Check {
	text := otherGatewaysText(m.OtherGateways)
	if text == "" {
		return nil
	}
	return &openshell.Check{ID: "other-gateway", Title: "Other gateway", Status: openshell.StatusWarn, Detail: text,
		Fix: &openshell.Fix{Summary: "stop that process (`kill PID` with the number above) once your sandboxes are saved; your organization's gateway needs no other"}}
}

// managedSuggestionDiff is suggestionDiff on a managed computer: a pack can
// only make a sandbox stricter than the organization's floor, so what the
// diff can say is which reached hosts the floor itself blocks (they stay
// blocked whatever the pack allows).
func managedSuggestionDiff(against string, current *sandboxapi.Explain, s *suggestion) *suggestionDiff {
	m := current.Managed
	diff := &suggestionDiff{Against: against + " (pack " + current.Pack + "; your organization's policy applies on top of any pack)",
		Settings: []settingChange{}}
	for _, host := range s.order {
		h := s.byHost[host]
		if h.Requests == 0 || h.kind == sandboxapi.DestinationModelProvider || h.kind == sandboxapi.DestinationCredential {
			continue
		}
		rule, match := "", ""
		if hit := firstCovering(config.OpenShellAdminBlockPatterns(m.EgressBlock), host); hit != "" {
			rule, match = "admin_block", hit
		} else if len(m.EgressAllowOnly) > 0 && firstCovering(m.EgressAllowOnly, host) == "" {
			rule, match = "admin_allow_only", "not on your organization's list of allowed hosts"
		}
		if rule == "" {
			continue
		}
		ports := s.ports[host]
		if len(ports) == 0 {
			ports = []int{0}
		}
		for _, port := range ports {
			diff.Blocked = append(diff.Blocked, sandboxapi.PolicyDecision{PolicyCheck: sandboxapi.PolicyCheck{Host: host, Port: port},
				Rule: rule, Match: match, Source: "your organization"})
		}
	}
	return diff
}

// firstCovering is the first of globs that matches host, "" when none does.
func firstCovering(globs []string, host string) string {
	addr, _ := netip.ParseAddr(host)
	for _, g := range globs {
		if p, err := config.ParseOpenShellEgressPattern(g); err == nil && p.Matches(host, addr) {
			return g
		}
	}
	return ""
}

// managedPolicyCheck is the doctor's "Organization policy" row on a managed
// computer: the caller's own profile and policy id, never the local
// configuration, and a warning while the directory could not be reached.
func (a *App) managedPolicyCheck(ctx context.Context, m *sandboxapi.ManagedStatus) openshell.Check {
	c := openshell.Check{ID: CheckIDAdmin, Title: "Organization policy", Status: openshell.StatusPass}
	// Before the first sandbox the daemon knows no profile: the row then
	// names the policy, not a "profile" without a name (GAP-0175).
	c.Detail = "your organization's policy"
	if name := sandboxapi.DisplayText(m.Profile); name != "" {
		c.Detail = "organization profile " + name
	}
	if id := shortDigest(m.EffectiveDigest); id != "" {
		c.Detail += " " + id
	}
	if ago := agoText(m.UpdatedAt, a.Now()); ago != "" {
		c.Detail += ", updated " + ago
	}
	allowed, denied := m.Allowed, m.DeniedHarnesses
	if m.LegacyAllowedMissing {
		var err error
		allowed, denied, err = a.legacyManagedPermission(ctx)
		if err != nil {
			c.Status = openshell.StatusFail
			c.Detail += ": this older sandbox service did not report authorization, and its policy explanation could not confirm it: " + sandboxapi.DisplayText(err.Error())
			c.Fix = &openshell.Fix{Summary: sandboxapi.AccessContact(m.RequestAccess)}
			return c
		}
	}
	if !allowed {
		c.Status = openshell.StatusFail
		if len(denied) > 0 {
			c.Detail += ": your organization doesn't allow sandboxes for " + strings.Join(sandboxapi.DisplayTexts(denied), ", ")
		} else {
			c.Detail += ": sandbox authorization could not be confirmed for your account"
		}
		c.Fix = &openshell.Fix{Summary: sandboxapi.AccessContact(m.RequestAccess)}
	} else if m.Provisional {
		c.Status = openshell.StatusWarn
		c.Detail += ": your directory couldn't be reached, so your organization's default applies for now"
		c.Fix = &openshell.Fix{Summary: "nothing to do on this computer; the policy updates when the directory answers. " +
			sandboxapi.AccessContact(m.RequestAccess)}
	}
	return c
}

// legacyDaemonHarness names, in a denial, the agent an older sandbox
// service judged for a doctor that named none.
const legacyDaemonHarness = "the agent your sandbox service is configured to run"

// legacyManagedPermission asks an older daemon's existing explain endpoint
// whether sandboxes may run. Its status did not carry that verdict, so
// absence must not mean a denial or an approval. For each harness this
// CLI's openshell.harnesses names it asks about that harness; with none,
// it asks once without a harness, which the daemon answers for the harness
// its own managed configuration runs (managedConnector in
// internal/gateway: the first of its harnesses, else Claude Code). The
// CLI's local setup defaults never stand in for the daemon's
// configuration. That answer cannot say which harness it judged, so a
// profile's allowed_harnesses list is the daemon's to apply at run time.
func (a *App) legacyManagedPermission(ctx context.Context) (bool, []string, error) {
	api, err := a.api()
	if err != nil {
		return false, nil, err
	}
	var names []string
	if a.Cfg != nil {
		names = a.Cfg.OpenShell.Harnesses
	}
	if len(names) == 0 {
		ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{})
		if err != nil {
			return false, nil, err
		}
		if ex == nil || ex.Managed == nil {
			return false, nil, fmt.Errorf("no managed policy for %s", legacyDaemonHarness)
		}
		if !ex.Managed.Allowed {
			return false, []string{legacyDaemonHarness}, nil
		}
		return true, nil, nil
	}
	specs, err := a.harnesses(names)
	if err != nil {
		return false, nil, err
	}
	var denied []string
	for _, spec := range specs {
		ex, err := api.Explain(ctx, sandboxapi.ExplainRequest{Harness: spec.Name})
		if err != nil {
			return false, nil, err
		}
		if ex == nil || ex.Managed == nil {
			return false, nil, fmt.Errorf("no managed policy for %s", spec.Name)
		}
		if !ex.Managed.Allowed || !managedHarnessListed(ex.Managed.AllowedHarnesses, spec.Name) {
			denied = append(denied, spec.Name)
		}
	}
	return len(denied) == 0, denied, nil
}

func managedHarnessListed(allowed []string, name string) bool {
	if len(allowed) == 0 {
		return true
	}
	name = config.NormalizeConnectorName(name)
	for _, h := range allowed {
		if config.NormalizeConnectorName(h) == name {
			return true
		}
	}
	return false
}

// managedRuntimeCheck is the doctor's row for the daemon's OpenShell on a
// managed computer: how it is installed and driven, and a pending restart.
func managedRuntimeCheck(m *sandboxapi.ManagedStatus) openshell.Check {
	c := openshell.Check{ID: CheckIDManagedRuntime, Title: "Sandbox runtime", Status: openshell.StatusPass}
	var parts []string
	if m.OpenShellVersion != "" {
		parts = append(parts, "OpenShell "+sandboxapi.DisplayText(m.OpenShellVersion))
	}
	if text := sandboxapi.DisplayText(openshell.DriverChoiceText(m.Driver, m.DriverReason)); text != "" {
		parts = append(parts, "driver "+text)
	}
	if m.InstallMode != "" {
		parts = append(parts, sandboxapi.DisplayText(m.InstallMode)+" install")
	}
	if m.GatewayPort > 0 {
		// The organization's port, not OpenShell's default (GAP-0215).
		parts = append(parts, fmt.Sprintf("gateway port %d", m.GatewayPort))
	}
	c.Detail = firstNonEmpty(strings.Join(parts, ", "), "managed by your organization")
	switch {
	case m.Unavailable == sandboxrelay.UnavailableSetupChanging:
		// The organization's switch of the setup is under way: it clears
		// by itself, and is nothing to ask IT about. A run refuses until
		// it clears, so doctor must not report ready (GAP-0528).
		c.Status = openshell.StatusFail
		c.Detail = m.Unavailable
		c.Fix = &openshell.Fix{Summary: "nothing to do on this computer; run the command again in a few minutes"}
	case m.Unavailable != "":
		c.Status = openshell.StatusFail
		c.Detail = sandboxapi.DisplayText(m.Unavailable)
		c.Fix = &openshell.Fix{Summary: sandboxapi.AccessContact(m.RequestAccess)}
	case m.PendingRestart:
		c.Status = openshell.StatusWarn
		c.Detail += "; an update waits until your sandboxes stop"
		c.Fix = &openshell.Fix{Summary: "stop your sandboxes (" + CommandName + " stop NAME); the next command applies the update"}
	}
	if m.RenderedConfigDrift {
		c.Detail += "; the organization's OpenShell gateway configuration changed outside DefenseClaw"
		if c.Status == openshell.StatusPass {
			c.Status = openshell.StatusFail
			c.Fix = &openshell.Fix{Summary: "ask IT to repair the managed OpenShell gateway configuration"}
		}
	}
	return c
}

// managedDriverCheck is the doctor's "Sandbox driver" row on a managed
// computer: the compute driver the caller's sandboxes get and why. The
// Linux docker fallback is a warning (the profile floors apply unchanged,
// only the MicroVM isolation is missing), with what the user can ask for;
// nil when the daemon names no driver.
func managedDriverCheck(m *sandboxapi.ManagedStatus) *openshell.Check {
	text := managedDriverText(m.Driver, m.DriverReason, m.DriverFallback)
	if text == "" {
		return nil
	}
	if m.PendingRestart || m.Unavailable == sandboxrelay.UnavailableSetupChanging {
		return &openshell.Check{ID: "managed-driver", Title: "Sandbox driver", Status: openshell.StatusWarn,
			Detail: text + "; the authorized sandbox setup update is waiting to finish",
			Fix:    &openshell.Fix{Summary: "stop your sandboxes (" + CommandName + " stop NAME), then retry; the next command applies the update"}}
	}
	c := openshell.Check{ID: "managed-driver", Title: "Sandbox driver", Status: openshell.StatusPass, Detail: text}
	if openshell.IsFallbackReason(m.DriverReason) {
		c.Status = openshell.StatusWarn
		c.Detail += "; your sandboxes run on docker with your organization's policy unchanged"
		c.Fix = &openshell.Fix{Summary: "MicroVM sandboxes need KVM for your account on this computer (/dev/kvm read-write, " +
			"virtualization on); nothing to do unless you need them. " + sandboxapi.AccessContact(m.RequestAccess)}
	}
	return &c
}

// managedAdminVMDriver finds the administrator's MicroVM driver with the
// check `enterprise verify` runs (openshell.AdminVMDriver); a seam for tests.
var managedAdminVMDriver = func(goos string) (found string, refused []string) {
	return openshell.AdminVMDriver(goos, func(p string) bool {
		return openshell.ExecutableVMDriver(p)
	}, func(p string) error { return managed.ValidateTrustedFilePath(p, "managed file") })
}

var managedRenderedVMDriver = func(goos, dir string) (string, string) {
	return openshell.RenderedAdminVMDriver(goos, dir, openshell.ExecutableVMDriver,
		func(p string) error { return managed.ValidateTrustedFilePath(p, "OpenShell MicroVM driver") })
}

var managedRenderedVMConfigTrust = managed.ValidateTrustedFilePath

// managedVMDriverGoarch is the CPU architecture the driver fix names; a seam
// for tests.
var managedVMDriverGoarch = runtime.GOARCH

// withAdminVMDriver checks, for the doctor's Sandbox driver row c, the
// administrator's openshell-driver-vm where the account's sandboxes need it
// (prerequisite install, the MicroVM driver), live and with the check the
// administrator's `enterprise verify` runs: the daemon's view of the driver
// is the lifecycle's last record, so a driver removed since read ready
// (GAP-0481). A missing or untrusted driver fails the row (warns on Linux
// with the docker fallback, which then runs the sandboxes), naming the path
// and the administrator's pinned-digest install. c is nil when the daemon
// named no driver.
func (a *App) withAdminVMDriver(c *openshell.Check, m *sandboxapi.ManagedStatus) *openshell.Check {
	if m.PendingRestart || m.Unavailable == sandboxrelay.UnavailableSetupChanging {
		return c
	}
	goos := a.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	wantsVM := m.Driver == config.EnterpriseOpenShellDriverVM || m.Driver == config.EnterpriseOpenShellDriverAuto
	if (goos != "linux" && goos != "darwin") || m.InstallMode != config.EnterpriseOpenShellInstallPrerequisite ||
		!wantsVM || openshell.IsFallbackReason(m.DriverReason) {
		return c
	}
	found, refused := managedAdminVMDriver(goos)
	if found != "" {
		return c
	}
	if c == nil {
		c = &openshell.Check{ID: "managed-driver", Title: "Sandbox driver", Detail: managedDriverText(m.Driver, m.DriverReason, m.DriverFallback)}
	}
	why := "the MicroVM driver openshell-driver-vm is not installed (looked in " + strings.Join(openshell.AdminVMDriverDirs(goos), ", ") + ")"
	if len(refused) > 0 {
		why = "the MicroVM driver openshell-driver-vm is installed only where an account other than root can change it: " + strings.Join(refused, "; ") +
			"; sandboxes do not use it"
	}
	if c.Detail != "" {
		why = c.Detail + "; but " + why
	}
	c.Detail = why
	c.Status = openshell.StatusFail
	if goos == "linux" && m.DriverFallback == config.EnterpriseOpenShellFallbackDocker {
		c.Status = openshell.StatusWarn
		c.Detail += ", so your sandboxes run on docker with your organization's policy unchanged"
	} else {
		c.Detail += ", so no sandbox can start for you on this computer"
	}
	fix := openshell.AdminVMDriverFix(goos, managedVMDriverGoarch)
	contact := sandboxapi.RequestAccessText(m.RequestAccess)
	if contact != sandboxapi.RequestAccessFallback {
		contact = "contact " + contact
	}
	c.Fix = &openshell.Fix{Summary: "nothing to do on your account; an administrator step (" + contact + "): " + fix.Summary,
		Command: fix.Command, Sudo: true}
	return c
}

// withRenderedVMDriver checks the path OpenShell will actually search. The
// administrator's shared search can find a later driver after the rendered
// driver_dir has gone stale; the gateway cannot use that later driver until
// enterprise ensure refreshes the render (GAP-0573).
func (a *App) withRenderedVMDriver(c *openshell.Check, m *sandboxapi.ManagedStatus, paths *openshell.RenderedPaths) *openshell.Check {
	if m.PendingRestart || m.Unavailable == sandboxrelay.UnavailableSetupChanging {
		return c
	}
	if c == nil || c.Status != openshell.StatusPass || m.InstallMode != config.EnterpriseOpenShellInstallPrerequisite ||
		(m.Driver != config.EnterpriseOpenShellDriverVM && m.Driver != config.EnterpriseOpenShellDriverAuto) || openshell.IsFallbackReason(m.DriverReason) {
		return c
	}
	goos := a.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	if goos != "linux" && goos != "darwin" {
		return c
	}
	problem := ""
	if paths == nil || paths.TOML == "" {
		problem = "the administrator's rendered gateway configuration is unavailable"
	} else if err := managedRenderedVMConfigTrust(paths.TOML, "OpenShell gateway configuration"); err != nil {
		problem = fmt.Sprintf("the administrator's rendered gateway configuration %s is not trusted: %v", paths.TOML, err)
	} else if data, err := os.ReadFile(paths.TOML); err != nil {
		problem = fmt.Sprintf("cannot read the administrator's rendered gateway configuration %s: %v", paths.TOML, err)
	} else if rendered, err := openshell.ParseRenderedGateway(data, nil); err != nil {
		problem = err.Error()
	} else if err := rendered.Validate(); err != nil {
		problem = err.Error()
	} else if rendered.ComputeDriver != openshell.DriverVM {
		problem = "the administrator's rendered gateway configuration does not select the MicroVM driver"
	} else {
		_, problem = managedRenderedVMDriver(goos, rendered.DriverDir)
	}
	if problem == "" {
		return c
	}
	c.Status = openshell.StatusFail
	c.Detail += "; but " + problem + ", so no MicroVM sandbox can start for you on this computer"
	c.Fix = &openshell.Fix{Summary: "nothing to do on your account; ask your administrator to run `enterprise " + openshell.EnterprisePlatformName(goos) + " ensure` so the rendered driver_dir names an installed, trusted openshell-driver-vm"}
	return c
}

// managedDockerCheck is the doctor's Docker row on a managed Mac. The
// MicroVM driver boots the agent images that DefenseClaw builds in the
// account's Docker, so if Docker does not answer for the account, every
// first run stops (GAP-0443).
func (a *App) managedDockerCheck(ctx context.Context, m *sandboxapi.ManagedStatus) openshell.Check {
	c := openshell.Check{ID: "managed-docker", Title: "Docker", Status: openshell.StatusPass}
	engine, err := a.DockerEngine(ctx)
	if err != nil {
		c.Status, c.Detail = openshell.StatusFail, "Docker does not answer for your account, and your agent's sandbox image is built in it"
		contact := sandboxapi.RequestAccessText(m.RequestAccess)
		if contact != sandboxapi.RequestAccessFallback {
			contact = "contact " + contact
		}
		c.Fix = &openshell.Fix{Summary: "start Docker Desktop and run this again; if you have no Docker, " + contact}
		return c
	}
	c.Detail = firstNonEmpty(engine, "running") + "; your agent images are built in it"
	if hint := shellDockerHostHint(os.LookupEnv); hint != "" {
		// This check ran with the shell's DOCKER_HOST, which the sandbox
		// daemon does not see (GAP-0613).
		c.Status = openshell.StatusWarn
		c.Detail += "; this check used your shell's DOCKER_HOST, which sandboxes do not use"
		c.Fix = &openshell.Fix{Summary: hint}
	}
	return c
}

// PolicyLine is one row of a rendered managed policy: its label and text.
type PolicyLine struct{ Label, Text string }

// ManagedPolicyLines renders a managed policy as `policy explain` does, for
// the administrator views that show the same rows for one registration.
func ManagedPolicyLines(m *sandboxapi.ManagedExplain, now time.Time) []PolicyLine {
	rows := managedExplainRows(m, now)
	out := make([]PolicyLine, len(rows))
	for i, r := range rows {
		out[i] = PolicyLine{Label: r.label, Text: r.text}
	}
	return out
}
