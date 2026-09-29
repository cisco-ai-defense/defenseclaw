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
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// PolicyOptions select the posture `policy show|explain` resolves: one
// sandbox's, or the one a `run` with these flags would get.
type PolicyOptions struct {
	Sandbox string
	Harness string
	Pack    string
	Profile string
	Copy    bool
	Safe    bool
	Unmask  []string
	Output  OutputFormat
}

func (a *App) explain(ctx context.Context, o PolicyOptions) (*sandboxapi.Explain, error) {
	api, err := a.api()
	if err != nil {
		return nil, err
	}
	req := sandboxapi.ExplainRequest{Sandbox: o.Sandbox, Pack: o.Pack, Profile: o.Profile, Copy: o.Copy, Safe: o.Safe, Unmask: o.Unmask}
	if o.Harness != "" {
		spec, err := ResolveHarness(o.Harness)
		if err != nil {
			return nil, err
		}
		req.Harness = spec.Name
	}
	if o.Sandbox == "" {
		if p, err := a.project(); err == nil {
			req.Project = p
		}
	}
	ex, err := api.Explain(ctx, req)
	if err != nil {
		return nil, apiError(err)
	}
	return ex, nil
}

// PolicyShow prints the effective sandbox policy.
func (a *App) PolicyShow(ctx context.Context, o PolicyOptions) error {
	ex, err := a.explain(ctx, o)
	if err != nil {
		return err
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, ex)
	}
	rows := [][2]string{
		{"Pack", ex.Pack + " (" + ex.PackSource + ") " + ex.PackDigest},
		{"Profile", ex.Profile}, {"Network", ex.NetworkMode}, {"Approvals", ex.Approvals},
		{"Organization", adminText(ex.Admin)},
	}
	for _, key := range []string{"yolo", "harness.allowed", "workdir.mode", "egress.feeds", "egress.block", "egress.admin_block",
		"egress.allow", "egress.allow_only", "egress.ports", "mcp.import", "hooks.fail_mode"} {
		if v := settingValue(ex.Settings, key); v != "" {
			shown, note := settingShown(ex, key, v)
			rows = append(rows, [2]string{key, withNote(listSummary(shown, 8), note)})
		}
	}
	// The key column fits the longest key: values never run into labels.
	width := 0
	for _, r := range rows {
		width = max(width, len(r[0]))
	}
	for _, r := range rows {
		a.line(fmt.Sprintf("%-*s  %s", width, r[0], r[1]))
	}
	for _, v := range ex.Violations {
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	a.note("where each value comes from: " + CommandName + " policy explain")
	return nil
}

// settingShown is a setting's value as the policy applies it, and a note
// on what it leaves out: allow entries outside the organization's
// allow-only list reach nothing, so they are not listed as allowed.
func settingShown(ex *sandboxapi.Explain, key, value string) (string, string) {
	if key != "egress.allow" {
		return value, ""
	}
	only := splitList(settingValue(ex.Settings, "egress.allow_only"))
	if len(only) == 0 {
		return value, ""
	}
	var inside, outside []string
	for _, entry := range splitList(value) {
		if coveredBy(only, entry) {
			inside = append(inside, entry)
		} else {
			outside = append(outside, entry)
		}
	}
	shown := "(none)"
	if len(inside) > 0 {
		shown = strings.Join(inside, ", ")
	}
	if len(outside) == 0 {
		return shown, ""
	}
	return shown, plural(int64(len(outside)), "entry", "entries") + " outside the organization's allow-only list: not reachable"
}

func withNote(value, note string) string {
	if note == "" {
		return value
	}
	return value + " (" + note + ")"
}

// listFit fits a list value into width characters: the entries that fit,
// then how many more there are.
func listFit(v string, width int) string {
	list := splitList(v)
	if len(list) < 2 || utf8.RuneCountInString(v) <= width {
		return truncate(v, width)
	}
	more := func(n int) string { return fmt.Sprintf(" (+%d more; -o json lists all)", n) }
	best := ""
	for i := range list {
		s := strings.Join(list[:i+1], ", ")
		if rest := len(list) - i - 1; rest > 0 {
			s += more(rest)
		}
		if utf8.RuneCountInString(s) > width {
			break
		}
		best = s
	}
	if best == "" {
		suffix := more(len(list) - 1)
		best = truncate(list[0], max(width-utf8.RuneCountInString(suffix), 8)) + suffix
	}
	return best
}

// splitList parses a setting's list value ("a, b", or "(none)").
func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "(") {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// listSummary shortens a long list value to its first n entries.
func listSummary(v string, n int) string {
	list := splitList(v)
	if len(list) <= n || strings.Contains(v, " (") {
		return v
	}
	return strings.Join(list[:n], ", ") + fmt.Sprintf(" (+%d more; -o json lists all)", len(list)-n)
}

// coveredBy reports whether every destination the egress pattern entry
// matches is matched by one of globs.
func coveredBy(globs []string, entry string) bool {
	inner, err := config.ParseOpenShellEgressPattern(entry)
	if err != nil {
		return false
	}
	for _, g := range globs {
		if p, err := config.ParseOpenShellEgressPattern(g); err == nil && p.Covers(inner) {
			return true
		}
	}
	return false
}

func adminText(s sandboxapi.AdminStatus) string {
	if !s.Configured {
		return "no openshell.admin constraints"
	}
	// The detail names the authority itself ("openshell.admin is
	// enforced but advisory: …"): once is enough.
	switch {
	case s.Detail == "":
		return s.Authority
	case s.Authority == "" || strings.Contains(s.Detail, s.Authority):
		return s.Detail
	}
	return s.Authority + ": " + s.Detail
}

// PolicyExplain prints every resolved setting with its provenance.
func (a *App) PolicyExplain(ctx context.Context, o PolicyOptions) error {
	ex, err := a.explain(ctx, o)
	if err != nil {
		return err
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, ex)
	}
	head := "pack " + ex.Pack + " " + ex.PackDigest + " from "
	a.line(a.bold("pack "+ex.Pack) + " " + ex.PackDigest + " from " +
		truncate(ex.PackSource, max(explainWidth-2-utf8.RuneCountInString(head), 24)))
	a.line(truncate("organization: "+adminText(ex.Admin), explainWidth-2))
	// Every line fits explainWidth columns: the key, source and origin
	// columns take what they need (the origin cut to explainOriginWidth),
	// and long values (the masks, the blocklist) get the rest, cut to the
	// entries that fit; -o json has them whole.
	keyW, srcW, originW := len("SETTING"), len("SOURCE"), len("ORIGIN")
	for _, s := range ex.Settings {
		keyW = max(keyW, utf8.RuneCountInString(s.Key))
		srcW = max(srcW, utf8.RuneCountInString(s.Source))
		originW = max(originW, min(utf8.RuneCountInString(s.Origin), explainOriginWidth))
	}
	valueW := min(max(explainWidth-keyW-srcW-originW-3*2, explainMinValueWidth), explainValueWidth)
	rows := make([][]string, 0, len(ex.Settings))
	var notes []string
	for _, s := range ex.Settings {
		shown, note := settingShown(ex, s.Key, s.Value)
		if note != "" {
			notes = append(notes, s.Key+": "+note)
		}
		asked := ""
		if s.Requested != "" {
			// A value the user chose and the policy replaced has a
			// violation; one the user never chose (a pack default, no
			// limit) was replaced, not asked for.
			verb := "instead of "
			if slices.ContainsFunc(ex.Violations, func(v sandboxapi.Violation) bool { return v.Key == s.Key }) {
				verb = "asked for "
			}
			asked = " (" + verb + listFit(strings.Trim(s.Requested, "()"), min(explainRequestedWidth, valueW/3)) + ")"
		}
		val := listFit(shown, valueW-utf8.RuneCountInString(asked)) + asked
		if utf8.RuneCountInString(val) > valueW {
			val = truncate(val, valueW)
		}
		rows = append(rows, []string{s.Key, val, s.Source, truncate(s.Origin, explainOriginWidth)})
	}
	a.table([]string{"SETTING", "VALUE", "SOURCE", "ORIGIN"}, rows)
	for _, n := range notes {
		a.note(n)
	}
	if lines := a.adminConstraints(); len(lines) > 0 {
		a.println()
		a.line(a.bold("Organization constraints") + " (openshell.admin)")
		for _, l := range lines {
			a.line("  " + l)
		}
	}
	for _, v := range ex.Violations {
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	return nil
}

// `policy explain` keeps every line within explainWidth columns, so its
// table fits a terminal: the masks and egress lists would otherwise pad
// every row to a thousand columns. The VALUE column gets what the other
// columns leave, at most explainValueWidth.
const (
	explainWidth          = 120
	explainValueWidth     = 72
	explainMinValueWidth  = 32
	explainOriginWidth    = 40
	explainRequestedWidth = 24
	// explainConstraintWidth fits a constraint's value after the
	// indentation and the 22-column key of adminConstraints.
	explainConstraintWidth = explainWidth - 4 - 23
)

// adminConstraints lists every openshell.admin key the configuration sets,
// whatever the pack: a required pack does not hide the others.
func (a *App) adminConstraints() []string {
	if a.Cfg == nil {
		return nil
	}
	ad := a.Cfg.OpenShell.Admin
	var out []string
	add := func(key, value string) {
		if value != "" {
			out = append(out, fmt.Sprintf("%-22s %s", key, value))
		}
	}
	boolean := func(key string, v *bool) {
		if v != nil {
			add(key, strconv.FormatBool(*v))
		}
	}
	list := func(key string, v []string) {
		if len(v) > 0 {
			add(key, listFit(strings.Join(v, ", "), explainConstraintWidth))
		}
	}
	add("required_pack", ad.RequiredPack)
	add("required_pack_digest", ad.RequiredPackDigest)
	add("min_profile", ad.MinProfile)
	boolean("allow_yolo", ad.AllowYolo)
	boolean("allow_mount", ad.AllowMount)
	boolean("allow_host_ports", ad.AllowHostPorts)
	boolean("allow_unblock", ad.AllowUnblock)
	boolean("allow_learn_mode", ad.AllowLearnMode)
	list("allowed_harnesses", ad.AllowedHarnesses)
	list("egress_block", ad.EgressBlock)
	list("egress_allow_only", ad.EgressAllowOnly)
	list("require_copy_for", ad.RequireCopyFor)
	if r := ad.MaxResources; r.CPU != "" || r.Memory != "" {
		add("max_resources", strings.TrimSpace(firstNonEmpty(r.CPU, "-")+" CPU, "+firstNonEmpty(r.Memory, "-")+" memory"))
	}
	list("locked", ad.Locked)
	return out
}

// SuggestOptions are the `policy suggest` flags.
type SuggestOptions struct {
	Sandbox string
	Output  OutputFormat
}

// PolicySuggest summarizes the destinations sandboxes reached into an
// allowlist for the balanced profile.
func (a *App) PolicySuggest(ctx context.Context, o SuggestOptions) error {
	api, err := a.api()
	if err != nil {
		return err
	}
	counts := map[string]int{}
	blocked := map[string]int{}
	err = api.Activity(ctx, sandboxapi.ActivityQuery{Sandbox: o.Sandbox}, func(ev sandboxapi.ActivityEvent) error {
		switch ev.Kind {
		case sandboxapi.ActivityEgressAllowed:
			if ev.Host != "" {
				counts[strings.ToLower(ev.Host)]++
			}
		case sandboxapi.ActivityEgressBlocked:
			if ev.Host != "" {
				blocked[strings.ToLower(ev.Host)]++
			}
		}
		return nil
	})
	if err != nil {
		return apiError(err)
	}
	hosts := make([]string, 0, len(counts))
	for h := range counts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if o.Output == OutputJSON {
		type entry struct {
			Host  string `json:"host"`
			Count int    `json:"count"`
		}
		out := struct {
			Allow   []entry  `json:"allow"`
			Blocked []string `json:"blocked,omitempty"`
		}{Allow: []entry{}}
		for _, h := range hosts {
			out.Allow = append(out.Allow, entry{h, counts[h]})
		}
		for h := range blocked {
			out.Blocked = append(out.Blocked, h)
		}
		sort.Strings(out.Blocked)
		return writeJSON(a.IO.Out, out)
	}
	if len(hosts) == 0 {
		a.note("no allowed destinations in the activity buffer yet; run a session first")
		return nil
	}
	a.println("# Destinations your sandboxes reached (" + CommandName + " policy suggest).")
	a.println("# Add them to config.yaml, then switch to the default-deny profile with --profile balanced.")
	a.println("openshell:")
	a.println("  egress:")
	a.println("    allow:")
	for _, h := range hosts {
		a.printf("      - %s  # %d\n", h, counts[h])
	}
	if len(blocked) > 0 {
		var list []string
		for h := range blocked {
			list = append(list, h)
		}
		sort.Strings(list)
		a.println("# Blocked (not suggested): " + strings.Join(list, ", "))
	}
	a.println("# Or one at a time: " + CommandName + " policy allow HOST")
	return nil
}

// PolicyEdit adds hosts to openshell.egress.allow or openshell.egress.block.
func (a *App) PolicyEdit(ctx context.Context, list string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("name at least one host")
	}
	key := "openshell.egress." + list
	var current []string
	if a.Cfg != nil {
		switch list {
		case "allow":
			current = a.Cfg.OpenShell.Egress.Allow
		case "block":
			current = a.Cfg.OpenShell.Egress.Block
		default:
			return fmt.Errorf("unknown egress list %q", list)
		}
	}
	next := append([]string(nil), current...)
	var added []string
	for _, h := range hosts {
		h = config.NormalizeOpenShellEgressPattern(h)
		if err := config.ValidateOpenShellEgressPattern(h); err != nil {
			return fmt.Errorf("%s: %w", h, err)
		}
		if list == "allow" && packs.IsBroadAllowGlob(h) {
			return fmt.Errorf("%s allows too much; name hosts or a subdomain wildcard like *.example.com", h)
		}
		if list == "allow" {
			if err := a.adminAllows(h); err != nil {
				return err
			}
		}
		dup := false
		for _, have := range next {
			if strings.EqualFold(have, h) {
				dup = true
			}
		}
		if !dup {
			next = append(next, h)
			added = append(added, h)
		}
	}
	if len(added) == 0 {
		a.ok("already in " + key)
		return nil
	}
	if err := a.patchConfig(map[string]any{key: next}); err != nil {
		return err
	}
	a.ok("added " + strings.Join(added, ", ") + " to " + key)
	if list == "allow" {
		a.note("allow entries matter in the balanced and strict profiles; open allows everything not blocked")
	}
	a.note("the daemon applies it to running sandboxes within a few seconds")
	return nil
}

// adminAllows refuses an allow entry the organization's policy would make
// dead: allow entries are ignored under allow_unblock: false, and nothing
// on egress_block or outside egress_allow_only is reachable whatever the
// entry says.
func (a *App) adminAllows(entry string) error {
	if a.Cfg == nil {
		return nil
	}
	ad := a.Cfg.OpenShell.Admin
	refuse := func(constraint, why string) error {
		v := &sandboxapi.Violation{Key: "egress.allow", Attempted: entry, Constraint: constraint, Admin: true, Detail: why}
		return errors.New(violationMessage(v, "", why, true))
	}
	if ad.AllowUnblock != nil && !*ad.AllowUnblock {
		return refuse("openshell.admin.allow_unblock", "your own allow entries are ignored; ask your administrator to add destinations")
	}
	for _, b := range ad.EgressBlock {
		// A host name there blocks its subdomains too.
		if coveredBy(config.OpenShellAdminBlockPatterns([]string{b}), entry) {
			return refuse("openshell.admin.egress_block", entry+" is on your organization's blocklist ("+b+")")
		}
	}
	if len(ad.EgressAllowOnly) > 0 && !coveredBy(ad.EgressAllowOnly, entry) {
		return refuse("openshell.admin.egress_allow_only", entry+" is not on your organization's list of allowed destinations")
	}
	return nil
}

// patchConfig writes keys to config.yaml, keeping the file valid.
func (a *App) patchConfig(updates map[string]any) error {
	a.defaults()
	if a.Cfg != nil && managed.IsManagedEnterprise(a.Cfg.DeploymentMode) {
		return errors.New(sandboxapi.AdminMessage + ": the configuration is administrator-owned")
	}
	path := a.ConfigPath
	before, err := os.ReadFile(path)
	existed := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := config.PatchYAMLFile(path, updates); err != nil {
		return err
	}
	if _, err := config.LoadRuntimeV8File(path); err != nil {
		if existed {
			_ = config.WriteFileAtomic(path, before, mode)
		} else {
			_ = os.Remove(path)
		}
		return fmt.Errorf("the change would make %s invalid (it was not written): %w", path, err)
	}
	return nil
}

// PackOptions are the `pack` flags.
type PackOptions struct {
	Output OutputFormat
}

func (a *App) packDir() string {
	if a.Cfg != nil {
		return a.Cfg.OpenShell.PackDir
	}
	return ""
}

// PackList lists the built-in and custom packs with their digests
// (openshell.admin.required_pack_digest pins one).
func (a *App) PackList(o PackOptions) error {
	a.defaults()
	list, err := packs.List(a.packDir())
	if err != nil {
		return err
	}
	if o.Output == OutputJSON {
		type item struct {
			packs.Entry
			Error string `json:"error,omitempty"`
		}
		out := make([]item, 0, len(list))
		for _, e := range list {
			it := item{Entry: e}
			if e.Err != nil {
				it.Error = e.Err.Error()
			}
			out = append(out, it)
		}
		return writeJSON(a.IO.Out, map[string]any{"packs": out})
	}
	rows := make([][]string, 0, len(list))
	var invalid []packs.Entry
	for _, e := range list {
		digest := e.Digest
		if e.Err != nil {
			// The reason goes below the table, whole.
			digest = a.style("invalid (see below)", ansiRed)
			invalid = append(invalid, e)
		}
		kind := "custom"
		if e.Builtin {
			kind = "built-in"
		}
		rows = append(rows, []string{e.Name, kind, e.Profile, digest})
	}
	a.table([]string{"NAME", "KIND", "PROFILE", "DIGEST"}, rows)
	for _, e := range invalid {
		a.bad(e.Name + ": " + e.Err.Error())
	}
	return nil
}

// PackShow prints one pack and its digest.
func (a *App) PackShow(ref string, o PackOptions) error {
	a.defaults()
	p, err := packs.Load(ref, a.packDir())
	if err != nil {
		return err
	}
	if o.Output == OutputJSON {
		return writeJSON(a.IO.Out, p)
	}
	data, err := p.Marshal()
	if err != nil {
		return err
	}
	a.println("# pack " + p.Name + " (" + p.Source + ")")
	a.println("# digest " + p.Digest + "  (pin it with openshell.admin.required_pack_digest)")
	_, err = a.IO.Out.Write(data)
	return err
}

// PackValidate strictly loads a pack file.
func (a *App) PackValidate(path string) error {
	a.defaults()
	p, err := packs.Validate(path)
	if err != nil {
		return err
	}
	a.ok("valid pack " + p.Name + " (profile " + p.Profile() + ") " + p.Digest)
	return nil
}
