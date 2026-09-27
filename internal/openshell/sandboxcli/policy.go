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
	"sort"
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
	row := func(k, v string) { a.line(fmt.Sprintf("%-14s%s", k, v)) }
	row("Pack", ex.Pack+" ("+ex.PackSource+") "+ex.PackDigest)
	row("Profile", ex.Profile)
	row("Network", ex.NetworkMode)
	row("Approvals", ex.Approvals)
	row("Organization", adminText(ex.Admin))
	for _, key := range []string{"yolo", "harness.allowed", "workdir.mode", "egress.feeds", "egress.block", "egress.admin_block",
		"egress.allow", "egress.allow_only", "egress.ports", "mcp.import", "hooks.fail_mode"} {
		if v := settingValue(ex.Settings, key); v != "" {
			row(key, v)
		}
	}
	for _, v := range ex.Violations {
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	a.note("where each value comes from: " + CommandName + " policy explain")
	return nil
}

func adminText(s sandboxapi.AdminStatus) string {
	if !s.Configured {
		return "no openshell.admin constraints"
	}
	t := s.Authority
	if s.Detail != "" {
		t += ": " + s.Detail
	}
	return t
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
	a.line(a.bold("pack "+ex.Pack) + " " + ex.PackDigest + " from " + ex.PackSource)
	a.line("organization: " + adminText(ex.Admin))
	rows := make([][]string, 0, len(ex.Settings))
	shortened := false
	for _, s := range ex.Settings {
		val, cut := shortList(s.Value, explainValueWidth)
		shortened = shortened || cut
		if s.Requested != "" {
			req, cut := shortList(s.Requested, explainRequestedWidth)
			shortened = shortened || cut
			val += " (asked for " + req + ")"
		}
		rows = append(rows, []string{s.Key, val, s.Source, s.Origin})
	}
	a.table([]string{"SETTING", "VALUE", "SOURCE", "ORIGIN"}, rows)
	if shortened {
		a.note("long values are shortened; " + CommandName + " policy explain -o json prints them in full")
	}
	for _, v := range ex.Violations {
		a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
	}
	return nil
}

// The VALUE column of `policy explain` is capped so the table fits a
// terminal: the masks and egress lists would otherwise pad every row to
// a thousand columns.
const (
	explainValueWidth     = 48
	explainRequestedWidth = 24
)

// shortList fits v into width runes. A ", "-separated list keeps the
// entries that fit and says how many it left out; any other value is cut.
// It reports whether v was shortened.
func shortList(v string, width int) (string, bool) {
	if utf8.RuneCountInString(v) <= width {
		return v, false
	}
	items := strings.Split(v, ", ")
	if len(items) < 2 {
		return truncate(v, width), true
	}
	var kept []string
	used := 0
	for i, item := range items {
		more := fmt.Sprintf(", … (+%d more)", len(items)-i-1)
		n := utf8.RuneCountInString(item)
		if len(kept) > 0 {
			n += 2
		}
		if len(kept) > 0 && used+n+utf8.RuneCountInString(more) > width {
			break
		}
		kept = append(kept, item)
		used += n
	}
	if len(kept) == 1 && utf8.RuneCountInString(kept[0]) > width {
		kept[0] = truncate(kept[0], width)
	}
	return strings.Join(kept, ", ") + fmt.Sprintf(", … (+%d more)", len(items)-len(kept)), true
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
	for _, e := range list {
		digest := e.Digest
		if e.Err != nil {
			digest = a.style("invalid: "+truncate(e.Err.Error(), 80), ansiRed)
		}
		kind := "custom"
		if e.Builtin {
			kind = "built-in"
		}
		rows = append(rows, []string{e.Name, kind, e.Profile, digest})
	}
	a.table([]string{"NAME", "KIND", "PROFILE", "DIGEST"}, rows)
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
