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
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// SuggestOptions are the `policy suggest` flags.
type SuggestOptions struct {
	Sandbox string
	Output  OutputFormat
	// PackOut writes the suggested pack to this file (never over one).
	PackOut string
	// Diff prints what the suggested pack changes against the effective
	// policy (the sandbox's, or a run's in this folder).
	Diff bool
}

// suggestBase is the pack a recorded pack extends: the default-deny web
// with DefenseClaw's curated developer allowlist.
const suggestBase = "balanced"

// maxSuggestedHosts is the most allow entries a pack holds.
const maxSuggestedHosts = 1024

// suggestedHost is one destination of a suggestion.
type suggestedHost struct {
	Host      string   `json:"host"`
	Requests  int64    `json:"requests,omitempty"`
	Refused   int64    `json:"refused,omitempty"`
	Binaries  []string `json:"binaries,omitempty"`
	Sandboxes []string `json:"sandboxes"`
	// Why says why a host is not on the allow list.
	Why string `json:"why,omitempty"`
	// kind and label are the destination's kind and provider or category.
	kind, label string
}

// suggestion is what `policy suggest` recorded: the hosts to allow, the
// ones the base pack's curated list covers, and the ones left out (each with
// why: only ever refused, shadow AI, the blocklist feed, the sandbox's own
// model provider, not a host name the allow list takes).
type suggestion struct {
	Sandboxes []string        `json:"sandboxes"`
	Allow     []suggestedHost `json:"allow"`
	Curated   []suggestedHost `json:"curated,omitempty"`
	Blocked   []suggestedHost `json:"blocked,omitempty"`
	Excluded  []suggestedHost `json:"excluded,omitempty"`
	// Pack is the suggested pack file; PackName its name.
	PackName string          `json:"pack_name"`
	Pack     string          `json:"pack"`
	Diff     *suggestionDiff `json:"diff,omitempty"`
	Wrote    string          `json:"wrote,omitempty"`
	byHost   map[string]*suggestedHost
	ports    map[string][]int
	order    []string
}

// suggestionDiff is what the suggested pack changes against the effective
// policy: the settings that differ, and the destinations reached that it
// would block.
type suggestionDiff struct {
	Against  string                      `json:"against"`
	Settings []settingChange             `json:"settings"`
	Blocked  []sandboxapi.PolicyDecision `json:"newly_blocked,omitempty"`
}

type settingChange struct {
	Key  string `json:"key"`
	From string `json:"from"`
	To   string `json:"to"`
}

// PolicySuggest records then locks: it reads what sandboxes reached (the
// kept destinations views, which survive daemon restarts and stops), and
// suggests a pack that extends balanced with every host they reached that
// balanced's curated list does not cover. Hosts only ever refused, shadow
// AI, hosts on the blocklist feed and the sandbox's own model provider are
// listed apart, not suggested. --pack-out writes the pack (checked as `pack
// validate` would), --diff says what it changes against the effective
// policy. Nothing is applied.
func (a *App) PolicySuggest(ctx context.Context, o SuggestOptions) error {
	a.defaults()
	api, err := a.api()
	if err != nil {
		return err
	}
	s, err := a.recordDestinations(ctx, api, o.Sandbox)
	if err != nil {
		return err
	}
	if o.PackOut != "" {
		if _, err := os.Lstat(o.PackOut); err == nil {
			return fmt.Errorf("%s exists; the suggestion never replaces a file, so remove it or name another", o.PackOut)
		}
	}
	s.PackName = suggestPackName(o.PackOut, o.Sandbox)
	s.Pack = s.render(a.Now().Format("2006-01-02"), o.Sandbox)
	// The pack must load as `pack validate` would load it.
	if _, err := packs.ParseIn([]byte(s.Pack), "suggested pack "+s.PackName, a.packDir()); err != nil {
		return fmt.Errorf("the suggested pack does not validate (please report it): %w", err)
	}
	if o.Diff {
		if s.Diff, err = a.suggestionDiff(ctx, api, o.Sandbox, s); err != nil {
			return err
		}
	}
	if o.PackOut != "" {
		if err := writeNewFile(o.PackOut, []byte(s.Pack)); err != nil {
			return err
		}
		if _, err := packs.Validate(o.PackOut, a.packDir()); err != nil {
			_ = os.Remove(o.PackOut)
			return fmt.Errorf("the written pack does not validate: %w", err)
		}
		s.Wrote = o.PackOut
	}
	switch {
	case o.Output == OutputJSON:
		return writeJSON(a.IO.Out, s)
	case o.PackOut != "":
		a.ok(fmt.Sprintf("wrote %s: pack %s, extends %s, %s to allow", o.PackOut, s.PackName, suggestBase,
			plural(int64(len(s.Allow)), "host", "hosts")))
		a.note("review it, then lock a project to it: " + CommandName + " run --pack " + o.PackOut +
			" (or put it at <openshell.pack_dir>/" + s.PackName + "/" + packs.PackFileName + " and use --pack " + s.PackName + ")")
	case !o.Diff:
		_, err := fmt.Fprint(a.IO.Out, s.Pack)
		return err
	}
	if s.Diff != nil {
		a.printSuggestionDiff(s.Diff, s.PackName)
	}
	return nil
}

// recordDestinations reads the destinations views of one sandbox, or of
// every sandbox, and sorts their hosts.
func (a *App) recordDestinations(ctx context.Context, api API, sandbox string) (*suggestion, error) {
	names := []string{sandbox}
	if sandbox == "" {
		list, err := api.List(ctx)
		if err != nil {
			return nil, apiError(err)
		}
		names = names[:0]
		for _, sb := range list {
			names = append(names, sb.Name)
		}
		sort.Strings(names)
	}
	s := &suggestion{Sandboxes: []string{}, Allow: []suggestedHost{}, byHost: map[string]*suggestedHost{}, ports: map[string][]int{}}
	for _, name := range names {
		d, err := api.Destinations(ctx, name)
		if sandbox == "" && sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
			continue // deleted since the list
		}
		if err != nil {
			return nil, apiError(err)
		}
		s.Sandboxes = append(s.Sandboxes, name)
		for _, r := range d.Destinations {
			s.add(name, r)
		}
	}
	if len(s.byHost) == 0 {
		what := "no sandbox has reached a destination yet"
		if sandbox != "" {
			what = "sandbox " + sandbox + " has reached no destination yet"
		}
		return nil, errors.New(what + "; run a session first, then suggest a pack from what it reached")
	}
	balanced, err := packs.Builtin(suggestBase)
	if err != nil {
		return nil, err
	}
	feed, err := egress.NewDecider(egress.DeciderOptions{Mode: egress.ModeOpen})
	if err != nil {
		return nil, err
	}
	for _, host := range s.order {
		h := s.byHost[host]
		switch {
		case h.kind == sandboxapi.DestinationModelProvider:
			h.Why = "the sandbox's model or credential provider opens it directly to its own programs"
			s.Excluded = append(s.Excluded, *h)
		case sandboxapi.ShadowAIKind(h.kind):
			h.Why = "shadow AI (" + firstNonEmpty(h.label, "an AI API") + "): an AI service the harness does not use; add it yourself if you use it"
			s.Excluded = append(s.Excluded, *h)
		case h.Requests == 0:
			h.Why = "only ever refused" + suffixIf(h.label != "" && h.label != sandboxapi.DestinationBlocked, " ("+h.label+")")
			s.Blocked = append(s.Blocked, *h)
		case host == packs.OpenShellHostAlias:
			h.Why = "this machine, reached through a consented host port, not the egress proxy"
			s.Excluded = append(s.Excluded, *h)
		case config.ValidateOpenShellEgressPattern(host) != nil || packs.IsBroadAllowGlob(host):
			h.Why = "not a host name an allow list takes"
			s.Excluded = append(s.Excluded, *h)
		case feedBlocks(feed, host):
			h.Why = "on DefenseClaw's blocklist feed: an allow entry would exempt it; unblock it per sandbox instead"
			s.Excluded = append(s.Excluded, *h)
		case packs.MatchAnyHost(balanced.Egress.Allow, host):
			s.Curated = append(s.Curated, *h)
		default:
			s.Allow = append(s.Allow, *h)
		}
	}
	if len(s.Allow) > maxSuggestedHosts {
		s.Allow = s.Allow[:maxSuggestedHosts]
	}
	return s, nil
}

// add merges one destination row of a sandbox.
func (s *suggestion) add(sandbox string, r sandboxapi.DestinationRow) {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(r.Host), "."))
	if host == "" {
		return
	}
	h := s.byHost[host]
	if h == nil {
		h = &suggestedHost{Host: host, kind: r.Kind}
		s.byHost[host] = h
		s.order = append(s.order, host)
		sort.Strings(s.order)
	}
	h.Requests += r.Connections + r.Tunnels
	h.Refused += r.Refused + r.Blocked
	if !slices.Contains(h.Sandboxes, sandbox) {
		h.Sandboxes = append(h.Sandboxes, sandbox)
	}
	for _, b := range r.Binaries {
		if b = commentText(b); b != "" && !slices.Contains(h.Binaries, b) && len(h.Binaries) < 4 {
			h.Binaries = append(h.Binaries, b)
		}
	}
	// The AI kinds win over plain ones: a host one sandbox reached as its
	// model provider and another as shadow AI is not suggested.
	if kindRank(r.Kind) > kindRank(h.kind) {
		h.kind = r.Kind
	}
	if label := firstNonEmpty(r.Provider, r.Category); label != "" {
		h.label = commentText(label)
	}
	for _, p := range r.Ports {
		if !slices.Contains(s.ports[host], p) {
			s.ports[host] = append(s.ports[host], p)
		}
	}
}

func kindRank(kind string) int {
	switch {
	case kind == sandboxapi.DestinationModelProvider:
		return 3
	case sandboxapi.ShadowAIKind(kind):
		return 2
	case kind == sandboxapi.DestinationHarnessVendor:
		return 1
	}
	return 0
}

// feedBlocks reports whether DefenseClaw's blocklist feed refuses host.
func feedBlocks(d *egress.Decider, host string) bool {
	dec := d.DecideHost(egress.Principal{BindingID: "sandbox-policy-suggest"}, host)
	return !dec.Allowed && dec.Source == egress.SourceFeed
}

func suffixIf(ok bool, s string) string {
	if ok {
		return s
	}
	return ""
}

// commentText makes agent-controlled text (binary paths, provider labels)
// safe in a YAML comment: one line of printable characters, bounded.
func commentText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u2028' || r == '\u2029' {
			return '?'
		}
		return r
	}, strings.TrimSpace(s))
	return truncate(s, 120)
}

var packNameUnsafe = regexp.MustCompile(`[^a-z0-9-]+`)

// suggestPackName names the suggested pack after the file it goes to
// (<name>/pack.yaml or <name>.yaml), else after the sandbox.
func suggestPackName(out, sandbox string) string {
	base := strings.TrimSuffix(filepath.Base(out), filepath.Ext(out))
	switch {
	case out == "" && sandbox != "":
		base = sandbox + "-recorded"
	case out == "":
		base = "recorded"
	case filepath.Base(out) == packs.PackFileName:
		base = filepath.Base(filepath.Dir(out))
	}
	name := strings.Trim(packNameUnsafe.ReplaceAllString(strings.ToLower(base), "-"), "-")
	if len(name) > 54 {
		name = strings.Trim(name[:54], "-")
	}
	switch {
	case name == "":
		name = "recorded"
	case packs.IsBuiltin(name):
		name += "-recorded"
	}
	return name
}

// render writes the suggested pack: balanced plus the hosts to allow, with
// what reached each one as a comment, and the hosts left out as comments.
func (s *suggestion) render(day, sandbox string) string {
	var b strings.Builder
	from := "your sandboxes (" + strings.Join(s.Sandboxes, ", ") + ")"
	if sandbox != "" {
		from = "sandbox " + sandbox
	}
	fmt.Fprintf(&b, "# Recorded by `%s policy suggest` on %s from what %s reached.\n", CommandName, day, from)
	b.WriteString("# Review every host before you lock a project to this pack; nothing is applied until you\n")
	fmt.Fprintf(&b, "# run with it: %s run --pack <this file>, or put it at <openshell.pack_dir>/%s/%s.\n",
		CommandName, s.PackName, packs.PackFileName)
	b.WriteString("version: 1\n")
	fmt.Fprintf(&b, "name: %s\n", s.PackName)
	fmt.Fprintf(&b, "description: %s\n", strconv.Quote(truncate("The "+suggestBase+" pack plus the destinations "+from+" reached, recorded "+day, 1000)))
	fmt.Fprintf(&b, "extends: %s\n", suggestBase)
	b.WriteString("egress:\n")
	if len(s.Allow) == 0 {
		b.WriteString("  allow: []\n")
	} else {
		b.WriteString("  allow:\n")
		for _, h := range s.Allow {
			fmt.Fprintf(&b, "    - %s # %s\n", h.Host, hostComment(h))
		}
	}
	if len(s.Curated) > 0 {
		fmt.Fprintf(&b, "# Covered by the %s pack's curated allowlist: %s\n", suggestBase, joinHosts(s.Curated))
	}
	for _, group := range []struct {
		what  string
		hosts []suggestedHost
	}{{"Not suggested, only ever refused", s.Blocked}, {"Not suggested", s.Excluded}} {
		if len(group.hosts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# %s:\n", group.what)
		for _, h := range group.hosts {
			fmt.Fprintf(&b, "#   %s: %s\n", h.Host, h.Why)
		}
	}
	return b.String()
}

func hostComment(h suggestedHost) string {
	parts := []string{plural(h.Requests, "request", "requests")}
	if len(h.Binaries) > 0 {
		parts = append(parts, "by "+strings.Join(h.Binaries, ", "))
	}
	if len(h.Sandboxes) > 1 {
		parts = append(parts, "in "+strings.Join(h.Sandboxes, ", "))
	}
	return strings.Join(parts, "; ")
}

func joinHosts(list []suggestedHost) string {
	names := make([]string, 0, len(list))
	for _, h := range list {
		names = append(names, h.Host)
	}
	return listFit(strings.Join(names, ", "), 200)
}

// writeNewFile creates path with data, never over an existing file.
func writeNewFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%s exists; the suggestion never replaces a file", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		_ = os.Remove(path)
		return err
	}
	return f.Close()
}

// suggestionDiff compares the suggested pack with the effective policy: the
// sandbox's (its own explain), or what a run in this folder gets. The pack
// is resolved here with this machine's configuration, as a run with --pack
// would be, and every reached host it would block is listed.
func (a *App) suggestionDiff(ctx context.Context, api API, sandbox string, s *suggestion) (*suggestionDiff, error) {
	req := sandboxapi.ExplainRequest{Sandbox: sandbox}
	against := "the policy of sandbox " + sandbox
	if sandbox == "" {
		against = "the policy a run in this folder gets"
		if p, err := a.project(); err == nil {
			req.Project = p
		}
	}
	current, err := api.Explain(ctx, req)
	if err != nil {
		return nil, apiError(err)
	}
	dir, err := os.MkdirTemp("", "dc-suggest-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	file := filepath.Join(dir, packs.PackFileName)
	if err := os.WriteFile(file, []byte(s.Pack), 0o600); err != nil {
		return nil, err
	}
	cfg := a.Cfg
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	// The run it is compared with keeps its harness, project and
	// repository policy.
	flags := packs.Flags{Pack: file, Project: req.Project}
	if h := settingValue(current.Settings, "harness"); h != "" && !strings.HasPrefix(h, "(") {
		flags.Harness = h
	}
	if flags.RepoPolicy, err = parseRepoPolicy(current.RepoPolicy); err != nil {
		return nil, err
	}
	eff, _, err := packs.Resolve(cfg, flags)
	if err != nil {
		return nil, err
	}
	diff := &suggestionDiff{Against: against + " (pack " + current.Pack + ")", Settings: []settingChange{}}
	now := map[string]string{}
	for _, st := range current.Settings {
		now[st.Key] = st.Value
	}
	for _, st := range eff.Explain() {
		from, ok := now[st.Key]
		if !ok || from == st.Value || st.Key == "pack" {
			continue
		}
		diff.Settings = append(diff.Settings, settingChange{Key: st.Key, From: from, To: st.Value})
	}
	for _, host := range s.order {
		h := s.byHost[host]
		if h.Requests == 0 || h.kind == sandboxapi.DestinationModelProvider {
			continue
		}
		ports := s.ports[host]
		if len(ports) == 0 {
			ports = []int{0}
		}
		for _, port := range ports {
			chk := eff.CheckEgress(nil, egress.Principal{BindingID: "sandbox-policy-suggest"}, host, port)
			if !chk.Allowed {
				diff.Blocked = append(diff.Blocked, sandboxapi.PolicyDecision{PolicyCheck: sandboxapi.PolicyCheck{Host: host, Port: port},
					Rule: string(chk.Rule), Match: chk.Match, Source: chk.Source, Reason: chk.Reason, Unblockable: chk.Unblockable})
			}
		}
	}
	return diff, nil
}

func (a *App) printSuggestionDiff(d *suggestionDiff, name string) {
	a.line(a.bold("pack "+name) + " against " + d.Against + ":")
	if len(d.Settings) == 0 {
		a.line("  no setting changes")
	}
	for _, c := range d.Settings {
		from, to := splitList(c.From), splitList(c.To)
		if len(from) > 1 || len(to) > 1 {
			var added, removed []string
			for _, v := range to {
				if !slices.Contains(from, v) {
					added = append(added, v)
				}
			}
			for _, v := range from {
				if !slices.Contains(to, v) {
					removed = append(removed, v)
				}
			}
			var parts []string
			if len(added) > 0 {
				parts = append(parts, "+"+listFit(strings.Join(added, ", "), 90))
			}
			if len(removed) > 0 {
				parts = append(parts, "−"+listFit(strings.Join(removed, ", "), 90))
			}
			a.line(fmt.Sprintf("  %-26s %s", c.Key, strings.Join(parts, "  ")))
			continue
		}
		a.line(fmt.Sprintf("  %-26s %s → %s", c.Key, truncate(c.From, 40), truncate(c.To, 40)))
	}
	if len(d.Blocked) == 0 {
		a.ok("every destination the sandboxes reached stays reachable")
		return
	}
	a.warn("reached now, blocked with the pack:")
	for _, b := range d.Blocked {
		dest := b.Host
		if b.Port != 0 {
			dest += ":" + strconv.Itoa(b.Port)
		}
		a.line(fmt.Sprintf("  %s — %s %s (%s)", dest, b.Rule, b.Match, b.Source))
	}
}
