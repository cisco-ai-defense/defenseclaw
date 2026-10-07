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
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
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

// suggestGroupBytes bounds each list of hosts a suggested pack names in
// comments, so the pack's allow list keeps the room of the file
// (packs.MaxPackBytes).
const suggestGroupBytes = 4 << 10

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
// model provider or --credential endpoints, not a host name the allow list
// takes).
type suggestion struct {
	Sandboxes []string        `json:"sandboxes"`
	Allow     []suggestedHost `json:"allow"`
	Curated   []suggestedHost `json:"curated,omitempty"`
	Blocked   []suggestedHost `json:"blocked,omitempty"`
	Excluded  []suggestedHost `json:"excluded,omitempty"`
	// LeftOut are reached hosts the pack had no room for (fit).
	LeftOut []suggestedHost `json:"left_out,omitempty"`
	// Ports is the pack's egress.ports when the hosts it allows were
	// reached on ports beyond the base pack's (packPorts), else empty.
	Ports []int `json:"ports,omitempty"`
	// Pack is the suggested pack file; PackName its name.
	PackName string          `json:"pack_name"`
	Pack     string          `json:"pack"`
	Diff     *suggestionDiff `json:"diff,omitempty"`
	Wrote    string          `json:"wrote,omitempty"`
	byHost   map[string]*suggestedHost
	ports    map[string][]int
	order    []string
	// basePorts are the base pack's egress.ports, and room how many allow
	// entries a pack that extends it has left.
	basePorts []int
	room      int
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
// AI, hosts on the blocklist feed and the sandbox's own model provider and
// --credential endpoints are listed apart, not suggested. --pack-out writes
// the pack (checked as `pack validate` would), --diff says what it changes
// against the effective policy. Nothing is applied.
func (a *App) PolicySuggest(ctx context.Context, o SuggestOptions) error {
	a.defaults()
	if o.PackOut != "" {
		var err error
		if o.PackOut, err = a.packOutPath(o.PackOut); err != nil {
			return err
		}
	}
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
	s.fit(a.Now().Format("2006-01-02"), o.Sandbox)
	// The pack must load as `pack validate` would load it.
	if _, err := packs.ParseIn([]byte(s.Pack), s.PackName, a.packDir()); err != nil {
		return fmt.Errorf("the suggested pack does not validate (please report it): %w", err)
	}
	if o.Diff {
		if s.Diff, err = a.suggestionDiff(ctx, api, o.Sandbox, s); err != nil {
			return err
		}
	}
	if o.PackOut != "" {
		undo, err := writeNewFile(o.PackOut, []byte(s.Pack))
		if err != nil {
			return err
		}
		if _, err := packs.Validate(o.PackOut, a.packDir()); err != nil {
			undo()
			return fmt.Errorf("the written pack does not validate: %w", err)
		}
		s.Wrote = o.PackOut
	}
	if n := len(s.LeftOut); n > 0 && o.Output != OutputJSON {
		// On stderr: the printed pack may be going to a file.
		a.warnErr(plural(int64(n), "reached host", "reached hosts") + " did not fit in the pack (" + s.fullText() +
			"); it lists them as comments. Suggest per sandbox with --sandbox, or add the ones you need by hand")
	}
	switch {
	case o.Output == OutputJSON:
		return writeJSON(a.IO.Out, s)
	case o.PackOut != "":
		a.ok(fmt.Sprintf("wrote %s: pack %s, extends %s, %s to allow", o.PackOut, s.PackName, suggestBase,
			plural(int64(len(s.Allow)), "host", "hosts")))
		home := "<openshell.pack_dir>/" + s.PackName + "/" + packs.PackFileName
		if dir := a.packDir(); dir != "" {
			home = a.tildePath(filepath.Join(dir, s.PackName, packs.PackFileName))
		}
		written := o.PackOut
		if dir, err := filepath.EvalSymlinks(filepath.Dir(written)); err == nil {
			written = filepath.Join(dir, filepath.Base(written))
		}
		if project, err := a.project(); err == nil && workspace.Overlaps(project, written) {
			// A run that mounts the project refuses a pack inside it: the
			// agent could change its own policy.
			a.warn(o.PackOut + " is inside the project folder, where a run that mounts the project refuses a pack (the agent could change its own policy)")
			a.note("review it, then move it to " + home + " and lock the project to it: " + CommandName + " run --pack " + s.PackName +
				" (or run with --copy --pack " + o.PackOut + ")")
			break
		}
		a.note("review it, then lock a project to it: " + CommandName + " run --pack " + o.PackOut +
			" (or put it at " + home + " and use --pack " + s.PackName + ")")
	case !o.Diff:
		_, err := fmt.Fprint(a.IO.Out, terminalText(s.Pack))
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
	sort.Strings(s.order)
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
			h.Why = "the sandbox's model provider opens it directly to its own programs"
			s.Excluded = append(s.Excluded, *h)
		case h.kind == sandboxapi.DestinationCredential:
			h.Why = "a --credential binding of the sandbox opens it directly to the programs it binds"
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
	// The pack's allow list is balanced's with these appended.
	s.basePorts, s.room = balanced.Egress.Ports, max(packs.MaxListEntries-len(balanced.Egress.Allow), 0)
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
		s.order = append(s.order, host) // sorted once every row is in
	}
	h.Requests += r.Connections + r.Tunnels
	h.Refused += r.Refused + r.Blocked
	if !slices.Contains(h.Sandboxes, sandbox) {
		h.Sandboxes = append(h.Sandboxes, sandbox)
	}
	for _, b := range r.Binaries {
		if b = commentText(b, 120); b != "" && !slices.Contains(h.Binaries, b) && len(h.Binaries) < 4 {
			h.Binaries = append(h.Binaries, b)
		}
	}
	// The provider and AI kinds win over plain ones: a host one sandbox
	// reached as its model provider or a --credential endpoint and another
	// as shadow AI or a plain host is not suggested.
	if kindRank(r.Kind) > kindRank(h.kind) {
		h.kind = r.Kind
	}
	if label := firstNonEmpty(r.Provider, r.Category); label != "" {
		h.label = commentText(label, 120)
	}
	for _, p := range r.Ports {
		if !slices.Contains(s.ports[host], p) {
			s.ports[host] = append(s.ports[host], p)
		}
	}
}

func kindRank(kind string) int {
	switch {
	case kind == sandboxapi.DestinationModelProvider || kind == sandboxapi.DestinationCredential:
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

// commentText makes agent-controlled text (a recorded host, a binary path,
// a provider label) safe in a YAML comment of the pack, at most n
// characters: everything but printable characters becomes '?'. YAML ends a
// comment at NEL, U+2028 and U+2029 as well as at a newline, so a host that
// held one would set pack keys; control, format and bidirectional
// characters would hide text from the reviewer, and U+FFFE/U+FFFF the YAML
// reader refuses.
func commentText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, strings.TrimSpace(s))
	return truncate(s, n)
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
			// Quoted: a host such as "null" or "yes" is not a YAML value.
			fmt.Fprintf(&b, "    - %s # %s\n", strconv.Quote(h.Host), hostComment(h))
		}
	}
	ports, added, unsure := s.packPorts()
	s.Ports = ports
	if len(ports) > 0 {
		fmt.Fprintf(&b, "  # Beyond %s's ports %s, reached by %s. A pack's ports are open to every host it allows.\n",
			suggestBase, intsText(s.basePorts), listFit(strings.Join(added, ", "), 200))
		fmt.Fprintf(&b, "  ports: [%s]\n", intsText(ports))
	}
	if len(unsure) > 0 {
		fmt.Fprintf(&b, "  # Not opened, since these hosts were also refused (perhaps for the port; add one if they need it): %s\n",
			listFit(strings.Join(unsure, ", "), 200))
	}
	if len(s.Curated) > 0 {
		fmt.Fprintf(&b, "# Covered by the %s pack's curated allowlist: %s\n", suggestBase, joinHosts(s.Curated))
	}
	for _, group := range []struct {
		what  string
		hosts []suggestedHost
	}{{"Not suggested, only ever refused", s.Blocked}, {"Not suggested", s.Excluded},
		{"Not suggested, no room in the pack (" + s.fullText() + ")", s.LeftOut}} {
		if len(group.hosts) == 0 {
			continue
		}
		fmt.Fprintf(&b, "# %s:\n", group.what)
		size := 0
		for i, h := range group.hosts {
			// These hosts are not checked as host names: any text the
			// sandbox's traffic carried.
			line := fmt.Sprintf("#   %s: %s\n", commentText(h.Host, 256), h.Why)
			if size += len(line); size > suggestGroupBytes {
				fmt.Fprintf(&b, "#   and %d more (`%s policy suggest -o json` lists them)\n", len(group.hosts)-i, CommandName)
				break
			}
			b.WriteString(line)
		}
	}
	return b.String()
}

// fit renders the pack with as many of the hosts to allow as a pack holds:
// at most room allow entries (the base pack's own count against the limit)
// and a file of packs.MaxPackBytes. The most requested hosts stay; the
// rest are left out and listed apart.
func (s *suggestion) fit(day, sandbox string) {
	reached := s.Allow
	byUse := slices.Clone(reached)
	sort.SliceStable(byUse, func(i, j int) bool { return byUse[i].Requests > byUse[j].Requests })
	keep := func(n int) {
		kept := map[string]bool{}
		for _, h := range byUse[:n] {
			kept[h.Host] = true
		}
		s.Allow, s.LeftOut = []suggestedHost{}, nil
		for _, h := range reached {
			if kept[h.Host] {
				s.Allow = append(s.Allow, h)
			} else {
				h.Why = "no room in the pack"
				s.LeftOut = append(s.LeftOut, h)
			}
		}
		s.Pack = s.render(day, sandbox)
	}
	n := min(len(reached), s.room)
	if keep(n); len(s.Pack) <= packs.MaxPackBytes {
		return
	}
	// The comments are bounded (suggestGroupBytes), so a pack without
	// hosts fits: find the most that do.
	lo, hi := 0, n-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if keep(mid); len(s.Pack) <= packs.MaxPackBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	keep(lo)
}

// fullText says what a pack holds.
func (s *suggestion) fullText() string {
	return fmt.Sprintf("a pack holds %d allow entries, %d of them %s's, and %d KiB", packs.MaxListEntries,
		packs.MaxListEntries-s.room, suggestBase, packs.MaxPackBytes>>10)
}

// packPorts is egress.ports for the pack (nil: the base pack's) when the
// hosts it allows, the suggested and the curated ones, were reached on
// ports beyond the base pack's. A port is added (a pack's ports are open
// to every host it allows) with the hosts that used it (added). A host that
// was also refused may have been refused for its port: its other ports are
// only named (unsure), as are the ones past packs.MaxPorts.
func (s *suggestion) packPorts() (ports []int, added, unsure []string) {
	users := map[int][]string{}
	for _, h := range slices.Concat(s.Allow, s.Curated) {
		for _, p := range s.ports[h.Host] {
			switch {
			case slices.Contains(s.basePorts, p):
			case h.Refused > 0:
				unsure = append(unsure, commentText(h.Host, 256)+":"+strconv.Itoa(p))
			default:
				users[p] = append(users[p], commentText(h.Host, 256))
			}
		}
	}
	extra := slices.Sorted(maps.Keys(users))
	if room := max(packs.MaxPorts-len(s.basePorts), 0); len(extra) > room {
		for _, p := range extra[room:] {
			for _, host := range users[p] {
				unsure = append(unsure, host+":"+strconv.Itoa(p))
			}
		}
		extra = extra[:room]
	}
	if len(extra) == 0 {
		return nil, nil, unsure
	}
	ports = slices.Concat(s.basePorts, extra)
	slices.Sort(ports)
	for _, p := range extra {
		who := users[p][0]
		if more := len(users[p]) - 1; more > 0 {
			who += fmt.Sprintf(" and %d more", more)
		}
		added = append(added, fmt.Sprintf("%d (%s)", p, who))
	}
	return ports, added, unsure
}

// intsText is a list of ports: "80, 443".
func intsText(list []int) string {
	out := make([]string, 0, len(list))
	for _, p := range list {
		out = append(out, strconv.Itoa(p))
	}
	return strings.Join(out, ", ")
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
		names = append(names, commentText(h.Host, 256))
	}
	return listFit(strings.Join(names, ", "), 200)
}

// packOutPath is --pack-out as an absolute path, as `run --pack` and `pack
// validate` take it: "~/" is the home folder (a shell leaves it as typed in
// --pack-out=~/x or in quotes), and a relative path is in this folder.
func (a *App) packOutPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := a.Home()
		if err != nil || home == "" {
			return "", errors.New("--pack-out " + p + ": cannot resolve the home folder")
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	if !filepath.IsAbs(p) {
		wd, err := a.Getwd()
		if err != nil {
			return "", fmt.Errorf("--pack-out %s: %w", p, err)
		}
		p = filepath.Join(wd, p)
	}
	return filepath.Clean(p), nil
}

// writeNewFile creates path with data, never over an existing file, and
// the folders it goes in (<pack_dir>/<name>/ for a pack named by name).
// undo removes the file and the folders it created.
func writeNewFile(path string, data []byte) (undo func(), err error) {
	var made []string // innermost first
	for d := filepath.Dir(path); filepath.Dir(d) != d; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		}
		made = append(made, d)
	}
	removeMade := func() {
		for _, d := range made {
			_ = os.Remove(d) // empty folders only
		}
	}
	undo = func() {
		_ = os.Remove(path)
		removeMade()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		removeMade()
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		removeMade()
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("%s exists; the suggestion never replaces a file", path)
		}
		return nil, err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		undo()
		return nil, err
	}
	if err := f.Close(); err != nil {
		undo()
		return nil, err
	}
	return undo, nil
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
	forced := map[string]bool{}
	for _, st := range current.Settings {
		now[st.Key] = st.Value
		// The gateway's compute driver holds it (a MicroVM gateway works on
		// a copy): whatever the pack says, a run gets the same.
		forced[st.Key] = st.Source == string(packs.SourceGateway)
	}
	for _, st := range eff.Explain() {
		from, ok := now[st.Key]
		if !ok || from == st.Value || st.Key == "pack" || forced[st.Key] {
			continue
		}
		diff.Settings = append(diff.Settings, settingChange{Key: st.Key, From: from, To: st.Value})
	}
	for _, host := range s.order {
		h := s.byHost[host]
		if h.Requests == 0 || h.kind == sandboxapi.DestinationModelProvider || h.kind == sandboxapi.DestinationCredential {
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
