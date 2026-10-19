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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
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
	// Sources labels each value of a managed computer's explain with where
	// it comes from (your organization, your profile, the pack, ...).
	Sources bool
	Output  OutputFormat
}

func (a *App) explain(ctx context.Context, o PolicyOptions) (*sandboxapi.Explain, error) {
	api, err := a.api()
	if err != nil {
		return nil, err
	}
	// Every view needs provenance to replace generic admin origins with the
	// caller's resolved owner. --sources only controls the summary's tags.
	req := sandboxapi.ExplainRequest{Sandbox: o.Sandbox, Pack: o.Pack, Profile: o.Profile, Copy: o.Copy, Safe: o.Safe, Unmask: o.Unmask, Sources: true}
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
	managedExplainProvenance(ex)
	return ex, nil
}

// managedExplainAssumption says what a managed `policy show|explain`
// without --sandbox or --harness explained: a new run of the default agent,
// whose profile can differ from the one a running sandbox of another agent
// matched (an engineering profile for Claude Code next to a Codex-only
// profile; es-demo:GAP-0013). It names the running sandboxes to ask about
// instead. "" when a flag chose what to explain.
func (a *App) managedExplainAssumption(ctx context.Context, o PolicyOptions) string {
	if o.Sandbox != "" || o.Harness != "" {
		return ""
	}
	note := "this is the policy of a new run of the default agent; for another agent add --harness NAME"
	api, err := a.api()
	if err != nil {
		return note
	}
	list, err := api.List(ctx)
	if err != nil {
		return note
	}
	var running []string
	for _, sb := range list {
		if sandboxMayRunPhase(sb.Phase) {
			running = append(running, sb.Name+" ("+firstNonEmpty(sb.Harness, "agent")+")")
		}
	}
	if len(running) == 0 {
		return note
	}
	sort.Strings(running)
	shown := strings.Join(running[:min(len(running), 4)], ", ")
	if more := len(running) - 4; more > 0 {
		shown += fmt.Sprintf(" and %d more", more)
	}
	return note + "; a running sandbox can match another profile: " + CommandName + " policy explain --sandbox NAME (running: " + shown + ")"
}

// sandboxMayRunPhase reports a phase of a sandbox that may be running.
func sandboxMayRunPhase(phase string) bool {
	switch strings.ToLower(strings.TrimSpace(phase)) {
	case "ready", "running", "provisioning", "starting":
		return true
	}
	return false
}

// folderRepoPolicyNote is parentRepoPolicyNote for `policy show` and
// `policy explain` of a run in this folder (no --sandbox).
func (a *App) folderRepoPolicyNote(o PolicyOptions, ex *sandboxapi.Explain) string {
	if o.Sandbox != "" {
		return ""
	}
	project, err := a.project()
	if err != nil {
		return ""
	}
	return a.parentRepoPolicyNote(project, ex.RepoPolicy)
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
	if ex.Managed != nil {
		// On a managed computer the organization's floor is the user's own
		// policy as the managed gateway resolved it; the local configuration
		// is not the user's to read.
		a.printManagedExplainFor(ex.Managed, ex, o.Harness, false)
		if note := a.managedExplainAssumption(ctx, o); note != "" {
			a.note(note)
		}
		for _, v := range ex.Violations {
			a.warn(violationMessage(&v, v.Message, v.Detail, v.Admin))
		}
		a.println()
		a.note("every setting and where it comes from: " + CommandName + " policy explain --sources")
		return nil
	}
	rows := [][2]string{
		{"Pack", ex.Pack + " (" + ex.PackSource + ") " + ex.PackDigest + extendsText(packLinks(ex.PackChain))},
		{"Network profile", ex.Profile}, {"Network", ex.NetworkMode}, {"Approvals", ex.Approvals},
		{"Organization", adminText(ex.Admin)},
	}
	if text := firstNonEmpty(repoPolicyText(ex.RepoPolicy), a.folderRepoPolicyNote(o, ex)); text != "" {
		rows = append(rows, [2]string{"Repository", text})
	}
	for _, key := range []string{"yolo", "harness.allowed", "workdir.mode", "egress.feeds", "egress.block", "egress.admin_block",
		"egress.allow", "egress.allow_only", "egress.ports", "mcp.import", "hooks.fail_mode"} {
		if v := settingValue(ex.Settings, key); v != "" {
			shown, note := settingShown(ex, key, v)
			rows = append(rows, [2]string{key, withNote(listSummary(shown, 8), note)})
		}
	}
	if settingValue(ex.Settings, "egress.block_large_uploads") == "true" {
		rows = append(rows, [2]string{"egress.block_large_uploads", "true (an upload of more than " +
			firstNonEmpty(settingValue(ex.Settings, "egress.large_upload_mb"), "?") +
			" MiB to a host the sandbox had not contacted is cut)"})
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

// repoPolicyChangedNote says, in a sandbox's explain, that its repository
// policy file changed on the host since the sandbox was created: nothing
// said that the running sandbox keeps the policy it was created with, and
// that the change applies to the next new run (GAP-0338). "" when the file
// is as it was, or cannot be read.
func repoPolicyChangedNote(name string, rp *sandboxapi.RepoPolicy) string {
	if rp.Path == "" || !strings.HasPrefix(rp.Digest, "sha256:") {
		return ""
	}
	keeps := name + " keeps the policy it was created with, and the change applies to the next new run (which refuses one that loosens it)"
	info, err := os.Stat(rp.Path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "the repository policy file is gone since " + name + " was created; " + keeps
	case err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20:
		return ""
	}
	data, err := os.ReadFile(rp.Path)
	if err != nil {
		return ""
	}
	if sum := sha256.Sum256(data); "sha256:"+hex.EncodeToString(sum[:]) == rp.Digest {
		return ""
	}
	return "the repository policy file changed since " + name + " was created; " + keeps
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
	managedHost := ex.Managed != nil
	if managedHost {
		a.printManagedExplainFor(ex.Managed, ex, o.Harness, o.Sources)
		if note := a.managedExplainAssumption(ctx, o); note != "" {
			a.note(note)
		}
		a.println()
	}
	head := "pack " + ex.Pack + " " + ex.PackDigest + " from "
	a.line(a.bold("pack "+ex.Pack) + " " + ex.PackDigest + " from " +
		truncate(ex.PackSource, max(explainWidth-2-utf8.RuneCountInString(head), 24)))
	for _, link := range ex.PackChain {
		a.line(truncate("  extends "+link.Name+" "+link.Digest+" from "+link.Source, explainWidth-2))
	}
	if !managedHost {
		a.line(truncate("organization: "+adminText(ex.Admin), explainWidth-2))
	}
	if rp := ex.RepoPolicy; rp != nil {
		a.line(truncate("repository: "+rp.Path+" "+rp.Digest, explainWidth-2))
		a.line(truncate("  "+repoPolicyText(rp)+"; settings it decided have the source repo", explainWidth-2))
		if o.Sandbox != "" {
			if note := repoPolicyChangedNote(o.Sandbox, rp); note != "" {
				a.note(note)
			}
		}
	} else if note := a.folderRepoPolicyNote(o, ex); note != "" {
		a.line("repository: " + note)
	}
	// Keep each origin whole so its setting key remains visible. Wide
	// tables become labelled rows on a narrow terminal; long list values
	// still shorten to the entries that fit, with -o json listing them all.
	keyW, srcW, originW := len("SETTING"), len("SOURCE"), len("ORIGIN")
	for _, s := range ex.Settings {
		keyW = max(keyW, utf8.RuneCountInString(s.Key))
		srcW = max(srcW, utf8.RuneCountInString(s.Source))
		originW = max(originW, utf8.RuneCountInString(managedSettingOrigin(ex, s)))
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
		rows = append(rows, []string{s.Key, val, s.Source, managedSettingOrigin(ex, s)})
	}
	a.table([]string{"SETTING", "VALUE", "SOURCE", "ORIGIN"}, rows)
	for _, n := range notes {
		a.note(n)
	}
	// On a managed computer the organization's constraints are the managed
	// section above: the local configuration is not the user's to read.
	if lines := a.adminConstraints(); len(lines) > 0 && !managedHost {
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
	ad := packs.BaseFloor(a.Cfg)
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
	if ad.BlockLargeUploads {
		add("block_large_uploads", "true")
	}
	list("require_copy_for", ad.RequireCopyFor)
	if r := ad.MaxResources; r.CPU != "" || r.Memory != "" {
		add("max_resources", strings.TrimSpace(firstNonEmpty(r.CPU, "-")+" CPU, "+firstNonEmpty(r.Memory, "-")+" memory"))
	}
	list("locked", ad.Locked)
	return out
}

// PolicyEdit adds hosts to openshell.egress.allow or openshell.egress.block.
func (a *App) PolicyEdit(ctx context.Context, list string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("name at least one host")
	}
	if list != "allow" && list != "block" {
		return fmt.Errorf("unknown egress list %q", list)
	}
	key := "openshell.egress." + list
	wanted := make([]string, 0, len(hosts))
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
		wanted = append(wanted, h)
	}
	added, err := a.addEgressHosts(list, wanted)
	if err != nil {
		return err
	}
	if len(added) == 0 {
		a.ok("already in " + key)
		return nil
	}
	a.ok("added " + strings.Join(added, ", ") + " to " + key)
	if list == "allow" {
		a.note("allow entries matter in the balanced and strict profiles; open allows everything not blocked")
	}
	a.note("the daemon applies it to running sandboxes within a few seconds")
	return nil
}

// PolicyRemove removes hosts from openshell.egress.allow or
// openshell.egress.block (`sandbox policy allow|block --remove`), entries
// matched as written, letter case aside: before it, only `config unset`
// emptied a whole list, and a block entry stays a block no unblock lifts
// (GAP-0151).
func (a *App) PolicyRemove(ctx context.Context, list string, hosts []string) error {
	if len(hosts) == 0 {
		return errors.New("name at least one host")
	}
	if list != "allow" && list != "block" {
		return fmt.Errorf("unknown egress list %q", list)
	}
	key := "openshell.egress." + list
	displayKey := key
	var removed, missing []string
	err := a.patchConfigComputed("", func(raw []byte) (map[string]any, error) {
		root, err := sandboxSource(raw)
		if err != nil {
			return nil, err
		}
		// The common block owns shared writes even when this list still
		// inherits its current entries from the legacy source.
		if sandboxSourceAt(root, "sandbox") != nil {
			displayKey = "sandbox.egress." + list
		}
		current, err := sourceEgressListAt(root, list)
		if err != nil {
			return nil, err
		}
		next := make([]string, 0, len(current))
		for _, have := range current {
			if slices.ContainsFunc(hosts, func(h string) bool { return strings.EqualFold(config.NormalizeOpenShellEgressPattern(h), have) }) {
				removed = append(removed, have)
			} else {
				next = append(next, have)
			}
		}
		if len(removed) == 0 {
			return nil, fmt.Errorf("%s is not in %s; `%s policy explain` shows where a block comes from", strings.Join(hosts, ", "), displayKey, CommandName)
		}
		return map[string]any{key: next}, nil
	})
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if !slices.ContainsFunc(removed, func(r string) bool { return strings.EqualFold(r, config.NormalizeOpenShellEgressPattern(h)) }) {
			missing = append(missing, h)
		}
	}
	a.ok("removed " + strings.Join(removed, ", ") + " from " + displayKey)
	if len(missing) > 0 {
		a.warn(strings.Join(missing, ", ") + " is not in " + displayKey)
	}
	a.note("the daemon applies it to running sandboxes within a few seconds")
	return nil
}

// addEgressHosts appends the hosts it does not already have to
// the effective egress list and returns the ones it added. Reading and
// changing the list share the config writer lock, retaining concurrent
// decisions and honoring the current policy source rather than a.Cfg.
func (a *App) addEgressHosts(list string, hosts []string) ([]string, error) {
	var added []string
	err := a.patchConfigComputed("", func(raw []byte) (map[string]any, error) {
		current, err := sourceEgressList(raw, list)
		if err != nil {
			return nil, err
		}
		next := slices.Clone(current)
		for _, h := range hosts {
			if !slices.ContainsFunc(next, func(have string) bool { return strings.EqualFold(strings.TrimSpace(have), h) }) {
				next = append(next, h)
				added = append(added, h)
			}
		}
		if len(added) == 0 {
			return nil, nil
		}
		return map[string]any{"openshell.egress." + list: next}, nil
	})
	return added, err
}

func sourceEgressList(raw []byte, list string) ([]string, error) {
	root, err := sandboxSource(raw)
	if err != nil {
		return nil, err
	}
	return sourceEgressListAt(root, list)
}

func sourceEgressListAt(root *yaml.Node, list string) ([]string, error) {
	node := sandboxSourceAt(root, "sandbox.egress."+list)
	if node == nil {
		node = sandboxSourceAt(root, "openshell.egress."+list)
	}
	var current []string
	var err error
	if node != nil {
		err = node.Decode(&current)
	}
	return current, err
}

// adminAllows refuses an allow entry the organization's policy would make
// dead: allow entries are ignored under allow_unblock: false, and nothing
// on egress_block or outside egress_allow_only is reachable whatever the
// entry says.
func (a *App) adminAllows(entry string) error {
	if a.Cfg == nil {
		return nil
	}
	ad := packs.BaseFloor(a.Cfg)
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

// managedConfigRefusal is the refusal of a local config edit on a managed
// device: the organization's sentence, and exit 3 like every other local writer
// (GAP-0052).
func managedConfigRefusal() error {
	return &ExitError{Code: 3, Err: errors.New(sandboxapi.AdminMessage + ": the configuration is administrator-owned")}
}

// patchConfig writes keys to config.yaml through the single config writer,
// which validates the change before anything is written.
func (a *App) patchConfig(updates map[string]any) error {
	return a.patchConfigIf(updates, "")
}

// patchConfigIf is patchConfig for a read-modify-write: a non-empty
// expectSHA256 (of the bytes the new values were computed from) makes the
// write fail with configwrite.ErrConflict when config.yaml has changed since.
//
// A standalone managed document is refused by the writer itself
// (configwrite.ErrManaged, below), and a managed host's sandboxes keep
// their "always" decisions in the managed gateway's decisions store
// through the daemon, not here. A Secure Client document is not refused by
// the writer, so the callback refuses its current source under the same lock.
func (a *App) patchConfigIf(updates map[string]any, expectSHA256 string) error {
	return a.patchConfigComputed(expectSHA256, func([]byte) (map[string]any, error) { return updates, nil })
}

func (a *App) patchConfigComputed(expectSHA256 string, compute func([]byte) (map[string]any, error)) error {
	a.defaults()
	if a.Cfg != nil && managed.IsManagedEnterprise(a.Cfg.DeploymentMode) && !a.Cfg.StandaloneEnterprise() {
		return managedConfigRefusal()
	}
	_, err := configwrite.ApplyComputed(context.Background(), a.ConfigPath, func(raw []byte) ([]configwrite.Change, error) {
		root, err := sandboxSource(raw)
		if err != nil {
			return nil, err
		}
		// The generic writer permits Secure Client config edits. Sandbox
		// policy is administrator-owned under either managed profile.
		mode := sandboxSourceAt(root, "deployment_mode")
		if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) || mode != nil && managed.IsManagedEnterprise(mode.Value) {
			return nil, configwrite.ErrManaged
		}
		updates, err := compute(raw)
		if err != nil {
			return nil, err
		}
		return sandboxPolicyChanges(root, updates)
	}, configwrite.Options{
		Actor:        configwrite.CurrentActor(configwrite.ActorPrefixCLI),
		Reason:       "defenseclaw-gateway sandbox",
		ExpectSHA256: expectSHA256,
	})
	if errors.Is(err, configwrite.ErrManaged) {
		return managedConfigRefusal()
	}
	if err != nil {
		return fmt.Errorf("%s was not changed: %w", a.ConfigPath, err)
	}
	return nil
}

// sandboxSource keeps authority decisions tied to explicit source keys, not
// loader defaults or the common policy projected into a.Cfg.OpenShell.
func sandboxSource(raw []byte) (*yaml.Node, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	doc, err := config.ParseV8YAML("", raw)
	if err != nil {
		return nil, err
	}
	return doc.Document.Content[0], nil
}

func sandboxSourceAt(root *yaml.Node, path string) *yaml.Node {
	node := root
	for _, key := range strings.Split(path, ".") {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
				break
			}
		}
		node = next
	}
	return node
}

func refuseAXISSetup(root *yaml.Node) error {
	if runtime := sandboxSourceAt(root, "sandbox.runtime"); runtime != nil && runtime.Value == "axis" {
		return axisSetupRefusal()
	}
	return nil
}

func axisSetupRefusal() error {
	return errors.New("sandbox.runtime is axis; AXIS is not available in this build, so OpenShell setup cannot enable it; explicitly select sandbox.runtime openshell before running setup")
}

func (a *App) checkSetupRuntime() error {
	file, err := os.Open(a.ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		if a.Cfg != nil && a.Cfg.SandboxDefaultRuntime() == "axis" {
			return axisSetupRefusal()
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s before setup: %w", a.ConfigPath, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(config.V8YAMLMaxSourceBytes)+1))
	if err != nil {
		return fmt.Errorf("read %s before setup: %w", a.ConfigPath, err)
	}
	root, err := sandboxSource(raw)
	if err != nil {
		return err
	}
	return refuseAXISSetup(root)
}

func sandboxPolicyChanges(root *yaml.Node, updates map[string]any) ([]configwrite.Change, error) {
	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var changes []configwrite.Change
	common := sandboxSourceAt(root, "sandbox") != nil
	for _, key := range keys {
		value := updates[key]
		suffix, legacy := strings.CutPrefix(key, "openshell.")
		if !common || !legacy {
			changes = append(changes, configwrite.Change{Path: key, Value: value})
			continue
		}
		if suffix == "enabled" {
			on, ok := value.(bool)
			if !ok {
				return nil, errors.New("openshell.enabled requires a boolean")
			}
			if on {
				if err := refuseAXISSetup(root); err != nil {
					return nil, err
				}
				changes = append(changes, configwrite.Change{Path: "sandbox.runtimes.openshell.enabled", Value: true})
			}
			changes = append(changes, configwrite.Change{Path: "sandbox.enabled", Value: on})
		} else if commonSandboxPolicySuffix(suffix) {
			// These callers write individual leaves. Refuse a whole policy
			// mapping rather than replace unrelated explicit legacy leaves.
			var encoded yaml.Node
			if err := encoded.Encode(value); err != nil {
				return nil, err
			}
			if encoded.Kind == yaml.MappingNode {
				return nil, fmt.Errorf("%s: write individual sandbox policy fields", key)
			}
			changes = append(changes, configwrite.Change{Path: "sandbox." + suffix, Value: value})
		} else {
			changes = append(changes, configwrite.Change{Path: key, Value: value})
			continue
		}
		// Keep an explicit duplicate synchronized only for the intended
		// leaf. Every other source conflict is still rejected by validation.
		if sandboxSourceAt(root, key) != nil {
			changes = append(changes, configwrite.Change{Path: key, Value: value})
		}
	}
	return changes, nil
}

func commonSandboxPolicySuffix(suffix string) bool {
	key, _, _ := strings.Cut(suffix, ".")
	// Shared fields of config.SandboxConfig; vendor fields stay openshell.*.
	switch key {
	case "ingress_port", "egress_port", "pack", "pack_dir", "profile", "yolo", "llm", "keep_headless",
		"workdir", "egress", "approvals", "resources", "harnesses", "wrappers", "mcp", "admin":
		return true
	}
	return false
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
	api, err := a.managedPackAPI()
	if err != nil {
		return apiError(err)
	}
	if api != nil {
		return a.managedPackList(context.Background(), api, o)
	}
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
		switch {
		case e.Builtin:
			kind = "built-in"
		case e.Extends != "":
			kind = "custom, extends " + e.Extends
		}
		rows = append(rows, []string{e.Name, kind, e.Profile, digest})
	}
	a.table([]string{"NAME", "KIND", "NETWORK PROFILE", "DIGEST"}, rows)
	for _, e := range invalid {
		a.bad(e.Name + ": " + e.Err.Error())
	}
	return nil
}

// PackShow prints one pack and its digest.
func (a *App) PackShow(ref string, o PackOptions) error {
	a.defaults()
	api, err := a.managedPackAPI()
	if err != nil {
		return apiError(err)
	}
	if api != nil {
		return a.managedPackShow(context.Background(), api, ref, o)
	}
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
	for _, link := range p.Chain {
		a.println("# extends " + link.Name + " (" + link.Source + ") " + link.Digest)
	}
	if len(p.Chain) > 0 {
		a.println("# the settings below are the merged result; the file sets only what it changes")
	}
	_, err = a.IO.Out.Write(data)
	return err
}

// PackValidate strictly loads a pack file.
func (a *App) PackValidate(path string) error {
	a.defaults()
	p, err := packs.Validate(path, a.packDir())
	if err != nil {
		return err
	}
	a.ok("valid pack " + p.Name + " (network profile " + p.Profile() + ") " + p.Digest + extendsText(p.Chain))
	return nil
}

// packLinks is an explain's pack chain as the packs package names it.
func packLinks(chain []sandboxapi.PackLink) []packs.PackLink {
	out := make([]packs.PackLink, 0, len(chain))
	for _, l := range chain {
		out = append(out, packs.PackLink{Name: l.Name, Builtin: l.Builtin, Source: l.Source, Digest: l.Digest})
	}
	return out
}

// extendsText names the packs a pack extends (" extends a, which extends
// b"), or "".
func extendsText(chain []packs.PackLink) string {
	var b strings.Builder
	for i, link := range chain {
		if i == 0 {
			b.WriteString(" extends ")
		} else {
			b.WriteString(", which extends ")
		}
		b.WriteString(link.Name)
	}
	return b.String()
}
