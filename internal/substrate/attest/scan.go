// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// AdmissionFunc decides a scan result with the existing admission rules
// (config admission.<type>.actions, the block and allow lists). The default
// is policy.EvaluateAdmissionFallback over policy.CompileAdmission, the Go
// twin of admission.rego; a gateway passes its OPA engine instead.
type AdmissionFunc func(ctx context.Context, in policy.AdmissionInput) (*policy.AdmissionOutput, error)

// FallbackAdmission is the Go-twin AdmissionFunc.
func FallbackAdmission(_ context.Context, in policy.AdmissionInput) (*policy.AdmissionOutput, error) {
	return policy.EvaluateAdmissionFallback(in), nil
}

// ExpectedFile is a file the kit and settings layer must have root-owned.
type ExpectedFile struct {
	Path string
	// Optional files are checked when present and not required.
	Optional bool
}

// ScanOptions configure ScanImage.
type ScanOptions struct {
	// Skill scans one skill directory (scanner.SkillScanner in production).
	Skill scanner.Scanner
	// MCPStatic scans a tools JSON file written from a server's source
	// (MCPStaticScanner in production). Nil means only the config rules run.
	MCPStatic scanner.Scanner
	// Admission decides each item. Nil is FallbackAdmission.
	Admission AdmissionFunc
	// Compiled is the compiled admission config by asset type
	// (policy.CompileAdmission). Nil fails closed: every finding blocks.
	Compiled             map[string]policy.CompiledAdmission
	BlockList, AllowList []policy.ListEntry
	// AllowedMCPHosts, when not empty, lists the remote MCP hosts allowed.
	AllowedMCPHosts []string

	Connector string
	// Expected are the root-owned hook and settings files.
	Expected []ExpectedFile
	// PhoneHome are the environment switches that must be set.
	PhoneHome map[string]string
	// ExtraEnvOK are config-file switches (Codex) checked in a file:
	// path → substrings that must all be present.
	ConfigSwitches map[string][]string

	// BlockAtOrAbove is the severity from which a finding blocks whatever the
	// host admission actions say (empty or FloorNone: no floor; Build
	// defaults to HIGH): a template is a
	// supply-chain artifact an admin builds on purpose, and a malicious skill
	// or MCP server in it must not ship because the host default only warns.
	BlockAtOrAbove scanner.Severity
	// AcceptFindings are rule ids an admin accepted at the build floor
	// (each with a reason). An accepted rule that lifts no block is an
	// error, so an acceptance never outlives the finding it was for.
	AcceptFindings []AcceptedFinding

	PolicyGeneration int64
	Now              func() time.Time
}

func (o *ScanOptions) now() time.Time {
	if o.Now != nil {
		return o.Now().UTC()
	}
	return time.Now().UTC()
}

// ScanReport is what ScanImage found.
type ScanReport struct {
	Summary ScanSummary
	Hooks   HookChecks
	// Results are the raw scanner results per item, for `scan --json`.
	Results map[string]*scanner.ScanResult
	// UserOK is false when the image runs as root.
	User string
}

// Blocked lists items whose verdict is block.
func (r *ScanReport) Blocked() []ScanItem {
	var out []ScanItem
	for _, it := range r.Summary.Items {
		if it.Verdict == VerdictBlock {
			out = append(out, it)
		}
	}
	return out
}

// HooksOK reports whether the hook-file and switch checks passed.
func (r *ScanReport) HooksOK() bool {
	return r.Hooks.RootOwned && r.Hooks.PhoneHomeOff && r.Hooks.EnvClean
}

// ScanImage scans every skill, plugin and MCP server definition in the
// image, and checks the hook files and the phone-home switches.
func ScanImage(ctx context.Context, fsys *ImageFS, cfg *ConfigDoc, o ScanOptions) (*ScanReport, error) {
	if o.Skill == nil {
		return nil, errors.New("scan: no skill scanner")
	}
	if o.Admission == nil {
		o.Admission = FallbackAdmission
	}
	work, err := os.MkdirTemp("", "dc-attest-scan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)

	rep := &ScanReport{Results: map[string]*scanner.ScanResult{}}
	sum := &rep.Summary
	sum.Findings = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	sum.Verdict = VerdictClean
	sum.ScannedAt = o.now()
	scannerSeen := map[string]bool{}
	note := func(name, version string) {
		if !scannerSeen[name] {
			scannerSeen[name] = true
			sum.Scanners = append(sum.Scanners, ScannerInfo{Name: name, Version: version})
		}
	}
	lifted := map[string][]string{} // accepted rule id → items
	record := func(kind, name, p, scanName string, res *scanner.ScanResult) {
		verdict, reason, accepted := o.decide(ctx, kind, name, p, res)
		item := ScanItem{Kind: kind, Name: name, Path: p, Scanner: scanName, Verdict: verdict,
			Findings: len(res.Findings), Reason: reason, Accepted: accepted}
		for _, id := range accepted {
			lifted[id] = append(lifted[id], kind+":"+p)
		}
		if len(res.Findings) > 0 {
			item.MaxSeverity = string(res.MaxSeverity())
		}
		for _, f := range res.Findings {
			sum.Findings[strings.ToLower(string(f.Severity))]++
		}
		sum.Items = append(sum.Items, item)
		rep.Results[kind+":"+p+":"+name] = res
		sum.Verdict = worse(sum.Verdict, verdict)
	}

	// Skills: a directory holding SKILL.md, outermost only.
	var skillDirs []string
	for _, p := range fsys.Paths() {
		if path.Base(p) != "SKILL.md" {
			continue
		}
		if r, _, ok := fsys.Resolve(p); !ok || !r.IsRegular() {
			continue
		}
		dir := path.Dir(p)
		nested := false
		for _, have := range skillDirs {
			if strings.HasPrefix(dir, have+"/") {
				nested = true
			}
		}
		if !nested {
			skillDirs = append(skillDirs, dir)
		}
	}
	for _, dir := range skillDirs {
		sum.Skills++
		note(o.Skill.Name(), o.Skill.Version())
		local, skipped, err := fsys.Materialize(dir, filepath.Join(work, "skills"))
		var res *scanner.ScanResult
		if err == nil {
			res, err = o.Skill.Scan(ctx, local)
		}
		if err != nil || res == nil {
			res = failedScan(o.Skill.Name(), dir, err)
		}
		if len(skipped) > 0 {
			// Content the scanner could not be given is a finding, never silence.
			res.Findings = append(res.Findings, scanner.Finding{ID: "skill-unscannable-entries", RuleID: "skill-unscannable-entries",
				Severity: scanner.SeverityMedium, Title: "Skill folder holds entries the scan could not read",
				Description: strings.Join(skipped, "; "), Location: dir, Scanner: ConfigScannerName, Category: "skill-config"})
		}
		record(config.AdmissionTypeSkill, path.Base(dir), dir, o.Skill.Name(), res)
	}

	// Plugins: a directory with a plugin manifest. Their skills and MCP
	// servers are found by the other passes; the plugin is judged by its
	// hook commands.
	for _, manifest := range []string{"/.claude-plugin/plugin.json", "/.codex-plugin/plugin.json"} {
		for _, p := range fsys.Paths() {
			if !strings.HasSuffix(p, manifest) {
				continue
			}
			dir := strings.TrimSuffix(p, manifest)
			sum.Plugins++
			note(ConfigScannerName, "1")
			res := &scanner.ScanResult{Scanner: ConfigScannerName, Target: dir, Timestamp: o.now()}
			res.Findings = append(res.Findings, pluginHookFindings(fsys, dir)...)
			record(config.AdmissionTypePlugin, path.Base(dir), dir, ConfigScannerName, res)
		}
	}

	// MCP servers: every definition in every config file.
	for _, p := range fsys.Paths() {
		if !isMCPConfig(p) {
			continue
		}
		if r, _, ok := fsys.Resolve(p); !ok || !r.IsRegular() {
			continue
		}
		data, err := fsys.Read(p)
		if err != nil {
			res := failedScan(ConfigScannerName, p, err)
			sum.MCPServers++
			record(config.AdmissionTypeMCP, path.Base(p), p, ConfigScannerName, res)
			continue
		}
		servers, err := ParseMCPConfig(p, data)
		if err != nil {
			sum.MCPServers++
			record(config.AdmissionTypeMCP, path.Base(p), p, ConfigScannerName, failedScan(ConfigScannerName, p, err))
			continue
		}
		for _, s := range servers {
			sum.MCPServers++
			note(ConfigScannerName, "1")
			res := &scanner.ScanResult{Scanner: ConfigScannerName, Target: p + "#" + s.Name, Timestamp: o.now()}
			res.Findings = append(res.Findings, ConfigRules(s, o.AllowedMCPHosts)...)
			scanName := ConfigScannerName
			if o.MCPStatic != nil && s.Transport == "stdio" {
				tools, srcNote := serverTools(fsys, s)
				if len(tools) > 0 {
					note(o.MCPStatic.Name(), o.MCPStatic.Version())
					scanName = o.MCPStatic.Name()
					if err := os.MkdirAll(filepath.Join(work, "tools"), 0o700); err != nil {
						return nil, err
					}
					tf := filepath.Join(work, "tools", fmt.Sprintf("tools-%d.json", len(sum.Items)))
					raw, _ := json.Marshal(map[string]any{"tools": tools})
					if err := os.WriteFile(tf, raw, 0o600); err != nil {
						return nil, err
					}
					sr, err := o.MCPStatic.Scan(ctx, tf)
					if err != nil || sr == nil {
						sr = failedScan(o.MCPStatic.Name(), s.Name, err)
					}
					res.Findings = append(res.Findings, sr.Findings...)
					if sr.ScanError != "" {
						res.ScanError, res.ExitCode = sr.ScanError, sr.ExitCode
					}
				} else if srcNote != "" {
					res.Findings = append(res.Findings, scanner.Finding{ID: "mcp-tools-unreadable", RuleID: "mcp-tools-unreadable",
						Severity: scanner.SeverityInfo, Title: "MCP tool definitions could not be read from the image",
						Description: srcNote, Location: p, Scanner: ConfigScannerName, Category: "mcp-config"})
				}
			}
			record(config.AdmissionTypeMCP, s.Name, p, scanName, res)
		}
	}

	sort.Slice(sum.Items, func(i, j int) bool {
		a, b := sum.Items[i], sum.Items[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Name < b.Name
	})
	sort.Slice(sum.Scanners, func(i, j int) bool { return sum.Scanners[i].Name < sum.Scanners[j].Name })

	env, err := cfg.EnvMap()
	if err != nil {
		return nil, err
	}
	user, _, _, _, err := cfg.Container()
	if err != nil {
		return nil, err
	}
	rep.User = user
	rep.Hooks = checkHooks(fsys, env, user, o)
	sum.Verdict = worse(sum.Verdict, VerdictClean)
	for _, a := range o.AcceptFindings {
		items := lifted[a.RuleID]
		if len(items) == 0 {
			return nil, fmt.Errorf("scan: --accept-finding %s lifts no blocked finding; remove it", a.RuleID)
		}
		a.Items = items
		if a.At.IsZero() {
			a.At = o.now()
		}
		sum.Accepted = append(sum.Accepted, a)
	}
	return rep, nil
}

// decide runs the admission rules on one result. accepted are the rule ids
// of AcceptFindings that lifted the build floor for this item.
func (o *ScanOptions) decide(ctx context.Context, kind, name, p string, res *scanner.ScanResult) (verdict, reason string, accepted []string) {
	in := policy.AdmissionInput{TargetType: kind, TargetName: name, Path: p, BlockList: o.BlockList, AllowList: o.AllowList}
	if c, ok := o.Compiled[kind]; ok {
		cc := c
		in.Admission = &cc
	}
	max := ""
	if len(res.Findings) > 0 {
		max = string(res.MaxSeverity())
	}
	in.ScanResult = &policy.ScanResultInput{MaxSeverity: max, TotalFindings: len(res.Findings),
		ScannerName: res.Scanner, ExitCode: res.ExitCode, ScanError: res.ScanError}
	for _, f := range res.Findings {
		in.ScanResult.Findings = append(in.ScanResult.Findings, policy.FindingInput{
			Severity: string(f.Severity), Scanner: f.Scanner, Title: f.Title, RuleID: f.RuleID})
	}
	out, err := o.Admission(ctx, in)
	if err != nil || out == nil {
		return VerdictBlock, "admission could not decide", nil
	}
	floor := o.BlockAtOrAbove
	hostBlocks := out.Verdict == "rejected" || out.Verdict == "blocked"
	if floor != "" && floor != FloorNone && !hostBlocks {
		// The floor counts every finding at or above it except those of an
		// accepted rule; the accepted ones are recorded on the item.
		blocking, liftedBy := false, map[string]bool{}
		for _, f := range res.Findings {
			if sevRank(f.Severity) < sevRank(floor) {
				continue
			}
			if o.accepts(f.RuleID) {
				liftedBy[f.RuleID] = true
				continue
			}
			blocking = true
		}
		if blocking {
			return VerdictBlock, fmt.Sprintf("a template build blocks %s findings (host admission said %s)", floor, out.Verdict), nil
		}
		for id := range liftedBy {
			accepted = append(accepted, id)
		}
		sort.Strings(accepted)
	}
	switch out.Verdict {
	case "rejected", "blocked":
		return VerdictBlock, out.Reason, nil
	case "warning":
		return VerdictWarn, out.Reason, accepted
	case "clean", "allowed":
		if len(accepted) > 0 {
			// An accepted finding is never "clean": the item warns.
			return VerdictWarn, "accepted findings: " + strings.Join(accepted, ", "), accepted
		}
		return VerdictClean, out.Reason, nil
	default:
		// "scan" or unknown: nothing admitted the item.
		return VerdictBlock, "not admitted: " + out.Verdict, nil
	}
}

func (o *ScanOptions) accepts(ruleID string) bool {
	if ruleID == "" {
		return false
	}
	for _, a := range o.AcceptFindings {
		if a.RuleID == ruleID {
			return true
		}
	}
	return false
}

func failedScan(name, target string, err error) *scanner.ScanResult {
	msg := "scan did not run"
	if err != nil {
		msg = err.Error()
	}
	return &scanner.ScanResult{Scanner: name, Target: target, Timestamp: time.Now().UTC(), ExitCode: 1, ScanError: msg}
}

func worse(a, b string) string {
	rank := map[string]int{VerdictClean: 0, VerdictWarn: 1, VerdictBlock: 2}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// pluginHookFindings applies the fetch-and-exec rule to a plugin's hooks.
func pluginHookFindings(fsys *ImageFS, dir string) []scanner.Finding {
	var out []scanner.Finding
	for _, e := range fsys.Under(dir) {
		if !e.IsRegular() || path.Base(e.Path) != "hooks.json" {
			continue
		}
		data, err := fsys.Read(e.Path)
		if err != nil {
			out = append(out, scanner.Finding{ID: "plugin-hook-unreadable", RuleID: "plugin-hook-unreadable",
				Severity: scanner.SeverityMedium, Title: "Plugin hook file could not be read",
				Description: err.Error(), Location: e.Path, Scanner: ConfigScannerName, Category: "plugin-config"})
			continue
		}
		if fetchAndExec.Match(data) {
			out = append(out, scanner.Finding{ID: "plugin-hook-fetch-and-exec", RuleID: "plugin-hook-fetch-and-exec",
				Severity: scanner.SeverityHigh, Title: "Plugin hook downloads and runs code",
				Description: "a hook command pipes a download into a shell", Location: e.Path,
				Scanner: ConfigScannerName, Category: "plugin-config"})
		}
	}
	return out
}

// serverTools reads the tool definitions of a stdio server whose source is in
// the image.
func serverTools(fsys *ImageFS, s MCPServer) ([]ToolDef, string) {
	var cands []string
	for _, tok := range append([]string{s.Command}, s.Args...) {
		if sourceExt[path.Ext(tok)] && !strings.Contains(tok, "://") {
			cands = append(cands, tok)
		}
	}
	if len(cands) == 0 {
		return nil, "the server is started without a script in the image (" + path.Base(s.Command) + "), so its tools cannot be read at build time"
	}
	var tools []ToolDef
	missing := false
	for _, c := range cands {
		var tries []string
		if path.IsAbs(c) {
			tries = []string{c}
		} else {
			cwd := path.Dir(s.Source)
			tries = []string{path.Join(cwd, c), path.Join("/workspace", c), path.Join("/app", c), path.Join("/", c)}
		}
		var src string
		for _, t := range tries {
			if data, err := fsys.Read(t); err == nil {
				src = string(data)
				// Sibling modules of the script in the same folder.
				for _, e := range fsys.Under(path.Dir(t)) {
					if e.IsRegular() && sourceExt[path.Ext(e.Path)] && e.Path != t && path.Dir(e.Path) == path.Dir(t) && e.Size < 512<<10 {
						if more, err := fsys.Read(e.Path); err == nil {
							src += "\n" + string(more)
						}
					}
				}
				break
			}
		}
		if src == "" {
			missing = true
			continue
		}
		tools = append(tools, ExtractToolDefs(src)...)
	}
	switch {
	case len(tools) > 0:
		return tools, ""
	case missing:
		return nil, "the server's script is not in the image"
	default:
		return nil, "the server's script declares no tool this build can read statically"
	}
}

// checkHooks verifies ownership of the expected files and the switches.
func checkHooks(fsys *ImageFS, env map[string]string, user string, o ScanOptions) HookChecks {
	hc := HookChecks{RootOwned: true, PhoneHomeOff: true, EnvClean: true}
	for k := range env {
		if unsafeEnv[strings.ToUpper(k)] {
			hc.EnvClean = false
			hc.UnsafeEnv = append(hc.UnsafeEnv, k)
		}
	}
	sort.Strings(hc.UnsafeEnv)
	for _, ef := range o.Expected {
		hf := HookFile{Path: ef.Path}
		e, ok := fsys.Lookup(ef.Path)
		switch {
		case !ok && ef.Optional:
			continue
		case !ok:
			hf.Note, hf.OK = "missing", false
		case e.IsSymlink():
			hf.UID, hf.GID, hf.Mode = e.UID, e.GID, fmt.Sprintf("%04o", e.Mode&0o7777)
			hf.Note, hf.OK = "is a symlink", false
		default:
			hf.UID, hf.GID, hf.Mode = e.UID, e.GID, fmt.Sprintf("%04o", e.Mode&0o7777)
			hf.OK = e.UID == 0 && e.Mode&0o022 == 0
			if !hf.OK {
				hf.Note = "must be owned by root and not writable by group or others"
			}
		}
		if hf.OK {
			if e.Path != path.Clean(ef.Path) {
				hf.OK, hf.Note = false, "reached through a link, real path "+e.Path
			} else if bad := badAncestor(fsys, e.Path); bad != "" {
				hf.OK, hf.Note = false, "parent folder "+bad+" can be changed by a non-root user"
			}
		}
		if !hf.OK {
			hc.RootOwned = false
		}
		hc.Files = append(hc.Files, hf)
	}
	// The agent must not run as root.
	u := strings.TrimSpace(user)
	uf := HookFile{Path: "(image USER)", Mode: "-"}
	switch {
	case u == "" || u == "0" || u == "root" || strings.HasPrefix(u, "0:") || strings.HasPrefix(u, "root:"):
		uf.Note = "the image runs as root; set a non-root USER"
	default:
		uf.OK = true
	}
	if !uf.OK {
		hc.RootOwned = false
	}
	hc.Files = append(hc.Files, uf)

	keys := make([]string, 0, len(o.PhoneHome))
	for k := range o.PhoneHome {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sc := SwitchCheck{Name: k, Want: o.PhoneHome[k], Got: env[k]}
		sc.OK = sc.Got == sc.Want
		if !sc.OK {
			hc.PhoneHomeOff = false
		}
		hc.Switches = append(hc.Switches, sc)
	}
	files := make([]string, 0, len(o.ConfigSwitches))
	for f := range o.ConfigSwitches {
		files = append(files, f)
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := fsys.Read(f)
		for _, want := range o.ConfigSwitches[f] {
			sc := SwitchCheck{Name: f + ": " + want, Want: want}
			if err == nil && strings.Contains(string(data), want) {
				sc.OK, sc.Got = true, want
			}
			if !sc.OK {
				hc.PhoneHomeOff = false
			}
			hc.Switches = append(hc.Switches, sc)
		}
	}
	return hc
}

// badAncestor returns the first parent folder a non-root user can change.
func badAncestor(fsys *ImageFS, p string) string {
	for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
		e, ok := fsys.Lookup(d)
		if !ok {
			continue // implicit parent: root, 0755
		}
		if e.IsSymlink() || e.UID != 0 || e.Mode&0o022 != 0 {
			return d
		}
	}
	return ""
}

// MCPStaticScanner runs mcp-scanner's offline "static" mode over a tools
// JSON file: the YARA analyzer (and the LLM and AI Defense analyzers when
// the environment configures them) read each tool's description, so tool
// poisoning, hidden instructions and exfiltration lures in a tool definition
// are found without starting the server.
type MCPStaticScanner struct {
	// Binary defaults to "mcp-scanner".
	Binary string
	// Analyzers defaults to "yara".
	Analyzers string
	Timeout   time.Duration
	// Env is added to a minimal environment (PATH, HOME, LANG): LLM keys and
	// endpoints for the llm analyzer.
	Env []string
}

func (s *MCPStaticScanner) Name() string               { return "mcp-scanner" }
func (s *MCPStaticScanner) Version() string            { return "static" }
func (s *MCPStaticScanner) SupportedTargets() []string { return []string{"mcp"} }

// Scan implements scanner.Scanner; target is the tools JSON file.
func (s *MCPStaticScanner) Scan(ctx context.Context, target string) (*scanner.ScanResult, error) {
	bin := s.Binary
	if bin == "" {
		bin = "mcp-scanner"
	}
	analyzers := s.Analyzers
	if analyzers == "" {
		analyzers = "yara"
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, "--analyzers", analyzers, "--raw", "static", "--tools", target)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"), "LANG=C.UTF-8"}, s.Env...)
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, max: 4096}
	out, err := cmd.Output()
	res := &scanner.ScanResult{Scanner: s.Name(), Target: target, TargetType: "mcp", Timestamp: time.Now().UTC()}
	if err != nil {
		res.ExitCode = 1
		res.ScanError = "mcp-scanner failed: " + strings.TrimSpace(firstLine(stderr.String(), err.Error()))
		return res, nil
	}
	findings, perr := parseMCPStaticOutput(out)
	if perr != nil {
		res.ExitCode = 1
		res.ScanError = perr.Error()
		return res, nil
	}
	res.Findings = findings
	return res, nil
}

type limitedWriter struct {
	w   *strings.Builder
	max int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.max - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}

func firstLine(s, fallback string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

type mcpStaticItem struct {
	Status   string `json:"status"`
	IsSafe   *bool  `json:"is_safe"`
	ToolName string `json:"tool_name"`
	Findings map[string]struct {
		Severity    string   `json:"severity"`
		ThreatNames []string `json:"threat_names"`
		Summary     string   `json:"threat_summary"`
		Total       int      `json:"total_findings"`
	} `json:"findings"`
}

// parseMCPStaticOutput maps the scanner's raw JSON to findings. Output that
// does not parse is an error, never "no findings".
func parseMCPStaticOutput(out []byte) ([]scanner.Finding, error) {
	out = []byte(strings.TrimSpace(string(out)))
	start := strings.IndexAny(string(out), "[{")
	if start < 0 {
		return nil, errors.New("mcp-scanner printed no JSON")
	}
	var items []mcpStaticItem
	if out[start] == '[' {
		if err := json.Unmarshal(out[start:], &items); err != nil {
			return nil, fmt.Errorf("mcp-scanner output: %w", err)
		}
	} else {
		var one mcpStaticItem
		if err := json.Unmarshal(out[start:], &one); err != nil {
			return nil, fmt.Errorf("mcp-scanner output: %w", err)
		}
		items = []mcpStaticItem{one}
	}
	var fs []scanner.Finding
	for _, it := range items {
		if it.Status != "" && it.Status != "completed" {
			return nil, fmt.Errorf("mcp-scanner reported status %q for tool %q", it.Status, it.ToolName)
		}
		names := make([]string, 0, len(it.Findings))
		for a := range it.Findings {
			names = append(names, a)
		}
		sort.Strings(names)
		for _, an := range names {
			f := it.Findings[an]
			sev := mapSeverity(f.Severity)
			if sev == "" || f.Total == 0 && len(f.ThreatNames) == 0 {
				continue
			}
			title := f.Summary
			if title == "" {
				title = strings.Join(f.ThreatNames, ", ")
			}
			fs = append(fs, scanner.Finding{ID: "mcp-" + an + "-" + it.ToolName, RuleID: "mcp-" + an,
				Severity: sev, Title: title, Description: "tool " + it.ToolName + ": " + strings.Join(f.ThreatNames, ", "),
				Location: "tool:" + it.ToolName, Scanner: "mcp-scanner", Category: "mcp-tool", Tags: f.ThreatNames})
		}
	}
	return fs, nil
}

func mapSeverity(s string) scanner.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	case "INFO":
		return scanner.SeverityInfo
	}
	return ""
}

func sevRank(s scanner.Severity) int {
	switch s {
	case scanner.SeverityCritical:
		return 5
	case scanner.SeverityHigh:
		return 4
	case scanner.SeverityMedium:
		return 3
	case scanner.SeverityLow:
		return 2
	case scanner.SeverityInfo:
		return 1
	}
	return 0
}

// FloorNone turns the severity floor off.
const FloorNone scanner.Severity = "none"

// unsafeEnv are image environment variables that make every process load
// code or settings the template did not scan.
var unsafeEnv = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "NODE_OPTIONS": true, "BASH_ENV": true, "ENV": true,
	"PYTHONSTARTUP": true, "PYTHONPATH": true, "PYTHONHOME": true, "RUBYOPT": true, "RUBYLIB": true, "PERL5OPT": true, "PERL5LIB": true,
	"JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "JDK_JAVA_OPTIONS": true, "DOTNET_STARTUP_HOOKS": true, "GIT_CONFIG_GLOBAL": true,
}
