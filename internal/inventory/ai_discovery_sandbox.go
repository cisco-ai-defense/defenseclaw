// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Sandbox scans (OpenShell sandboxes, Linux and macOS).
//
// The agent in an OpenShell sandbox installs and configures what it likes in
// the sandbox's own home: MCP servers, skills, plugins, CLIs and packages the
// host's scan never sees. The sandbox manager (internal/openshell/manager)
// runs a read-only collector in every ready sandbox, checks what it sent and
// writes it, file by file, into a private tree on the host
// (<data_dir>/sandboxes/<name>/discovery/root: the sandbox's path P at
// root+P). ScanSandboxRoot scans that tree with the per-user scan's detectors
// and the sandbox's processes, executables, environment variable names and
// variables in place of the host's, and without the detectors of
// machine-wide surfaces (applications, IDEs, loopback endpoints, model
// files): nothing of the host leaks into a sandbox's report. Every path the
// report keeps is the sandbox's own. The manager writes the report with the
// sandbox's identity to <data_dir>/sandboxes/<name>/discovery/scan.json
// (SandboxScanRecord), and every full scan of the gateway ingests the records
// (detectSandboxScans): the signals are attributed to the sandbox the record
// names and their hashes re-derived in that sandbox's namespace. A stopped
// sandbox keeps its record, so what was found stays seen; a delete removes
// it, and its signals go.

const (
	// AISourceSandbox is the source of every signal a sandbox scan found.
	AISourceSandbox = "sandbox"
	// SandboxDiscoveryDirName is the directory under
	// <data_dir>/sandboxes/<name> that holds a sandbox's collected tree
	// (SandboxTreeDirName) and its scan record (SandboxScanRecordName).
	SandboxDiscoveryDirName = "discovery"
	SandboxTreeDirName      = "root"
	SandboxScanRecordName   = "scan.json"
	// SandboxScanRecordVersion is the scan record schema.
	SandboxScanRecordVersion = 1
	// MaxSandboxScanSignals bounds one sandbox's report.
	MaxSandboxScanSignals = MaxUserScanSignals

	maxSandboxScanRecordBytes = 16 << 20
	// maxSandboxCollectDetail bounds the sandbox_collect detector error: a
	// detail is at most 1024 bytes (ValidateUserScanReport).
	maxSandboxCollectDetail = 1024
	// sandboxRecordDirName is the sandbox manager's own record directory
	// under <data_dir>/sandboxes, which is no sandbox.
	sandboxRecordDirName = "manager"
	// sandboxSkillDepth is how deep a skills folder is listed: a Codex
	// .system container holds skills one level down, and a Hermes skills
	// root keeps them under category folders (<category>/<skill>/SKILL.md).
	sandboxSkillDepth = 3
)

// sandboxNamePattern accepts the names of sandbox directories the scan
// records live in (DefenseClaw sandbox names are shorter and stricter).
var sandboxNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

// SandboxScanDirForConfig is <data_dir>/sandboxes while sandboxes are on, and
// empty otherwise and on Windows, where sandboxes do not run.
func SandboxScanDirForConfig(cfg *config.Config) string {
	if cfg == nil || !cfg.OpenShell.Enabled || runtime.GOOS == "windows" || cfg.DataDir == "" {
		return ""
	}
	return filepath.Join(cfg.DataDir, "sandboxes")
}

// SandboxScanOptions are the discovery settings a sandbox scan runs with.
type SandboxScanOptions struct {
	Mode                    string
	IncludeShellHistory     bool
	IncludePackageManifests bool
	IncludeEnvVarNames      bool
	IncludeNetworkDomains   bool
	MaxFilesPerScan         int
	MaxFileBytes            int64
	StoreRawLocalPaths      bool
}

// SandboxScanOptionsFromConfig keeps the privacy settings and bounds of
// ai_discovery.
func SandboxScanOptionsFromConfig(cfg *config.Config) SandboxScanOptions {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	ad := cfg.AIDiscovery
	opts := SandboxScanOptions{
		Mode:                    ad.Mode,
		IncludeShellHistory:     ad.IncludeShellHistory,
		IncludePackageManifests: ad.IncludePackageManifests,
		IncludeEnvVarNames:      ad.IncludeEnvVarNames,
		IncludeNetworkDomains:   ad.IncludeNetworkDomains,
		MaxFilesPerScan:         ad.MaxFilesPerScan,
		MaxFileBytes:            int64(ad.MaxFileBytes),
		StoreRawLocalPaths:      ad.StoreRawLocalPaths,
	}
	if opts.MaxFilesPerScan <= 0 {
		opts.MaxFilesPerScan = 1000
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 512 * 1024
	}
	return opts
}

// SandboxProcess is one workload process of a sandbox, as the collector
// read it: every field is the sandbox's, and agent-controlled.
type SandboxProcess struct {
	PID  int
	PPID int
	Comm string
	// Argv0 is the process's argv[0], and Argv0Target the sandbox path it
	// resolves to when it names a file (a symlinked launcher's target).
	Argv0       string
	Argv0Target string
	// Exe is the executable /proc/<pid>/exe names.
	Exe       string
	StartedAt time.Time
}

// SandboxScan is what one sandbox scan reads.
type SandboxScan struct {
	// Root is the host directory holding the collected files: the sandbox's
	// file P is Root+P. Empty when only planning (PlanSandboxScan).
	Root string
	// Home is the workload's home (/sandbox) and Workspace the project
	// folder as the sandbox sees it (/work/<project>, /sandbox/work/<repo>;
	// empty: none). Both absolute and clean.
	Home      string
	Workspace string
	// Processes are the workload's processes.
	Processes []SandboxProcess
	// Executables maps a catalog binary name to the sandbox path of the
	// executable the workload's PATH finds for it.
	Executables map[string]string
	// EnvNames are the names, never the values, of the environment
	// variables of the workload's processes.
	EnvNames []string
	// Variables resolve the catalog's $VAR paths ($CODEX_HOME, $HERMES_HOME)
	// to sandbox paths. A candidate naming one that is not set is left out.
	Variables map[string]string
	// Problems are the collection's own shortfalls (a bound it stopped at,
	// records it refused); a report with any is partial.
	Problems []string
}

// SandboxDir is a folder a sandbox scan lists, Depth levels deep.
type SandboxDir struct {
	Path  string
	Depth int
}

// SandboxCandidates are the sandbox paths a sandbox scan looks at, which is
// what the collector reads: Stat paths whose presence counts (config paths),
// Read files a detector parses (MCP configs), Dirs whose entries it lists
// (skills, rules, plugins), History files whose tail it reads, Walk roots
// searched for the package manifests Manifests names (ManifestSuffixes too;
// SkipDirs are not entered), and the Binaries an executable lookup tries.
type SandboxCandidates struct {
	Stat, Read, History []string
	Dirs                []SandboxDir
	Walk                []string
	Manifests           []string
	ManifestSuffixes    []string
	SkipDirs            []string
	Binaries            []string
}

// sandboxFacts stand in for the host's in a sandbox scan
// (ContinuousDiscoveryService.sandbox). Paths are host paths under the
// collected tree.
type sandboxFacts struct {
	processes   []processInfo
	executables map[string]string
	envNames    []string
	variables   map[string]string
	// hermesSkills is the sandbox's Hermes skills root.
	hermesSkills string
}

// PlanSandboxScan plans a sandbox scan: the sandbox paths the detectors
// read for scan's Home, Workspace and Variables.
func PlanSandboxScan(scan SandboxScan, opts SandboxScanOptions, catalog []AISignature) (SandboxCandidates, error) {
	scan.Root = ""
	svc, err := newSandboxScanService(scan, opts, catalog)
	if err != nil {
		return SandboxCandidates{}, err
	}
	var out SandboxCandidates
	seen := map[string]bool{}
	add := func(list *[]string, kind string, paths ...string) {
		for _, p := range paths {
			if p == "" || seen[kind+"\x00"+p] {
				continue
			}
			seen[kind+"\x00"+p] = true
			*list = append(*list, p)
		}
	}
	dirs := map[string]int{}
	addDir := func(depth int, paths ...string) {
		for _, p := range paths {
			if depth > dirs[p] {
				dirs[p] = depth
			}
		}
	}
	for _, sig := range catalog {
		for _, candidate := range sig.ConfigPaths {
			add(&out.Stat, "stat", svc.expandCandidatePath(candidate)...)
		}
		for _, candidate := range sig.MCPPaths {
			add(&out.Read, "read", svc.expandCandidatePath(candidate)...)
		}
		for _, candidate := range sig.SkillPaths {
			addDir(sandboxSkillDepth, svc.expandCandidatePath(candidate)...)
		}
		for _, list := range [][]string{sig.RulePaths, sig.PluginPaths} {
			for _, candidate := range list {
				addDir(1, svc.expandCandidatePath(candidate)...)
			}
		}
		for _, bin := range sig.BinaryNames {
			if bin = strings.TrimSpace(bin); bin != "" && !strings.ContainsAny(bin, `/\`) {
				add(&out.Binaries, "bin", bin)
			}
		}
	}
	for p, depth := range dirs {
		out.Dirs = append(out.Dirs, SandboxDir{Path: p, Depth: depth})
	}
	sort.Slice(out.Dirs, func(i, j int) bool { return out.Dirs[i].Path < out.Dirs[j].Path })
	if opts.IncludeShellHistory {
		for _, home := range svc.homesToScan() {
			add(&out.History, "history",
				path.Join(home, ".zsh_history"), path.Join(home, ".bash_history"), path.Join(home, ".config", "fish", "fish_history"))
		}
	}
	if opts.IncludePackageManifests && scan.Workspace != "" {
		out.Walk = []string{scan.Workspace}
		for name := range packageManifestNames {
			out.Manifests = append(out.Manifests, name)
		}
		sort.Strings(out.Manifests)
		out.ManifestSuffixes = []string{".csproj", ".fsproj", ".vbproj"}
		out.SkipDirs = []string{".git", ".cache", "cache", "dist", "build", "target", "__pycache__", "library"}
	}
	return out, nil
}

// ScanSandboxRoot runs one full scan of a sandbox's collected tree with no
// state store, history or telemetry. It keeps only evidence inside the
// tree, and reports it with the sandbox's own paths.
func ScanSandboxRoot(ctx context.Context, scan SandboxScan, opts SandboxScanOptions, catalog []AISignature) (AIDiscoveryReport, error) {
	start := time.Now()
	if scan.Root == "" || !filepath.IsAbs(scan.Root) {
		return AIDiscoveryReport{}, errors.New("a sandbox scan needs the absolute host path of its collected tree")
	}
	svc, err := newSandboxScanService(scan, opts, catalog)
	if err != nil {
		return AIDiscoveryReport{}, err
	}
	root := filepath.Clean(scan.Root)
	scanID := newScanID()
	signals, stats := svc.scanSignals(ctx, scanID, &aiDiscoveryScanObservation{}, true, nil)
	out := make([]AISignal, 0, len(signals))
	seen := time.Now().UTC()
	for _, sig := range signals {
		evidence, ok := sandboxEvidence(sig.Evidence, root, opts.StoreRawLocalPaths)
		if !ok {
			continue
		}
		sig.Evidence = evidence
		if len(sig.Evidence) > maxEvidencePerSignal {
			sig.Evidence = sig.Evidence[:maxEvidencePerSignal]
			sig.Partial, sig.CoverageReason = true, CoverageReasonCapExceeded
		}
		sig.PathHashes = boundedUserScanList(sig.PathHashes)
		sig.Basenames = boundedUserScanList(sig.Basenames)
		sig.SignalID = stableSignalID(sig.Fingerprint)
		sig.Source = AISourceSandbox
		sig.State = AIStateSeen
		sig.UserID, sig.UserName = "", ""
		if sig.Runtime != nil {
			runtimeInfo := *sig.Runtime
			runtimeInfo.User = ""
			runtimeInfo.OtherInstances = append([]ProcessRuntime(nil), runtimeInfo.OtherInstances...)
			for i := range runtimeInfo.OtherInstances {
				runtimeInfo.OtherInstances[i].User = ""
			}
			sig.Runtime = &runtimeInfo
		}
		if sig.FirstSeen.IsZero() {
			sig.FirstSeen = seen
		}
		if sig.LastSeen.IsZero() {
			sig.LastSeen = seen
		}
		out = append(out, sig)
	}
	if len(out) > MaxSandboxScanSignals {
		out = out[:MaxSandboxScanSignals]
		stats.Errors++
		stats.DetectorErrors["sandbox_scan"] = "signal limit reached"
	}
	if len(scan.Problems) > 0 {
		stats.Errors++
		// Within what a report may carry (ValidateUserScanReport).
		detail := strings.Join(scan.Problems, "; ")
		if len(detail) > maxSandboxCollectDetail {
			detail = strings.ToValidUTF8(detail[:maxSandboxCollectDetail-3], "") + "..."
		}
		stats.DetectorErrors["sandbox_collect"] = detail
	}
	if ctx.Err() != nil {
		stats.Errors++
		stats.DetectorErrors["sandbox_scan"] = "scan time limit reached"
	}
	summary := AIDiscoverySummary{
		ScanID:            scanID,
		ScannedAt:         time.Now().UTC(),
		DurationMs:        time.Since(start).Milliseconds(),
		PrivacyMode:       svc.opts.Mode,
		Source:            AISourceSandbox,
		Result:            "ok",
		TotalSignals:      len(out),
		ActiveSignals:     len(out),
		FilesScanned:      stats.FilesScanned,
		DedupeSuppressed:  stats.DedupeSuppressed,
		Errors:            stats.Errors,
		DetectorErrors:    stats.DetectorErrors,
		DetectorDurations: stats.DetectorDurations,
	}
	if stats.Errors > 0 {
		summary.Result = "partial"
	}
	return AIDiscoveryReport{Summary: summary, Signals: out}, nil
}

// newSandboxScanService is the scanner of one sandbox tree (scan.Root; empty
// plans in the sandbox's own paths). Its only roots are absolute: a
// relative candidate resolves in the project folder, else the home, never in
// the working directory of the daemon.
func newSandboxScanService(scan SandboxScan, opts SandboxScanOptions, catalog []AISignature) (*ContinuousDiscoveryService, error) {
	for _, p := range []string{scan.Home, scan.Workspace} {
		if p != "" && (!path.IsAbs(p) || path.Clean(p) != p) {
			return nil, fmt.Errorf("sandbox scan path %q is not absolute and clean", p)
		}
	}
	if scan.Home == "" {
		return nil, errors.New("a sandbox scan needs the sandbox's home")
	}
	host := func(p string) string {
		if scan.Root == "" {
			return p
		}
		return filepath.Join(filepath.Clean(scan.Root), filepath.FromSlash(p))
	}
	home := host(scan.Home)
	root := home
	if scan.Workspace != "" {
		root = host(scan.Workspace)
	}
	facts := &sandboxFacts{executables: map[string]string{}, variables: map[string]string{}}
	for name, p := range scan.Executables {
		if path.IsAbs(p) && path.Clean(p) == p {
			facts.executables[name] = host(p)
		}
	}
	for name, p := range scan.Variables {
		if path.IsAbs(p) && path.Clean(p) == p {
			facts.variables[name] = host(p)
		}
	}
	hermesHome := path.Join(scan.Home, ".hermes")
	if v := scan.Variables["HERMES_HOME"]; path.IsAbs(v) && path.Clean(v) == v {
		hermesHome = v
	}
	facts.hermesSkills = host(path.Join(hermesHome, "skills"))
	facts.envNames = append(facts.envNames, scan.EnvNames...)
	for _, p := range scan.Processes {
		facts.processes = append(facts.processes, sandboxProcessInfo(p))
	}
	svc := &ContinuousDiscoveryService{
		opts: normalizeAIDiscoveryOptions(AIDiscoveryOptions{
			Enabled:                 true,
			Mode:                    opts.Mode,
			ScanRoots:               []string{root},
			IncludeShellHistory:     opts.IncludeShellHistory,
			IncludePackageManifests: opts.IncludePackageManifests && scan.Workspace != "",
			IncludeEnvVarNames:      opts.IncludeEnvVarNames,
			IncludeNetworkDomains:   opts.IncludeNetworkDomains,
			MaxFilesPerScan:         opts.MaxFilesPerScan,
			MaxFileBytes:            opts.MaxFileBytes,
			// Raw paths map the evidence back to the sandbox's own paths;
			// they leave this process only when the administrator keeps them.
			StoreRawLocalPaths: true,
			// Never written: this service has no state store.
			DataDir:      filepath.Join(home, ".defenseclaw"),
			HomeDir:      home,
			HomeDirs:     []string{home},
			IDEInventory: config.IDEInventoryOff,
		}),
		catalog: catalog,
		sandbox: facts,
	}
	return svc, nil
}

// sandboxProcessInfo is a sandbox process as the process detector reads
// one: argv[0] and what it resolves to count only where they differ from
// comm (see procArgv0).
func sandboxProcessInfo(p SandboxProcess) processInfo {
	info := processInfo{PID: p.PID, PPID: p.PPID, Comm: p.Comm, StartedAt: p.StartedAt}
	if raw := strings.TrimSpace(p.Argv0); raw != "" {
		if name := strings.ToLower(path.Base(raw)); name != "." && name != "/" && name != p.Comm {
			info.Argv0 = name
		}
	}
	if target := strings.TrimSpace(p.Argv0Target); target != "" {
		name := strings.ToLower(path.Base(target))
		if name != "." && name != "/" && name != p.Comm && name != info.Argv0 && name != strings.ToLower(path.Base(p.Argv0)) {
			info.Argv0Target = name
		}
	}
	return info
}

// sandboxEvidence maps each evidence row's raw path from the collected tree
// at root back to the sandbox's own path, and drops the raw paths unless
// keep. A row naming a host path outside the tree rejects the signal.
func sandboxEvidence(evidence []AIEvidence, root string, keep bool) ([]AIEvidence, bool) {
	out := make([]AIEvidence, len(evidence))
	for i, ev := range evidence {
		if ev.RawPath != "" {
			rel, err := filepath.Rel(root, filepath.Clean(ev.RawPath))
			if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
				return nil, false
			}
			ev.RawPath = "/" + filepath.ToSlash(rel)
			if !keep {
				ev.RawPath = ""
			}
		}
		out[i] = ev
	}
	return out, true
}

// The facts a scan reads: the host's, or in a sandbox scan the sandbox's.

func (s *ContinuousDiscoveryService) processes() ([]processInfo, error) {
	if s.sandbox != nil {
		return append([]processInfo(nil), s.sandbox.processes...), nil
	}
	return processSnapshot()
}

func (s *ContinuousDiscoveryService) lookPath(name string) (string, error) {
	if s.sandbox != nil {
		if p, ok := s.sandbox.executables[name]; ok {
			return p, nil
		}
		return "", exec.ErrNotFound
	}
	return exec.LookPath(name)
}

// environment is the process environment as KEY=VALUE pairs; a sandbox
// scan knows the names only.
func (s *ContinuousDiscoveryService) environment() []string {
	if s.sandbox != nil {
		out := make([]string, 0, len(s.sandbox.envNames))
		for _, name := range s.sandbox.envNames {
			out = append(out, name+"=")
		}
		return out
	}
	return os.Environ()
}

func (s *ContinuousDiscoveryService) variable(name string) (string, bool) {
	if s.sandbox != nil {
		value, ok := s.sandbox.variables[name]
		return value, ok
	}
	return platformDiscoveryVariable(name, s.opts.HomeDir)
}

// hostOnlyDetector reports a detector of a machine-wide surface, which a
// sandbox scan does not run.
func (s *ContinuousDiscoveryService) hostOnlyDetector(name string) bool {
	if s.sandbox == nil {
		return false
	}
	switch name {
	case "application", "editor_extension", "local_endpoint", "local_model_api", "model_file":
		return true
	}
	return false
}

// SandboxScanRecord is one sandbox's scan record
// (<data_dir>/sandboxes/<name>/discovery/scan.json), written by the sandbox
// manager from ScanSandboxRoot's report.
type SandboxScanRecord struct {
	Version     int               `json:"version"`
	SandboxID   string            `json:"sandbox_id,omitempty"`
	SandboxName string            `json:"sandbox_name"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Report      AIDiscoveryReport `json:"report"`
}

// SandboxScanRecordPath is the scan record of sandbox name under
// sandboxesDir (<data_dir>/sandboxes).
func SandboxScanRecordPath(sandboxesDir, name string) string {
	return filepath.Join(sandboxesDir, name, SandboxDiscoveryDirName, SandboxScanRecordName)
}

// WriteSandboxScanRecord writes a scan record owner-only, atomically.
func WriteSandboxScanRecord(path string, record SandboxScanRecord) error {
	record.Version = SandboxScanRecordVersion
	if !sandboxNamePattern.MatchString(record.SandboxName) || record.SandboxName == sandboxRecordDirName {
		return fmt.Errorf("sandbox scan record: invalid sandbox name %q", record.SandboxName)
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > maxSandboxScanRecordBytes {
		return fmt.Errorf("sandbox scan record of %s exceeds %d bytes", record.SandboxName, maxSandboxScanRecordBytes)
	}
	return safefile.WritePrivate(path, data)
}

// ReadSandboxScanRecord reads one scan record: a regular file within the
// size limit, in the current schema.
func ReadSandboxScanRecord(path string) (SandboxScanRecord, error) {
	var record SandboxScanRecord
	data, err := safefile.ReadRegularFileBounded(path, maxSandboxScanRecordBytes)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("parse record: %w", err)
	}
	if record.Version != SandboxScanRecordVersion {
		return record, fmt.Errorf("unsupported record version %d", record.Version)
	}
	return record, nil
}

// detectSandboxScans reads every sandbox's scan record. A record that does
// not name the sandbox it is filed under, or does not pass the per-user
// report checks, is refused.
func (s *ContinuousDiscoveryService) detectSandboxScans() ([]AISignal, int, map[string]string) {
	entries, err := os.ReadDir(s.opts.SandboxScanDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, map[string]string{"sandbox_scan": err.Error()}
	}
	var out []AISignal
	files := 0
	errs := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || name == sandboxRecordDirName || !sandboxNamePattern.MatchString(name) {
			continue
		}
		record, err := ReadSandboxScanRecord(SandboxScanRecordPath(s.opts.SandboxScanDir, name))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && record.SandboxName != name {
			err = errors.New("the record names another sandbox")
		}
		if err == nil && (len(record.SandboxID) > maxUserScanField || !userScanText(record.SandboxID, maxUserScanField) || strings.ContainsAny(record.SandboxID, `/\`)) {
			err = errors.New("the record names no valid sandbox id")
		}
		if err == nil {
			err = ValidateUserScanReport(record.Report, s.catalog)
		}
		if err != nil {
			errs["sandbox_scan:"+name] = err.Error()
			continue
		}
		files += record.Report.Summary.FilesScanned
		if record.Report.Summary.Result != "ok" {
			errs["sandbox_scan:"+name] = "partial scan: " + userScanDetectorNames(record.Report.Summary.DetectorErrors)
		}
		for _, sig := range record.Report.Signals {
			out = append(out, s.attributeSandboxSignal(sig, record.SandboxID, name))
		}
	}
	return out, files, errs
}

// sandboxScanNamespace re-derives a sandbox scan's digest in the sandbox's
// namespace, so the same file in two sandboxes, or in a sandbox and on the
// host, stays distinct.
func sandboxScanNamespace(id string) func(string) string {
	return func(value string) string {
		if value == "" {
			return ""
		}
		input := "ai-discovery/sandbox/v1\x00" + id + "\x00" + value
		if key := currentPathHashKey(); len(key) > 0 {
			return "hmac-sha256:" + keyedHashHex(key, input)
		}
		return "sha256:" + hashHex(input)
	}
}

// attributeSandboxSignal binds a sandbox scan's signal to its sandbox (id,
// or the name while OpenShell has given it none), in that sandbox's hash
// namespace. A sandbox's processes run as its workload, never as a host
// account.
func (s *ContinuousDiscoveryService) attributeSandboxSignal(sig AISignal, id, name string) AISignal {
	scope := id
	if scope == "" {
		scope = "name:" + name
	}
	namespace := sandboxScanNamespace(scope)
	evidence := make([]AIEvidence, len(sig.Evidence))
	for i, ev := range sig.Evidence {
		ev.PathHash = namespace(ev.PathHash)
		ev.WorkspaceHash = namespace(ev.WorkspaceHash)
		if !s.opts.StoreRawLocalPaths {
			ev.RawPath = ""
		}
		evidence[i] = ev
	}
	sig.Evidence = evidence
	pathHashes := make([]string, 0, len(sig.PathHashes))
	for _, value := range sig.PathHashes {
		pathHashes = append(pathHashes, namespace(value))
	}
	sort.Strings(pathHashes)
	sig.PathHashes = pathHashes
	sig.WorkspaceHash = namespace(sig.WorkspaceHash)
	sig.EvidenceHash = hashEvidence(evidence)
	sig.Fingerprint = namespace(sig.Fingerprint)
	sig.SignalID = stableSignalID(sig.Fingerprint)
	sig.Source = AISourceSandbox
	sig.SandboxID, sig.SandboxName = id, name
	sig.UserID, sig.UserName = "", ""
	sig.ModelAPISourceHash = ""
	if sig.Runtime != nil {
		runtimeInfo := *sig.Runtime
		runtimeInfo.User = ""
		runtimeInfo.OtherInstances = nil
		for _, other := range sig.Runtime.OtherInstances {
			other.User = ""
			other.OtherInstances = nil
			runtimeInfo.OtherInstances = append(runtimeInfo.OtherInstances, other)
		}
		sig.Runtime = &runtimeInfo
	}
	sig.Model = nil
	return sig
}
