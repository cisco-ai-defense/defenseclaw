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

package inventory

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	SignalSupportedConnector = "supported_connector"
	SignalAICLI              = "ai_cli"
	SignalActiveProcess      = "active_process"
	SignalEditorExtension    = "editor_extension"
	SignalMCPServer          = "mcp_server"
	SignalSkill              = "skill"
	SignalRule               = "rule"
	SignalPlugin             = "plugin"
	SignalPackageDependency  = "package_dependency"
	SignalEnvVarName         = "env_var_name"
	SignalShellHistoryMatch  = "shell_history_match"
	SignalProviderDomain     = "provider_domain"
	SignalWorkspaceArtifact  = "workspace_artifact"
	SignalDesktopApp         = "desktop_app"
	SignalLocalAIEndpoint    = "local_ai_endpoint"
)

const (
	AIStateNew     = "new"
	AIStateSeen    = "seen"
	AIStateChanged = "changed"
	AIStateGone    = "gone"
)

const aiDiscoveryStateVersion = 1

var allowedAISignalCategories = map[string]bool{
	SignalSupportedConnector: true,
	SignalAICLI:              true,
	SignalActiveProcess:      true,
	SignalEditorExtension:    true,
	SignalMCPServer:          true,
	SignalSkill:              true,
	SignalRule:               true,
	SignalPlugin:             true,
	SignalPackageDependency:  true,
	SignalEnvVarName:         true,
	SignalShellHistoryMatch:  true,
	SignalProviderDomain:     true,
	SignalWorkspaceArtifact:  true,
	SignalDesktopApp:         true,
	SignalLocalAIEndpoint:    true,
}

// AIDiscoveryOptions is the sidecar-local runtime view of config.AIDiscoveryConfig.
type AIDiscoveryOptions struct {
	Enabled                 bool
	Mode                    string
	ScanInterval            time.Duration
	ProcessInterval         time.Duration
	ScanRoots               []string
	IncludeShellHistory     bool
	IncludePackageManifests bool
	IncludeEnvVarNames      bool
	IncludeNetworkDomains   bool
	MaxFilesPerScan         int
	MaxFileBytes            int64
	EmitOTel                bool
	StoreRawLocalPaths      bool
	DataDir                 string
	HomeDir                 string
}

// AIEvidence is an internal normalized evidence record. RawPath is never
// exported outside the local state file, and only when StoreRawLocalPaths is
// explicitly enabled.
type AIEvidence struct {
	Type          string `json:"type"`
	Basename      string `json:"basename,omitempty"`
	PathHash      string `json:"path_hash,omitempty"`
	ValueHash     string `json:"value_hash,omitempty"`
	WorkspaceHash string `json:"workspace_hash,omitempty"`
	RawPath       string `json:"raw_path,omitempty"`
}

// AISignal is the sanitized signal shape returned by API responses and used
// in gateway/OTel telemetry. It carries hashes and basenames, never raw file
// paths, command lines, prompt text, or secret values.
type AISignal struct {
	Fingerprint        string       `json:"fingerprint"`
	SignalID           string       `json:"signal_id"`
	SignatureID        string       `json:"signature_id"`
	Name               string       `json:"name"`
	Vendor             string       `json:"vendor"`
	Product            string       `json:"product"`
	Category           string       `json:"category"`
	SupportedConnector string       `json:"supported_connector,omitempty"`
	Confidence         float64      `json:"confidence"`
	State              string       `json:"state"`
	Detector           string       `json:"detector"`
	Source             string       `json:"source"`
	EvidenceTypes      []string     `json:"evidence_types,omitempty"`
	PathHashes         []string     `json:"path_hashes,omitempty"`
	Basenames          []string     `json:"basenames,omitempty"`
	WorkspaceHash      string       `json:"workspace_hash,omitempty"`
	Version            string       `json:"version,omitempty"`
	FirstSeen          time.Time    `json:"first_seen"`
	LastSeen           time.Time    `json:"last_seen"`
	EvidenceHash       string       `json:"-"`
	Evidence           []AIEvidence `json:"-"`
}

type AIDiscoverySummary struct {
	ScanID            string         `json:"scan_id"`
	ScannedAt         time.Time      `json:"scanned_at"`
	DurationMs        int64          `json:"duration_ms"`
	PrivacyMode       string         `json:"privacy_mode"`
	Source            string         `json:"source"`
	Result            string         `json:"result"`
	TotalSignals      int            `json:"total_signals"`
	ActiveSignals     int            `json:"active_signals"`
	NewSignals        int            `json:"new_signals"`
	ChangedSignals    int            `json:"changed_signals"`
	GoneSignals       int            `json:"gone_signals"`
	FilesScanned      int            `json:"files_scanned"`
	DedupeSuppressed  int            `json:"dedupe_suppressed"`
	Errors            int            `json:"errors"`
	DetectorDurations map[string]int `json:"detector_durations_ms,omitempty"`
}

type AIDiscoveryReport struct {
	Summary AIDiscoverySummary `json:"summary"`
	Signals []AISignal         `json:"signals"`
}

type aiStoredSignal struct {
	AISignal
	RawPaths []string `json:"raw_paths,omitempty"`
}

type aiStateFile struct {
	Version   int                       `json:"version"`
	UpdatedAt time.Time                 `json:"updated_at"`
	Signals   map[string]aiStoredSignal `json:"signals"`
}

// ContinuousDiscoveryService owns device-level AI visibility. It is deliberately
// sidecar-scoped so CLI/TUI/API callers all see the same state and OTel fanout.
type ContinuousDiscoveryService struct {
	opts    AIDiscoveryOptions
	catalog []AISignature
	store   *AIStateStore
	otel    *telemetry.Provider
	events  *gatewaylog.Writer

	mu       sync.RWMutex
	last     AIDiscoveryReport
	lastErr  error
	triggers chan chan scanResponse
}

type scanResponse struct {
	report AIDiscoveryReport
	err    error
}

// NewContinuousDiscoveryService builds a sidecar discovery service from the
// full gateway config. It returns nil when ai_discovery.enabled is false.
func NewContinuousDiscoveryService(cfg *config.Config, otel *telemetry.Provider, events *gatewaylog.Writer) (*ContinuousDiscoveryService, error) {
	if cfg == nil || !cfg.AIDiscovery.Enabled {
		return nil, nil
	}
	catalog, err := LoadAISignatures()
	if err != nil {
		return nil, err
	}
	opts := AIDiscoveryOptionsFromConfig(cfg)
	return NewContinuousDiscoveryServiceWithOptions(opts, catalog, otel, events), nil
}

func NewContinuousDiscoveryServiceWithOptions(opts AIDiscoveryOptions, catalog []AISignature, otel *telemetry.Provider, events *gatewaylog.Writer) *ContinuousDiscoveryService {
	opts = normalizeAIDiscoveryOptions(opts)
	return &ContinuousDiscoveryService{
		opts:     opts,
		catalog:  catalog,
		store:    NewAIStateStore(filepath.Join(opts.DataDir, "ai_discovery_state.json")),
		otel:     otel,
		events:   events,
		triggers: make(chan chan scanResponse, 1),
	}
}

func AIDiscoveryOptionsFromConfig(cfg *config.Config) AIDiscoveryOptions {
	home, _ := os.UserHomeDir()
	ad := cfg.AIDiscovery
	return normalizeAIDiscoveryOptions(AIDiscoveryOptions{
		Enabled:                 ad.Enabled,
		Mode:                    ad.Mode,
		ScanInterval:            time.Duration(ad.ScanIntervalMin) * time.Minute,
		ProcessInterval:         time.Duration(ad.ProcessIntervalSec) * time.Second,
		ScanRoots:               append([]string{}, ad.ScanRoots...),
		IncludeShellHistory:     ad.IncludeShellHistory,
		IncludePackageManifests: ad.IncludePackageManifests,
		IncludeEnvVarNames:      ad.IncludeEnvVarNames,
		IncludeNetworkDomains:   ad.IncludeNetworkDomains,
		MaxFilesPerScan:         ad.MaxFilesPerScan,
		MaxFileBytes:            int64(ad.MaxFileBytes),
		EmitOTel:                ad.EmitOTel,
		StoreRawLocalPaths:      ad.StoreRawLocalPaths,
		DataDir:                 cfg.DataDir,
		HomeDir:                 home,
	})
}

func normalizeAIDiscoveryOptions(opts AIDiscoveryOptions) AIDiscoveryOptions {
	if opts.Mode == "" {
		opts.Mode = "enhanced"
	}
	opts.Mode = normalizeAIID(opts.Mode)
	if opts.ScanInterval <= 0 {
		opts.ScanInterval = 5 * time.Minute
	}
	if opts.ProcessInterval <= 0 {
		opts.ProcessInterval = 60 * time.Second
	}
	if opts.MaxFilesPerScan <= 0 {
		opts.MaxFilesPerScan = 1000
	}
	if opts.MaxFileBytes <= 0 {
		opts.MaxFileBytes = 512 * 1024
	}
	if opts.DataDir == "" {
		opts.DataDir = config.DefaultDataPath()
	}
	if opts.HomeDir == "" {
		opts.HomeDir, _ = os.UserHomeDir()
	}
	if len(opts.ScanRoots) == 0 && opts.HomeDir != "" {
		opts.ScanRoots = []string{"~"}
	}
	return opts
}

func (s *ContinuousDiscoveryService) Run(ctx context.Context) error {
	if s == nil {
		return nil
	}
	_, _ = s.runScan(ctx, true, "startup")

	fullTicker := time.NewTicker(s.opts.ScanInterval)
	defer fullTicker.Stop()
	processTicker := time.NewTicker(s.opts.ProcessInterval)
	defer processTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-fullTicker.C:
			_, _ = s.runScan(ctx, true, "scheduled")
		case <-processTicker.C:
			_, _ = s.runScan(ctx, false, "process")
		case resp := <-s.triggers:
			report, err := s.runScan(ctx, true, "api")
			resp <- scanResponse{report: report, err: err}
		}
	}
}

func (s *ContinuousDiscoveryService) ScanNow(ctx context.Context) (AIDiscoveryReport, error) {
	if s == nil {
		return AIDiscoveryReport{}, errors.New("ai discovery disabled")
	}
	resp := make(chan scanResponse, 1)
	select {
	case s.triggers <- resp:
	case <-ctx.Done():
		return AIDiscoveryReport{}, ctx.Err()
	default:
		return s.runScan(ctx, true, "api")
	}
	select {
	case out := <-resp:
		return out.report, out.err
	case <-ctx.Done():
		return AIDiscoveryReport{}, ctx.Err()
	}
}

func (s *ContinuousDiscoveryService) Snapshot() AIDiscoveryReport {
	if s == nil {
		return AIDiscoveryReport{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneAIDiscoveryReport(s.last)
}

func (s *ContinuousDiscoveryService) LastError() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastErr
}

func (s *ContinuousDiscoveryService) runScan(ctx context.Context, full bool, source string) (AIDiscoveryReport, error) {
	start := time.Now()
	scanID := newScanID()
	ctx, span := s.otel.Tracer().Start(ctx, "defenseclaw.ai.discovery",
		trace.WithAttributes(
			attribute.String("defenseclaw.ai.discovery.scan_id", scanID),
			attribute.String("defenseclaw.ai.discovery.source", source),
			attribute.String("defenseclaw.ai.discovery.privacy_mode", s.opts.Mode),
		),
	)
	defer span.End()

	prev, _ := s.store.Load()
	signals, stats := s.scanSignals(ctx, full)
	report := s.classifyAndPersist(scanID, source, start, signals, stats, prev, full)
	if stats.Errors > 0 {
		span.SetStatus(codes.Error, "one or more detectors failed")
	}
	span.SetAttributes(
		attribute.Int("defenseclaw.ai.discovery.signals", report.Summary.TotalSignals),
		attribute.Int("defenseclaw.ai.discovery.active_signals", report.Summary.ActiveSignals),
		attribute.Int("defenseclaw.ai.discovery.files_scanned", report.Summary.FilesScanned),
	)

	s.mu.Lock()
	s.last = cloneAIDiscoveryReport(report)
	s.lastErr = nil
	s.mu.Unlock()

	if s.opts.EmitOTel {
		s.emitTelemetry(ctx, report)
	}
	s.emitGatewayEvents(ctx, report)
	return report, nil
}

type scanStats struct {
	FilesScanned      int
	Errors            int
	DedupeSuppressed  int
	DetectorDurations map[string]int
}

func (s *ContinuousDiscoveryService) scanSignals(ctx context.Context, full bool) ([]AISignal, scanStats) {
	stats := scanStats{DetectorDurations: map[string]int{}}
	var signals []AISignal
	seen := map[string]bool{}

	add := func(in []AISignal) {
		for _, sig := range in {
			if !allowedAISignalCategories[sig.Category] {
				continue
			}
			if seen[sig.Fingerprint] {
				stats.DedupeSuppressed++
				continue
			}
			seen[sig.Fingerprint] = true
			signals = append(signals, sig)
		}
	}
	measure := func(name string, fn func() ([]AISignal, int, error)) {
		start := time.Now()
		_, child := s.otel.Tracer().Start(ctx, "defenseclaw.ai.discovery.detector",
			trace.WithAttributes(attribute.String("defenseclaw.ai.discovery.detector", name)))
		out, files, err := fn()
		child.SetAttributes(attribute.Int("defenseclaw.ai.discovery.signals", len(out)))
		if files > 0 {
			child.SetAttributes(attribute.Int("defenseclaw.ai.discovery.files_scanned", files))
		}
		if err != nil {
			stats.Errors++
			child.RecordError(err)
			child.SetStatus(codes.Error, err.Error())
		}
		child.End()
		stats.FilesScanned += files
		stats.DetectorDurations[name] = int(time.Since(start).Milliseconds())
		add(out)
	}

	measure("process", func() ([]AISignal, int, error) { return s.detectProcesses(), 0, nil })
	if !full {
		sortAISignals(signals)
		return signals, stats
	}

	measure("config", func() ([]AISignal, int, error) { return s.detectConfigPaths(), 0, nil })
	measure("binary", func() ([]AISignal, int, error) { return s.detectBinaries(), 0, nil })
	measure("application", func() ([]AISignal, int, error) { return s.detectApplications(), 0, nil })
	measure("editor_extension", func() ([]AISignal, int, error) { return s.detectEditorExtensions(), 0, nil })
	measure("mcp", func() ([]AISignal, int, error) { return s.detectMCPPaths(), 0, nil })
	if s.opts.IncludeNetworkDomains {
		measure("local_endpoint", func() ([]AISignal, int, error) { return s.detectLocalEndpoints(), 0, nil })
	}
	if s.opts.IncludeEnvVarNames {
		measure("env", func() ([]AISignal, int, error) { return s.detectEnvVars(), 0, nil })
	}
	if s.opts.IncludePackageManifests {
		measure("package_manifest", func() ([]AISignal, int, error) { return s.detectPackageManifests() })
	}
	if s.opts.IncludeShellHistory {
		measure("shell_history", func() ([]AISignal, int, error) { return s.detectShellHistory() })
	}

	sortAISignals(signals)
	return signals, stats
}

func (s *ContinuousDiscoveryService) classifyAndPersist(scanID, source string, start time.Time, signals []AISignal, stats scanStats, prev aiStateFile, full bool) AIDiscoveryReport {
	now := time.Now().UTC()
	prevMap := prev.Signals
	if prevMap == nil {
		prevMap = map[string]aiStoredSignal{}
	}

	current := map[string]aiStoredSignal{}
	out := make([]AISignal, 0, len(signals))
	counts := map[string]int{}
	for _, sig := range signals {
		sig.SignalID = stableSignalID(sig.Fingerprint)
		sig.FirstSeen = now
		sig.LastSeen = now
		if old, ok := prevMap[sig.Fingerprint]; ok {
			sig.FirstSeen = old.FirstSeen
			if old.EvidenceHash != sig.EvidenceHash {
				sig.State = AIStateChanged
			} else {
				sig.State = AIStateSeen
			}
		} else {
			sig.State = AIStateNew
		}
		if sig.State == AIStateNew || sig.State == AIStateChanged {
			out = append(out, sig)
		}
		counts[sig.State]++
		current[sig.Fingerprint] = aiStoredSignal{AISignal: sig, RawPaths: rawPathsForSignal(sig, s.opts.StoreRawLocalPaths)}
	}

	if full {
		for fp, old := range prevMap {
			if _, ok := current[fp]; ok {
				continue
			}
			gone := old.AISignal
			gone.State = AIStateGone
			gone.LastSeen = now
			out = append(out, gone)
			counts[AIStateGone]++
		}
	}

	_ = s.store.Save(aiStateFile{Version: aiDiscoveryStateVersion, UpdatedAt: now, Signals: current})

	summary := AIDiscoverySummary{
		ScanID:            scanID,
		ScannedAt:         now,
		DurationMs:        time.Since(start).Milliseconds(),
		PrivacyMode:       s.opts.Mode,
		Source:            source,
		Result:            "ok",
		TotalSignals:      len(signals),
		ActiveSignals:     len(current),
		NewSignals:        counts[AIStateNew],
		ChangedSignals:    counts[AIStateChanged],
		GoneSignals:       counts[AIStateGone],
		FilesScanned:      stats.FilesScanned,
		DedupeSuppressed:  stats.DedupeSuppressed,
		Errors:            stats.Errors,
		DetectorDurations: stats.DetectorDurations,
	}
	if stats.Errors > 0 {
		summary.Result = "partial"
	}
	sortAISignals(out)
	return AIDiscoveryReport{Summary: summary, Signals: out}
}

func (s *ContinuousDiscoveryService) detectConfigPaths() []AISignal {
	var out []AISignal
	for _, sig := range s.catalog {
		for _, candidate := range sig.ConfigPaths {
			for _, path := range s.expandCandidatePath(candidate) {
				if pathExists(path) {
					category := SignalWorkspaceArtifact
					if sig.SupportedConnector != "" {
						category = SignalSupportedConnector
					}
					out = append(out, s.signalFromPath(sig, category, "config", path))
				}
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectMCPPaths() []AISignal {
	var out []AISignal
	for _, sig := range s.catalog {
		for _, candidate := range sig.MCPPaths {
			for _, path := range s.expandCandidatePath(candidate) {
				if pathExists(path) {
					out = append(out, s.signalFromPath(sig, SignalMCPServer, "mcp", path))
				}
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectBinaries() []AISignal {
	var out []AISignal
	for _, sig := range s.catalog {
		for _, bin := range sig.BinaryNames {
			if path, err := exec.LookPath(bin); err == nil && path != "" {
				out = append(out, s.signalFromPath(sig, SignalAICLI, "binary", path))
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectProcesses() []AISignal {
	names, err := processNames()
	if err != nil {
		return nil
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, want := range sig.ProcessNames {
			want = strings.ToLower(strings.TrimSpace(want))
			if want == "" {
				continue
			}
			for _, have := range names {
				if processNameMatches(have, want) {
					out = append(out, s.signalFromValue(sig, SignalActiveProcess, "process", have))
					break
				}
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectApplications() []AISignal {
	names := installedApplicationNames(s.opts.HomeDir)
	if len(names) == 0 {
		return nil
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, want := range sig.ApplicationNames {
			want = strings.ToLower(strings.TrimSpace(want))
			if want == "" {
				continue
			}
			for _, have := range names {
				if applicationNameMatches(have, want) {
					out = append(out, s.signalFromValue(sig, SignalDesktopApp, "application", have))
					break
				}
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectEditorExtensions() []AISignal {
	roots := []string{
		filepath.Join(s.opts.HomeDir, ".vscode", "extensions"),
		filepath.Join(s.opts.HomeDir, ".vscode-insiders", "extensions"),
		filepath.Join(s.opts.HomeDir, ".vscodium", "extensions"),
		filepath.Join(s.opts.HomeDir, ".cursor", "extensions"),
		filepath.Join(s.opts.HomeDir, ".windsurf", "extensions"),
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "Code", "User", "globalStorage"),
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "Code - Insiders", "User", "globalStorage"),
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "VSCodium", "User", "globalStorage"),
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "Cursor", "User", "globalStorage"),
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "Windsurf", "User", "globalStorage"),
	}
	for _, pattern := range []string{
		filepath.Join(s.opts.HomeDir, "Library", "Application Support", "JetBrains", "*", "plugins"),
		filepath.Join(s.opts.HomeDir, ".local", "share", "JetBrains", "*", "plugins"),
	} {
		if matches, err := filepath.Glob(pattern); err == nil {
			roots = append(roots, matches...)
		}
	}
	var entries []string
	for _, root := range roots {
		children, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, child := range children {
			entries = append(entries, strings.ToLower(child.Name()))
		}
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, ext := range sig.ExtensionIDs {
			ext = strings.ToLower(ext)
			for _, entry := range entries {
				if strings.Contains(entry, ext) {
					out = append(out, s.signalFromValue(sig, SignalEditorExtension, "editor_extension", ext))
					break
				}
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectLocalEndpoints() []AISignal {
	client := &http.Client{
		Timeout: 750 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, endpoint := range sig.LocalEndpoints {
			endpoint = strings.TrimSpace(endpoint)
			if endpoint == "" || !isSafeLoopbackEndpoint(endpoint) {
				continue
			}
			req, err := http.NewRequest(http.MethodGet, endpoint, nil)
			if err != nil {
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 500 {
				ev := AIEvidence{Type: "local_endpoint", ValueHash: hashValue(endpoint)}
				out = append(out, s.signalFromEvidence(sig, SignalLocalAIEndpoint, "local_endpoint", []AIEvidence{ev}))
				break
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectEnvVars() []AISignal {
	present := map[string]bool{}
	for _, kv := range os.Environ() {
		if idx := strings.IndexByte(kv, '='); idx > 0 {
			present[strings.ToUpper(kv[:idx])] = true
		}
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, name := range sig.EnvVarNames {
			name = strings.ToUpper(strings.TrimSpace(name))
			if present[name] {
				out = append(out, s.signalFromValue(sig, SignalEnvVarName, "env", name))
			}
		}
	}
	return out
}

func (s *ContinuousDiscoveryService) detectPackageManifests() ([]AISignal, int, error) {
	manifestNames := map[string]bool{
		"package.json":             true,
		"pyproject.toml":           true,
		"requirements.txt":         true,
		"requirements-dev.txt":     true,
		"requirements.in":          true,
		"constraints.txt":          true,
		"poetry.lock":              true,
		"uv.lock":                  true,
		"Pipfile":                  true,
		"Pipfile.lock":             true,
		"environment.yml":          true,
		"environment.yaml":         true,
		"go.mod":                   true,
		"Gemfile":                  true,
		"composer.json":            true,
		"pom.xml":                  true,
		"build.gradle":             true,
		"build.gradle.kts":         true,
		"Cargo.toml":               true,
		"deno.json":                true,
		"deno.lock":                true,
		"bun.lock":                 true,
		"bun.lockb":                true,
		"yarn.lock":                true,
		"pnpm-lock.yaml":           true,
		"package-lock.json":        true,
		"Directory.Packages.props": true,
		"packages.config":          true,
		"Dockerfile":               true,
		"docker-compose.yml":       true,
		"docker-compose.yaml":      true,
		"compose.yml":              true,
		"compose.yaml":             true,
	}
	var out []AISignal
	files := 0
	for _, root := range s.scanRoots() {
		if files >= s.opts.MaxFilesPerScan {
			break
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || files >= s.opts.MaxFilesPerScan {
				return nil
			}
			if d.IsDir() {
				if shouldSkipDiscoveryDir(d.Name()) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if !manifestNames[d.Name()] && !isProjectPackageManifest(d.Name()) {
				return nil
			}
			files++
			body, ok := readBoundedText(path, s.opts.MaxFileBytes)
			if !ok {
				return nil
			}
			lower := strings.ToLower(body)
			workspaceHash := hashPath(filepath.Dir(path))
			for _, sig := range s.catalog {
				for _, pkg := range sig.PackageNames {
					pkgLower := strings.ToLower(pkg)
					if strings.Contains(lower, pkgLower) {
						ev := AIEvidence{
							Type:          "package",
							Basename:      filepath.Base(path),
							PathHash:      hashPath(path),
							WorkspaceHash: workspaceHash,
							ValueHash:     hashValue(pkgLower),
						}
						out = append(out, s.signalFromEvidence(sig, SignalPackageDependency, "package_manifest", []AIEvidence{ev}))
						break
					}
				}
			}
			return nil
		})
	}
	return out, files, nil
}

func (s *ContinuousDiscoveryService) detectShellHistory() ([]AISignal, int, error) {
	paths := []string{
		filepath.Join(s.opts.HomeDir, ".zsh_history"),
		filepath.Join(s.opts.HomeDir, ".bash_history"),
		filepath.Join(s.opts.HomeDir, ".config", "fish", "fish_history"),
	}
	var out []AISignal
	files := 0
	for _, path := range paths {
		body, ok := readBoundedTail(path, s.opts.MaxFileBytes)
		if !ok {
			continue
		}
		files++
		lower := strings.ToLower(body)
		for _, sig := range s.catalog {
			for _, pattern := range sig.HistoryPatterns {
				pattern = strings.ToLower(strings.TrimSpace(pattern))
				if pattern == "" || !strings.Contains(lower, pattern) {
					continue
				}
				ev := AIEvidence{
					Type:      "history",
					Basename:  filepath.Base(path),
					PathHash:  hashPath(path),
					ValueHash: hashValue(sig.ID + ":" + pattern + ":" + hashValue(body)),
				}
				out = append(out, s.signalFromEvidence(sig, SignalShellHistoryMatch, "shell_history", []AIEvidence{ev}))
				break
			}
			if !s.opts.IncludeNetworkDomains {
				continue
			}
			for _, domain := range sig.DomainPatterns {
				domain = strings.ToLower(strings.TrimSpace(domain))
				if domain == "" || !strings.Contains(lower, domain) {
					continue
				}
				ev := AIEvidence{
					Type:      "domain",
					Basename:  filepath.Base(path),
					PathHash:  hashPath(path),
					ValueHash: hashValue(sig.ID + ":" + domain),
				}
				out = append(out, s.signalFromEvidence(sig, SignalProviderDomain, "shell_history", []AIEvidence{ev}))
				break
			}
		}
	}
	return out, files, nil
}

func (s *ContinuousDiscoveryService) signalFromPath(sig AISignature, category, detector, path string) AISignal {
	ev := AIEvidence{Type: detector, Basename: filepath.Base(path), PathHash: hashPath(path)}
	if s.opts.StoreRawLocalPaths {
		ev.RawPath = path
	}
	return s.signalFromEvidence(sig, category, detector, []AIEvidence{ev})
}

func (s *ContinuousDiscoveryService) signalFromValue(sig AISignature, category, detector, value string) AISignal {
	ev := AIEvidence{Type: detector, ValueHash: hashValue(value)}
	return s.signalFromEvidence(sig, category, detector, []AIEvidence{ev})
}

func (s *ContinuousDiscoveryService) signalFromEvidence(sig AISignature, category, detector string, evidence []AIEvidence) AISignal {
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].Type+evidence[i].PathHash+evidence[i].ValueHash < evidence[j].Type+evidence[j].PathHash+evidence[j].ValueHash
	})
	evidenceHash := hashEvidence(evidence)
	fp := hashValue(strings.Join([]string{sig.ID, category, detector, evidenceHash}, "|"))
	out := AISignal{
		Fingerprint:        fp,
		SignatureID:        sig.ID,
		Name:               sig.Name,
		Vendor:             sig.Vendor,
		Product:            sig.Name,
		Category:           category,
		SupportedConnector: sig.SupportedConnector,
		Confidence:         sig.Confidence,
		Detector:           detector,
		Source:             "sidecar",
		EvidenceHash:       evidenceHash,
		Evidence:           evidence,
	}
	for _, ev := range evidence {
		if ev.Type != "" {
			out.EvidenceTypes = appendUnique(out.EvidenceTypes, ev.Type)
		}
		if ev.PathHash != "" {
			out.PathHashes = appendUnique(out.PathHashes, ev.PathHash)
		}
		if ev.Basename != "" {
			out.Basenames = appendUnique(out.Basenames, ev.Basename)
		}
		if out.WorkspaceHash == "" && ev.WorkspaceHash != "" {
			out.WorkspaceHash = ev.WorkspaceHash
		}
	}
	sort.Strings(out.EvidenceTypes)
	sort.Strings(out.PathHashes)
	sort.Strings(out.Basenames)
	return out
}

func (s *ContinuousDiscoveryService) scanRoots() []string {
	var roots []string
	for _, root := range s.opts.ScanRoots {
		for _, expanded := range s.expandCandidatePath(root) {
			if st, err := os.Stat(expanded); err == nil && st.IsDir() {
				roots = append(roots, expanded)
			}
		}
	}
	if len(roots) == 0 && s.opts.HomeDir != "" {
		roots = append(roots, s.opts.HomeDir)
	}
	return roots
}

func (s *ContinuousDiscoveryService) expandCandidatePath(candidate string) []string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return nil
	}
	if strings.HasPrefix(candidate, "~") {
		return []string{filepath.Clean(filepath.Join(s.opts.HomeDir, strings.TrimPrefix(candidate, "~")))}
	}
	if filepath.IsAbs(candidate) {
		return []string{filepath.Clean(candidate)}
	}
	var out []string
	for _, root := range s.scanRootsForRelative() {
		out = append(out, filepath.Clean(filepath.Join(root, candidate)))
	}
	return out
}

func (s *ContinuousDiscoveryService) scanRootsForRelative() []string {
	var roots []string
	for _, root := range s.opts.ScanRoots {
		if root == "" || root == "." {
			if cwd, err := os.Getwd(); err == nil {
				roots = append(roots, cwd)
			}
			continue
		}
		if strings.HasPrefix(root, "~") {
			roots = append(roots, filepath.Clean(filepath.Join(s.opts.HomeDir, strings.TrimPrefix(root, "~"))))
			continue
		}
		if filepath.IsAbs(root) {
			roots = append(roots, filepath.Clean(root))
		}
	}
	if len(roots) == 0 {
		if cwd, err := os.Getwd(); err == nil {
			roots = append(roots, cwd)
		}
	}
	return roots
}

func (s *ContinuousDiscoveryService) emitTelemetry(ctx context.Context, report AIDiscoveryReport) {
	if s.otel == nil || !s.otel.Enabled() {
		return
	}
	sum := report.Summary
	s.otel.RecordAIDiscoveryRun(ctx, sum.Source, sum.PrivacyMode, sum.Result, float64(sum.DurationMs), sum.TotalSignals, sum.ActiveSignals, sum.NewSignals, sum.GoneSignals, sum.FilesScanned, sum.DedupeSuppressed)
	s.otel.EmitAIDiscoverySummaryLog(ctx, sum.Source, sum.PrivacyMode, sum.Result, float64(sum.DurationMs), sum.TotalSignals, sum.ActiveSignals, sum.NewSignals, sum.GoneSignals, sum.FilesScanned)
	if sum.Errors > 0 {
		s.otel.RecordAIDiscoveryError(ctx, "scan", "partial")
	}
	for _, sig := range report.Signals {
		s.otel.RecordAIDiscoverySignal(ctx, sig.Category, sig.Vendor, sig.Product, sig.State, sig.Detector, sig.Confidence)
		s.otel.EmitAIDiscoverySignalLog(ctx, sig.Category, sig.Vendor, sig.Product, sig.State, sig.Detector, sig.Confidence)
	}
}

func (s *ContinuousDiscoveryService) emitGatewayEvents(ctx context.Context, report AIDiscoveryReport) {
	if s.events == nil {
		return
	}
	for _, sig := range report.Signals {
		if sig.State != AIStateNew && sig.State != AIStateChanged && sig.State != AIStateGone {
			continue
		}
		s.events.Emit(gatewaylog.Event{
			EventType: gatewaylog.EventAIDiscovery,
			Severity:  gatewaylog.SeverityInfo,
			AIDiscovery: &gatewaylog.AIDiscoveryPayload{
				ScanID:        report.Summary.ScanID,
				SignalID:      sig.SignalID,
				Category:      sig.Category,
				Vendor:        sig.Vendor,
				Product:       sig.Product,
				Confidence:    sig.Confidence,
				State:         sig.State,
				EvidenceTypes: sig.EvidenceTypes,
				PathHashes:    sig.PathHashes,
				Basenames:     sig.Basenames,
				WorkspaceHash: sig.WorkspaceHash,
				LastSeen:      sig.LastSeen.UTC().Format(time.RFC3339),
			},
		})
	}
}

// IngestExternalReport validates and records sanitized reports from external
// discovery clients. It does not merge raw evidence into local state.
func (s *ContinuousDiscoveryService) IngestExternalReport(ctx context.Context, report AIDiscoveryReport) error {
	if s == nil {
		return errors.New("ai discovery disabled")
	}
	if err := ValidateSanitizedAIDiscoveryReport(report); err != nil {
		return err
	}
	if s.opts.EmitOTel {
		s.emitTelemetry(ctx, report)
	}
	s.emitGatewayEvents(ctx, report)
	return nil
}

func ValidateSanitizedAIDiscoveryReport(report AIDiscoveryReport) error {
	if strings.TrimSpace(report.Summary.ScanID) == "" {
		return errors.New("scan_id is required")
	}
	if len(report.Signals) > 256 {
		return errors.New("too many signals")
	}
	for _, sig := range report.Signals {
		if !allowedAISignalCategories[sig.Category] {
			return fmt.Errorf("unsupported category %q", sig.Category)
		}
		for _, value := range sig.PathHashes {
			if value != "" && !isSHA256Hash(value) {
				return errors.New("path hashes must be sha256:<64 hex>")
			}
		}
		if sig.WorkspaceHash != "" && !isSHA256Hash(sig.WorkspaceHash) {
			return errors.New("workspace_hash must be sha256:<64 hex>")
		}
		for _, value := range sig.Basenames {
			if strings.Contains(value, "/") || strings.Contains(value, "\\") {
				return errors.New("raw paths are not allowed")
			}
		}
	}
	return nil
}

func isSHA256Hash(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, ch := range value[len(prefix):] {
		if (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') {
			continue
		}
		return false
	}
	return true
}

// AIStateStore persists local discovery deltas under the DefenseClaw data dir.
// The file carries no secrets, but is still mode 0600 because it can contain
// local path hashes and, when explicitly enabled, raw local paths.
type AIStateStore struct {
	path string
}

func NewAIStateStore(path string) *AIStateStore { return &AIStateStore{path: path} }

func (s *AIStateStore) Load() (aiStateFile, error) {
	var out aiStateFile
	if s == nil || s.path == "" {
		return out, nil
	}
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return aiStateFile{}, err
	}
	if out.Version != aiDiscoveryStateVersion {
		return aiStateFile{}, nil
	}
	if out.Signals == nil {
		out.Signals = map[string]aiStoredSignal{}
	}
	return out, nil
}

func (s *AIStateStore) Save(state aiStateFile) error {
	if s == nil || s.path == "" {
		return nil
	}
	state.Version = aiDiscoveryStateVersion
	state.UpdatedAt = time.Now().UTC()
	if state.Signals == nil {
		state.Signals = map[string]aiStoredSignal{}
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".ai_discovery_state.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(state); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

func processNames() ([]string, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ps", "-axo", "comm=")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		names = append(names, strings.ToLower(filepath.Base(line)))
	}
	return names, nil
}

func processNameMatches(have, want string) bool {
	have = strings.ToLower(strings.TrimSpace(filepath.Base(have)))
	want = strings.ToLower(strings.TrimSpace(filepath.Base(want)))
	if have == "" || want == "" {
		return false
	}
	if have == want {
		return true
	}
	// Short process names such as Amazon Q's `q` are far too noisy for
	// substring matching (`quicklook`, `qemu`, etc.). Require exact matches.
	if len(want) <= 3 {
		return false
	}
	return strings.Contains(have, want)
}

func installedApplicationNames(home string) []string {
	roots := []string{}
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots, "/Applications", "/System/Applications")
		if home != "" {
			roots = append(roots, filepath.Join(home, "Applications"))
		}
	case "linux":
		roots = append(roots, "/usr/share/applications")
		if home != "" {
			roots = append(roots, filepath.Join(home, ".local", "share", "applications"))
		}
	default:
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		children, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, child := range children {
			name := strings.ToLower(strings.TrimSpace(child.Name()))
			if name == "" {
				continue
			}
			if runtime.GOOS == "darwin" && !strings.HasSuffix(name, ".app") {
				continue
			}
			if runtime.GOOS == "linux" && !strings.HasSuffix(name, ".desktop") {
				continue
			}
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

func applicationNameMatches(have, want string) bool {
	have = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(have)), ".app"), ".desktop")
	want = strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(want)), ".app"), ".desktop")
	if have == "" || want == "" {
		return false
	}
	return have == want || strings.Contains(have, want)
}

func isSafeLoopbackEndpoint(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := u.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isProjectPackageManifest(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".csproj") ||
		strings.HasSuffix(lower, ".fsproj") ||
		strings.HasSuffix(lower, ".vbproj")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func readBoundedText(path string, maxBytes int64) (string, bool) {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > maxBytes {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func readBoundedTail(path string, maxBytes int64) (string, bool) {
	fh, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil || st.IsDir() {
		return "", false
	}
	offset := int64(0)
	if st.Size() > maxBytes {
		offset = st.Size() - maxBytes
	}
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return "", false
	}
	raw, err := io.ReadAll(io.LimitReader(fh, maxBytes))
	if err != nil {
		return "", false
	}
	return string(raw), true
}

func shouldSkipDiscoveryDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", ".cache", "cache", "dist", "build", "target", ".venv", "venv", "__pycache__", "library":
		return true
	default:
		return false
	}
}

func hashPath(path string) string {
	if path == "" {
		return ""
	}
	abs, err := filepath.Abs(path)
	if err == nil {
		path = abs
	}
	return "sha256:" + hashHex(path)
}

func hashValue(value string) string {
	if value == "" {
		return ""
	}
	return "sha256:" + hashHex(value)
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func hashEvidence(evidence []AIEvidence) string {
	raw, _ := json.Marshal(evidence)
	return hashValue(string(raw))
}

func stableSignalID(fp string) string {
	sum := sha256.Sum256([]byte(fp))
	return "ai-" + hex.EncodeToString(sum[:])[:16]
}

func newScanID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("scan-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("scan-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:]))
}

func rawPathsForSignal(sig AISignal, keep bool) []string {
	if !keep {
		return nil
	}
	var paths []string
	for _, ev := range sig.Evidence {
		if ev.RawPath != "" {
			paths = appendUnique(paths, ev.RawPath)
		}
	}
	sort.Strings(paths)
	return paths
}

func appendUnique(values []string, value string) []string {
	if value == "" {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func sortAISignals(signals []AISignal) {
	sort.Slice(signals, func(i, j int) bool {
		return signals[i].Category+signals[i].Vendor+signals[i].Product+signals[i].Fingerprint <
			signals[j].Category+signals[j].Vendor+signals[j].Product+signals[j].Fingerprint
	})
}

func cloneAIDiscoveryReport(in AIDiscoveryReport) AIDiscoveryReport {
	raw, err := json.Marshal(in)
	if err != nil {
		return in
	}
	var out AIDiscoveryReport
	if err := json.Unmarshal(raw, &out); err != nil {
		return in
	}
	return out
}
