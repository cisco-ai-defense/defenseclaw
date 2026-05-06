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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/inventory/lockparse"
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

// aiDiscoveryStateVersion is the schema version of the on-disk state file
// (`ai_discovery_state.json`). v2 introduced per-signal `evidence_hash`,
// `evidence`, `last_active_at`, `component`, and `runtime` so that:
//
//   - `Changed` detection survives sidecar restarts (v1 stripped
//     EvidenceHash via `json:"-"`, so every signal looked "changed"
//     after Load());
//   - non-process detectors can carry a separate "last invoked" timestamp
//     independent of "last scanned and still matched";
//   - the package_manifest detector can promote the catch-all
//     `ai-sdks` signature into per-component (e.g. openai==1.45.0) rows
//     without dropping data on restart.
//
// v1 state files are migrated transparently on Load() — old entries land
// in v2 with empty EvidenceHash, which makes the first post-upgrade scan
// behave like a `seen` (we explicitly skip the `!=` comparison when the
// stored hash is empty so an upgrade does not produce a flood of
// `changed` events the operator never asked for).
const aiDiscoveryStateVersion = 2

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
	Enabled                  bool
	Mode                     string
	ScanInterval             time.Duration
	ProcessInterval          time.Duration
	ScanRoots                []string
	SignaturePacks           []string
	AllowWorkspaceSignatures bool
	DisabledSignatureIDs     []string
	IncludeShellHistory      bool
	IncludePackageManifests  bool
	IncludeEnvVarNames       bool
	IncludeNetworkDomains    bool
	MaxFilesPerScan          int
	MaxFileBytes             int64
	EmitOTel                 bool
	StoreRawLocalPaths       bool
	ConfidencePolicyPath     string
	// DisableRedaction mirrors config.Privacy.DisableRedaction. When
	// true, on-the-wire AIDiscovery payloads (gateway events, OTel
	// logs) carry full Evidence rows including the raw_path field
	// (raw_path further requires StoreRawLocalPaths). When false (the
	// default), evidence is sanitized before leaving this process so
	// remote sinks never see local filesystem paths or unhashed
	// values.
	DisableRedaction bool
	DataDir          string
	HomeDir          string
}

// AIEvidence is an internal normalized evidence record. RawPath is never
// exported outside the local state file, and only when StoreRawLocalPaths is
// explicitly enabled.
//
// Quality and MatchKind are inputs to the Bayesian confidence engine in
// confidence.go: each detector's likelihood-ratio contribution is
// exponentiated by `Quality * signature.Specificity` (and additionally
// by a recency factor for presence). A `Quality=1.0, MatchKind="exact"`
// observation contributes the full LR; `Quality=0.4, MatchKind="heuristic"`
// is treated as substantially weaker evidence per row even though the
// detector class is the same. Populated by the detector that produced the
// evidence; the engine treats missing values as Quality=1.0,
// MatchKind="exact" so legacy detectors that have not been migrated keep
// their pre-engine semantics.
type AIEvidence struct {
	Type          string  `json:"type"`
	Basename      string  `json:"basename,omitempty"`
	PathHash      string  `json:"path_hash,omitempty"`
	ValueHash     string  `json:"value_hash,omitempty"`
	WorkspaceHash string  `json:"workspace_hash,omitempty"`
	RawPath       string  `json:"raw_path,omitempty"`
	Quality       float64 `json:"quality,omitempty"`    // 0..1, default 1.0 when unset (defaultEvidenceQuality)
	MatchKind     string  `json:"match_kind,omitempty"` // exact | substring | heuristic; engine reads to weight contributions
}

// Match-kind constants. Stamped by detectors so the confidence engine
// (and audit log readers) can reason about why we trusted this row.
const (
	MatchKindExact     = "exact"
	MatchKindSubstring = "substring"
	MatchKindHeuristic = "heuristic"
)

// defaultEvidenceQuality is what the confidence engine assumes when a
// detector did not stamp a Quality value (zero-valued field on the
// struct). Pinning the default to 1.0 means legacy detectors get the
// same per-observation weight they always had; new detectors must
// explicitly downgrade their evidence quality if it is weak.
const defaultEvidenceQuality = 1.0

// AIComponent is the high-fidelity identifier for a specific SDK / framework
// / package surfaced by a signal. The catch-all "AI SDKs / Multiple"
// signature historically hid which package matched (`openai` vs `langchain`
// vs `llama-index` …); when a signature pack declares `components` and the
// matched value resolves to one, the detector now stamps that resolved
// identity here. Consumers can pivot on `(Ecosystem, Name, Version)` to
// answer "do we have openai==1.45.0 anywhere?" without scraping prose.
type AIComponent struct {
	Ecosystem string `json:"ecosystem,omitempty"` // pypi | npm | cargo | go | dotnet | rubygems | maven | gradle | …
	Name      string `json:"name,omitempty"`      // e.g. "openai", "@anthropic-ai/sdk"
	Version   string `json:"version,omitempty"`   // populated when a co-located lockfile is parsed
	Framework string `json:"framework,omitempty"` // human-readable framework label, e.g. "OpenAI Python SDK"
}

// ProcessRuntime is the per-process liveness block emitted only by the
// `process` detector. It intentionally never carries the full argv (which
// can contain secrets, prompts, or workspace paths) — that surface is
// gated behind the existing `StoreRawLocalPaths` privacy switch via
// per-evidence raw paths, not here.
type ProcessRuntime struct {
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid,omitempty"`
	StartedAt time.Time `json:"started_at,omitempty"`
	UptimeSec int64     `json:"uptime_sec,omitempty"`
	User      string    `json:"user,omitempty"`
	Comm      string    `json:"comm,omitempty"`
}

// AISignal is the sanitized signal shape returned by API responses and used
// in gateway/OTel telemetry. It carries hashes and basenames, never raw file
// paths, command lines, prompt text, or secret values (unless the operator
// has explicitly opted into `StoreRawLocalPaths`).
//
// The `Component` and `Runtime` blocks are nil-omitted: only detectors
// that actually have framework / liveness fidelity populate them
// (today: `package_manifest` for components, `process` for runtimes).
// `LastActiveAt` is a separate timestamp from `LastSeen` so consumers
// can distinguish "we scanned and the signature still exists on disk"
// (`LastSeen`) from "the underlying thing was running / used since the
// previous scan" (`LastActiveAt`).
type AISignal struct {
	Fingerprint        string          `json:"fingerprint"`
	SignalID           string          `json:"signal_id"`
	SignatureID        string          `json:"signature_id"`
	Name               string          `json:"name"`
	Vendor             string          `json:"vendor"`
	Product            string          `json:"product"`
	Category           string          `json:"category"`
	SupportedConnector string          `json:"supported_connector,omitempty"`
	Confidence         float64         `json:"confidence"`
	State              string          `json:"state"`
	Detector           string          `json:"detector"`
	Source             string          `json:"source"`
	EvidenceTypes      []string        `json:"evidence_types,omitempty"`
	PathHashes         []string        `json:"path_hashes,omitempty"`
	Basenames          []string        `json:"basenames,omitempty"`
	WorkspaceHash      string          `json:"workspace_hash,omitempty"`
	Version            string          `json:"version,omitempty"`
	Component          *AIComponent    `json:"component,omitempty"`
	Runtime            *ProcessRuntime `json:"runtime,omitempty"`
	FirstSeen          time.Time       `json:"first_seen"`
	LastSeen           time.Time       `json:"last_seen"`
	LastActiveAt       *time.Time      `json:"last_active_at,omitempty"`
	EvidenceHash       string          `json:"-"`
	// Identity / Presence are populated by
	// EnrichSignalsWithComponentConfidence() at API-response time
	// (NOT during scan/persist). They mirror the per-component
	// scores `/api/v1/ai-usage/components` returns so the CLI's
	// `agent usage --detail` view can render the same numbers
	// without a second round-trip. Signals without a Component
	// block (catch-all process / shell-history rows) leave the
	// fields zero; `omitempty` keeps them off the wire so older
	// API consumers that don't know about the fields don't see
	// noisy nulls. Persistence (`aiStoredSignal`) ignores these
	// fields too -- they're recomputed on every API call from the
	// authoritative confidence engine.
	IdentityScore float64 `json:"identity_score,omitempty"`
	IdentityBand  string  `json:"identity_band,omitempty"`
	PresenceScore float64 `json:"presence_score,omitempty"`
	PresenceBand  string  `json:"presence_band,omitempty"`
	// Evidence is the per-row breakdown that the confidence engine
	// and the gateway components endpoint consume. It ships on the
	// wire so remote sinks (OTel, webhooks) can render the same
	// "what we saw" view the operator gets locally. RawPath is
	// scrubbed by SanitizeEvidenceForWire unless privacy.disable_redaction
	// AND ai_discovery.store_raw_local_paths are both true; size is
	// bounded by maxEvidencePerSignal so a hostile pack cannot
	// blow up payload size.
	Evidence []AIEvidence `json:"evidence,omitempty"`
}

// maxEvidencePerSignal caps the number of evidence rows the engine
// will accept on a single signal. The bound is generous (manifests
// + lockfiles + version pins for one component rarely produce more
// than a dozen rows in practice) but it is finite so a malicious
// pack cannot DOS the gateway or the SQLite store via a single
// pathological signal.
const maxEvidencePerSignal = 32

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

// aiStoredSignal is the on-disk shape persisted under the data dir's
// `ai_discovery_state.json`. v2 added `StoredEvidenceHash` and
// `StoredEvidence` because `AISignal.{EvidenceHash,Evidence}` are
// `json:"-"` (kept out of API responses for privacy reasons), but we
// MUST persist the hash to make `Changed` detection survive restarts.
//
// The `Stored…` fields mirror the in-memory `AISignal` fields rather
// than dropping the `json:"-"` tag, so the public API contract on
// `AISignal` is unchanged: API consumers still never see the raw
// per-evidence blob.
type aiStoredSignal struct {
	AISignal
	RawPaths           []string     `json:"raw_paths,omitempty"`
	StoredEvidenceHash string       `json:"evidence_hash,omitempty"`
	StoredEvidence     []AIEvidence `json:"evidence,omitempty"`
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
	// invStore is the optional SQLite-backed history. It is created
	// during NewContinuousDiscoveryServiceWithOptions when the data
	// dir is writable. When nil (open failed, disk full, etc.) the
	// service degrades to "current snapshot only" -- the JSON state
	// file remains the authoritative current view, and only history
	// queries are disabled.
	invStore         *InventoryStore
	confidenceParams ConfidenceParams
	otel             *telemetry.Provider
	events           *gatewaylog.Writer

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
	catalog, err := LoadAISignaturesForConfig(cfg)
	if err != nil {
		return nil, err
	}
	opts := AIDiscoveryOptionsFromConfig(cfg)
	return NewContinuousDiscoveryServiceWithOptions(opts, catalog, otel, events), nil
}

func NewContinuousDiscoveryServiceWithOptions(opts AIDiscoveryOptions, catalog []AISignature, otel *telemetry.Provider, events *gatewaylog.Writer) *ContinuousDiscoveryService {
	opts = normalizeAIDiscoveryOptions(opts)
	svc := &ContinuousDiscoveryService{
		opts:     opts,
		catalog:  catalog,
		store:    NewAIStateStore(filepath.Join(opts.DataDir, "ai_discovery_state.json")),
		otel:     otel,
		events:   events,
		triggers: make(chan chan scanResponse, 1),
	}
	// Try to open the SQLite history store. Failure is logged but
	// not fatal -- the service stays functional, only history
	// queries are disabled.
	if opts.DataDir != "" {
		dbPath := filepath.Join(opts.DataDir, "inventory.db")
		if inv, err := NewInventoryStore(dbPath); err == nil {
			svc.invStore = inv
		} else {
			fmt.Fprintf(os.Stderr, "[ai-discovery] inventory history disabled: %v\n", err)
		}
	}
	// Load the confidence policy. Missing override files fall back
	// to the embedded default; unreadable or invalid overrides
	// degrade to defaults with a stderr diagnostic because this
	// constructor cannot currently return initialization errors.
	policy, err := LoadConfidencePolicyFromFile(opts.ConfidencePolicyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ai-discovery] confidence policy degraded to defaults: %v\n", err)
		if fallback, fallbackErr := LoadDefaultConfidencePolicy(); fallbackErr == nil {
			policy = fallback
		} else {
			fmt.Fprintf(os.Stderr, "[ai-discovery] embedded confidence policy failed to load: %v\n", fallbackErr)
		}
	}
	svc.confidenceParams = ConfidenceParams{
		Policy:               policy,
		SignatureSpecificity: buildSignatureSpecificityIndex(catalog),
	}
	return svc
}

// buildSignatureSpecificityIndex projects the SignatureID ->
// Specificity mapping out of a loaded catalog so the confidence
// engine can honour curator-tuned per-signature specificity. We
// build it once at constructor time (catalogs are immutable after
// load) so the hot path doesn't re-scan O(N) signatures per signal.
// Returns nil when the catalog is empty so resolveSpecificity falls
// straight through to the heuristic.
func buildSignatureSpecificityIndex(catalog []AISignature) map[string]float64 {
	if len(catalog) == 0 {
		return nil
	}
	out := make(map[string]float64, len(catalog))
	for _, sig := range catalog {
		id := strings.TrimSpace(sig.ID)
		if id == "" || sig.Specificity <= 0 {
			continue
		}
		out[id] = sig.Specificity
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func AIDiscoveryOptionsFromConfig(cfg *config.Config) AIDiscoveryOptions {
	home, _ := os.UserHomeDir()
	ad := cfg.AIDiscovery
	return normalizeAIDiscoveryOptions(AIDiscoveryOptions{
		Enabled:                  ad.Enabled,
		Mode:                     ad.Mode,
		ScanInterval:             time.Duration(ad.ScanIntervalMin) * time.Minute,
		ProcessInterval:          time.Duration(ad.ProcessIntervalSec) * time.Second,
		ScanRoots:                append([]string{}, ad.ScanRoots...),
		SignaturePacks:           append([]string{}, ad.SignaturePacks...),
		AllowWorkspaceSignatures: ad.AllowWorkspaceSignatures,
		DisabledSignatureIDs:     append([]string{}, ad.DisabledSignatureIDs...),
		IncludeShellHistory:      ad.IncludeShellHistory,
		IncludePackageManifests:  ad.IncludePackageManifests,
		IncludeEnvVarNames:       ad.IncludeEnvVarNames,
		IncludeNetworkDomains:    ad.IncludeNetworkDomains,
		MaxFilesPerScan:          ad.MaxFilesPerScan,
		MaxFileBytes:             int64(ad.MaxFileBytes),
		EmitOTel:                 ad.EmitOTel,
		StoreRawLocalPaths:       ad.StoreRawLocalPaths,
		ConfidencePolicyPath:     ad.ConfidencePolicyPath,
		// Mirror the global redaction kill-switch so detectors and
		// emitters know whether they should scrub raw_path / full
		// evidence before a payload leaves the local process.
		DisableRedaction: cfg.Privacy.DisableRedaction,
		DataDir:          cfg.DataDir,
		HomeDir:          home,
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
	if opts.ConfidencePolicyPath == "" {
		opts.ConfidencePolicyPath = filepath.Join(opts.DataDir, "confidence.yaml")
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

// InventoryStore exposes the optional SQLite history backend so
// gateway handlers can serve `/components/{ecosystem}/{name}/locations`
// and `…/history` endpoints. Returns nil when the store could not
// be opened on this host -- callers must handle that.
func (s *ContinuousDiscoveryService) InventoryStore() *InventoryStore {
	if s == nil {
		return nil
	}
	return s.invStore
}

// ConfidenceParams returns the policy + tunables the engine uses
// when scoring components. Gateway handlers call ComputeComponentConfidence
// with this value to get scores for the live snapshot.
func (s *ContinuousDiscoveryService) ConfidenceParams() ConfidenceParams {
	if s == nil {
		return ConfidenceParams{}
	}
	return s.confidenceParams
}

// Options exposes the resolved discovery options so handlers can
// inspect privacy flags (DisableRedaction, StoreRawLocalPaths)
// without re-reading the global config object.
func (s *ContinuousDiscoveryService) Options() AIDiscoveryOptions {
	if s == nil {
		return AIDiscoveryOptions{}
	}
	return s.opts
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

	prev, prevErr := s.store.Load()
	if prevErr != nil {
		// Loading the previous-scan snapshot is best-effort — a
		// missing file is the cold-start case (handled inside
		// Load), an unsupported version (e.g. a forward-rolled
		// state file) returns an error here and we MUST log it
		// instead of silently treating the world as new. The
		// downstream scanSignals call will start with stats.Errors
		// at zero; we bump it AFTER the scan returns so the regression
		// is visible on dashboards.
		fmt.Fprintf(os.Stderr, "[ai-discovery] previous-scan load failed (treating workspace as new): %v\n", prevErr)
		prev = aiStateFile{}
	}
	signals, stats := s.scanSignals(ctx, full)
	if prevErr != nil {
		stats.Errors++
	}
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

	s.fanoutReport(ctx, report)
	return report, nil
}

// fanoutReport runs the OTel + gateway-events emitters off a
// SINGLE rollup snapshot so the two paths never disagree on the
// per-component identity / presence numbers (would happen if each
// path called ComputeComponentConfidence with its own
// time.Now()). The snapshot is built lazily so default-config
// installs (no OTel, redaction enabled) don't pay for a rollup
// they'd discard.
func (s *ContinuousDiscoveryService) fanoutReport(ctx context.Context, report AIDiscoveryReport) {
	otelOn := s.opts.EmitOTel && s.otel != nil && s.otel.Enabled()
	eventsOn := s.events != nil
	// The snapshot is only consulted when (a) OTel is on, or
	// (b) gateway events are on AND redaction is OFF (otherwise
	// BuildAIDiscoveryPayload strips Confidence anyway). Skip
	// the rollup entirely when neither path needs it.
	var snap componentRollupSnapshot
	if otelOn || (eventsOn && s.opts.DisableRedaction) {
		snap = buildComponentRollupSnapshot(report.Signals, s.confidenceParams)
	}
	if otelOn {
		s.emitTelemetry(ctx, report, snap)
	}
	if eventsOn {
		s.emitGatewayEvents(ctx, report, snap)
	}
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
		measure("package_manifest", func() ([]AISignal, int, error) { return s.detectPackageManifests(ctx) })
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

	// On non-full scans (the process-only ticker), we must MERGE
	// onto the prior persisted map instead of replacing it. The v1
	// implementation rebuilt `current` from `signals` only, which on
	// a process-only tick erased every config / binary / manifest
	// fingerprint until the next full scan — flapping `gone`/`new`
	// rows and resetting FirstSeen continuity. The fix preserves
	// non-process fingerprints across process-only ticks and only
	// overwrites the entries the current scan actually re-emitted.
	current := map[string]aiStoredSignal{}
	if !full {
		for fp, stored := range prevMap {
			current[fp] = stored
		}
	}

	out := make([]AISignal, 0, len(signals))
	counts := map[string]int{}
	// emittedFps tracks fingerprints classified by THIS scan tick.
	// On a process-only (non-full) tick we use it to append the
	// carried-forward inventory rows below, so report.Signals
	// always reflects len(current) == summary.ActiveSignals (the
	// CLI relies on this invariant: the table header reports
	// active_signals while the body iterates Signals -- when the
	// two diverge the operator sees a 4-vs-755 mismatch on every
	// process-only tick).
	emittedFps := make(map[string]bool, len(signals))
	for _, sig := range signals {
		sig.SignalID = stableSignalID(sig.Fingerprint)
		sig.FirstSeen = now
		sig.LastSeen = now
		// LastActiveAt: process detector pre-stamps Runtime.StartedAt
		// when known; for any non-process detector that supplied an
		// `mtime`-style hint via signal.LastActiveAt, keep that
		// value; otherwise default LastActiveAt to `now` so consumers
		// always have *some* "freshness" timestamp to render.
		if sig.LastActiveAt == nil {
			t := now
			sig.LastActiveAt = &t
		}
		if old, ok := prevMap[sig.Fingerprint]; ok {
			sig.FirstSeen = old.FirstSeen
			storedHash := old.EvidenceHash
			if storedHash == "" {
				storedHash = old.StoredEvidenceHash
			}
			// v1 → v2 grace: if the stored hash is empty (v1 migration
			// or first scan), treat as `seen` to avoid a flood of
			// spurious `changed` rows on the first post-upgrade scan.
			switch {
			case storedHash == "":
				sig.State = AIStateSeen
			case storedHash != sig.EvidenceHash:
				sig.State = AIStateChanged
			default:
				sig.State = AIStateSeen
			}
		} else {
			sig.State = AIStateNew
		}
		// Include every active signal in the report (not just deltas)
		// so callers like `defenseclaw agent usage` can render the
		// full live inventory without a second round-trip. The `state`
		// field still tells consumers what changed since last scan, so
		// downstream filters that only care about deltas keep working.
		out = append(out, sig)
		counts[sig.State]++
		emittedFps[sig.Fingerprint] = true
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
	} else {
		// Non-full ticker tick: extend report.Signals with the
		// carried-forward inventory so consumers see the same
		// count the summary advertises. The carried-forward rows
		// ship as state=seen regardless of what they were last
		// classified as, so the OTel + gateway-events emitters
		// (which fire only on new/changed/gone) don't replay
		// lifecycle events on every 5-second process tick. The
		// persistence map (`current`) is left untouched so the
		// next FULL scan still sees the prior state for proper
		// reclassification.
		for fp, stored := range current {
			if emittedFps[fp] {
				continue
			}
			carried := stored.AISignal
			carried.State = AIStateSeen
			out = append(out, carried)
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
	report := AIDiscoveryReport{Summary: summary, Signals: out}
	// Best-effort SQL persistence of the scan + computed
	// confidence snapshots. Failures are logged via stderr but
	// never fail the scan: the JSON state file remains the
	// authoritative current snapshot.
	s.recordScanIfPossible(report)
	return report
}

// recordScanIfPossible writes a scan to the optional inventory
// store. It exists as a separate helper because the call needs to
// degrade silently when invStore is nil (DB unavailable on this
// host) and we do not want that branch noise in the middle of
// classifyAndPersist.
func (s *ContinuousDiscoveryService) recordScanIfPossible(report AIDiscoveryReport) {
	if s == nil || s.invStore == nil {
		return
	}
	if err := s.invStore.RecordScan(context.Background(), report, s.confidenceParams); err != nil {
		fmt.Fprintf(os.Stderr, "[ai-discovery] inventory record failed: %v\n", err)
	}
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
	procs, err := processSnapshot()
	if err != nil || len(procs) == 0 {
		return nil
	}
	now := time.Now().UTC()
	var out []AISignal
	for _, sig := range s.catalog {
		for _, want := range sig.ProcessNames {
			want = strings.ToLower(strings.TrimSpace(want))
			if want == "" {
				continue
			}
			// Pick the *most recently started* matching process so
			// the rendered Runtime block is the freshest invocation,
			// not whichever ps row sorted first. This makes "Last
			// active" intuitive when a long-lived helper process and
			// a fresh agent run share the same comm.
			var best *processInfo
			for i := range procs {
				if !processNameMatches(procs[i].Comm, want) {
					continue
				}
				if best == nil || procs[i].StartedAt.After(best.StartedAt) {
					p := procs[i]
					best = &p
				}
			}
			if best == nil {
				continue
			}
			// Quality reflects how confident this row is *as evidence
			// of the named SDK*. Exact comm match (the kernel-reported
			// process name equals a catalog `process_names` entry) is
			// the strongest signal a `ps` snapshot can give us;
			// substring matches (e.g. "claude-code" containing "claude")
			// are still useful but less specific, so the engine
			// down-weights them via Quality.
			quality := 1.0
			matchKind := MatchKindExact
			if !processCommExactlyEquals(best.Comm, want) {
				quality = 0.5
				matchKind = MatchKindSubstring
			}
			ev := AIEvidence{
				Type:      "process",
				ValueHash: hashValue(best.Comm),
				Quality:   quality,
				MatchKind: matchKind,
			}
			signal := s.signalFromEvidence(sig, SignalActiveProcess, "process", []AIEvidence{ev})
			runtime := &ProcessRuntime{
				PID:       best.PID,
				PPID:      best.PPID,
				StartedAt: best.StartedAt,
				UptimeSec: int64(now.Sub(best.StartedAt).Seconds()),
				User:      best.User,
				Comm:      best.Comm,
			}
			signal.Runtime = runtime
			// Process detector's `LastActiveAt` is the process'
			// start time, not the scan time. That's the answer to
			// "when was this thing last active" the operator wants.
			started := best.StartedAt
			signal.LastActiveAt = &started
			out = append(out, signal)
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

// safeLocalEndpointPaths is the allow-list of URL paths that
// detectLocalEndpoints will GET as a fallback when a HEAD probe is not
// supported by the local AI server. Every entry here MUST be a
// purely-metadata, idempotent endpoint that cannot, under any vendor's
// deployment, run inference, mutate state, or trigger billing.
//
// The list is keyed exact (case-sensitive). Adding to it requires
// (1) confirming with the vendor's docs that the path is read-only
// metadata, and (2) matching the path against the same vendor's
// signature.local_endpoints entry in ai_signatures.json.
var safeLocalEndpointPaths = map[string]struct{}{
	"/api/tags":    {}, // Ollama — list installed models
	"/api/version": {}, // Ollama — server version
	"/v1/models":   {}, // OpenAI-compatible (LM Studio, vLLM, LocalAI, llama.cpp server)
	"/v1/health":   {}, // common health endpoint
	"/health":      {}, // ditto
	"/healthz":     {}, // Kubernetes-style health
}

// detectLocalEndpoints probes the loopback HTTP endpoints declared in
// each AISignature.LocalEndpoints and emits a SignalLocalAIEndpoint when
// a server responds.
//
// SECURITY (M-3): the previous implementation issued an unauthenticated
// HTTP GET against every signature's endpoint. For OpenAI-compatible
// servers (`/v1/models`) and Ollama (`/api/tags`) those URLs are
// metadata only, but:
//   - operator-supplied signature packs may add custom endpoints, and a
//     misconfigured pack could end up GETing an inference URL with an
//     empty body, triggering work or billing on the local server;
//   - even on safe paths, the request signals "DefenseClaw is here" to
//     whatever process happens to be listening on that port, which is a
//     fingerprinting concern;
//   - many OpenAI-compatible servers return very large payloads on
//     `/v1/models` (full model metadata) that we don't actually need.
//
// We now (a) prefer HEAD which never carries a body and which most
// OpenAI/Ollama metadata endpoints support; (b) fall back to GET only
// when the URL path is in safeLocalEndpointPaths AND HEAD failed in a
// way that suggests "method not allowed" rather than "host unreachable";
// (c) advertise ourselves with a stable User-Agent so server access
// logs make the source obvious; (d) cap the discarded response body
// hard. The endpoint allow-list is enforced even for HEAD as a
// defense-in-depth check against operator-supplied packs probing
// surprise URLs.
func (s *ContinuousDiscoveryService) detectLocalEndpoints() []AISignal {
	client := &http.Client{
		Timeout: 750 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	probe := func(method, endpoint string) (int, bool) {
		req, err := http.NewRequest(method, endpoint, nil)
		if err != nil {
			return 0, false
		}
		req.Header.Set("User-Agent", "defenseclaw-discovery/1.0 (+https://defenseclaw.com/discovery)")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Connection", "close")
		resp, err := client.Do(req)
		if err != nil {
			return 0, false
		}
		defer resp.Body.Close()
		// Best-effort drain. Cap MUCH lower than the previous 1 KiB —
		// we only care about the status code; the body is irrelevant
		// and may be megabytes on some /v1/models responses.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 256))
		return resp.StatusCode, true
	}
	var out []AISignal
	for _, sig := range s.catalog {
		for _, endpoint := range sig.LocalEndpoints {
			endpoint = strings.TrimSpace(endpoint)
			if endpoint == "" || !isSafeLoopbackEndpoint(endpoint) {
				continue
			}
			// Defense-in-depth: only probe paths the project has
			// explicitly cleared as metadata-only. Operator packs that
			// drift outside this allow-list silently skip the probe.
			u, err := url.Parse(endpoint)
			if err != nil {
				continue
			}
			if _, ok := safeLocalEndpointPaths[u.Path]; !ok {
				continue
			}
			status, ok := probe(http.MethodHead, endpoint)
			if !ok || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented {
				// HEAD wasn't accepted; try GET as a fallback.
				// (Already gated by safeLocalEndpointPaths above.)
				status, ok = probe(http.MethodGet, endpoint)
				if !ok {
					continue
				}
			}
			if status >= 200 && status < 500 {
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

// packageManifestNames is the allow-list of basenames the
// `package_manifest` detector treats as ecosystem-relevant. It includes
// both manifests (declared deps) and lockfiles (resolved deps); the
// lockfile entries are read to enrich co-located manifest matches with
// concrete versions via internal/inventory/lockparse.
var packageManifestNames = map[string]bool{
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
	"go.sum":                   true,
	"Gemfile":                  true,
	"Gemfile.lock":             true,
	"composer.json":            true,
	"composer.lock":            true,
	"pom.xml":                  true,
	"build.gradle":             true,
	"build.gradle.kts":         true,
	"Cargo.toml":               true,
	"Cargo.lock":               true,
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

// pkgManifestEntry is one matched manifest file in a directory the
// detector visits. The lockfile→version index is computed once per dir
// so multiple manifests in the same dir don't reparse the lockfile.
type pkgManifestEntry struct {
	path             string
	basename         string
	body             string
	bodyLower        string
	pathHash         string
	wsHash           string
	ecosystem        string
	parsedComponents map[string]map[string]string
}

func (s *ContinuousDiscoveryService) detectPackageManifests(ctx context.Context) ([]AISignal, int, error) {
	var out []AISignal
	files := 0
	walkErrs := 0
	// Walk each scan root; collect entries grouped by dir so we can
	// compute lockfile-based version indexes once per dir.
	for _, root := range s.scanRoots() {
		if err := ctx.Err(); err != nil {
			// Caller cancelled (sidecar shutdown / scan timeout).
			// Stop honestly rather than continue queuing work.
			break
		}
		if files >= s.opts.MaxFilesPerScan {
			break
		}
		// dirEntries: dir path -> manifest entries inside that dir.
		dirEntries := map[string][]pkgManifestEntry{}
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			// Cancellation check on every entry — large monorepo
			// walks otherwise block shutdown for tens of seconds.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if err != nil {
				// Permission errors / vanished entries are
				// expected in long-running scans; record one bump
				// per error so dashboards see the regression but
				// keep going. Walking is best-effort.
				walkErrs++
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if files >= s.opts.MaxFilesPerScan {
				return filepath.SkipAll
			}
			if d.IsDir() {
				if shouldSkipDiscoveryDir(d.Name()) && path != root {
					return filepath.SkipDir
				}
				return nil
			}
			if !packageManifestNames[d.Name()] && !isProjectPackageManifest(d.Name()) {
				return nil
			}
			files++
			body, ok := readBoundedText(path, s.opts.MaxFileBytes)
			if !ok {
				return nil
			}
			// wsHash is the PROJECT ROOT hash, not the
			// manifest's immediate dir. This is the big
			// dedup lever: every `node_modules/<dep>/package.json`
			// inside one project shares one wsHash (= the project
			// root), so 358 transitive package.json hits collapse
			// to one signal per (component, project) instead of
			// per file. See projectRootForManifest for the
			// cache-segment walk-up rules.
			entry := pkgManifestEntry{
				path:      path,
				basename:  filepath.Base(path),
				body:      body,
				bodyLower: strings.ToLower(body),
				pathHash:  hashPath(path),
				wsHash:    hashPath(projectRootForManifest(path)),
				ecosystem: lockparse.Ecosystem(filepath.Base(path)),
			}
			comps, _ := lockparse.Parse(path, s.opts.MaxFileBytes)
			entry.parsedComponents = indexParsedManifestComponents(comps, entry.ecosystem)
			dir := filepath.Dir(path)
			dirEntries[dir] = append(dirEntries[dir], entry)
			return nil
		})
		// WalkDir returns the first error returned by the visit
		// callback (other than ErrSkipDir / ErrSkipAll). Cancellation
		// surfaces as ctx.Err(); anything else is the visit-fn's
		// per-entry diagnostic which we already counted in walkErrs.
		if walkErr != nil && ctx.Err() != nil {
			return out, files, ctx.Err()
		}
		// Per-dir: build version index from any parseable lockfile,
		// then emit one signal per (manifest entry, matched component).
		// We collect emissions into `raw` first and then aggregate
		// by (sigID, componentKey, wsHash) below so transitive
		// `node_modules/<dep>/package.json` records inside one project
		// collapse to a single per-project signal instead of N
		// near-identical fingerprints.
		var raw []AISignal
		for dir, entries := range dirEntries {
			versionsByEcosystem := map[string]map[string]string{}
			for _, entry := range entries {
				for eco, components := range entry.parsedComponents {
					if _, ok := versionsByEcosystem[eco]; !ok {
						versionsByEcosystem[eco] = map[string]string{}
					}
					for name, version := range components {
						if existing := versionsByEcosystem[eco][name]; existing == "" {
							versionsByEcosystem[eco][name] = version
						}
					}
				}
			}
			_ = dir // kept for future per-dir caching; intentionally unused
			for _, entry := range entries {
				raw = append(raw, s.matchManifestEntry(entry, versionsByEcosystem)...)
			}
		}
		out = append(out, aggregateManifestSignalsByProjectRoot(raw)...)
	}
	if walkErrs > 0 {
		// Surface the count via the (signal-count, file-count, error)
		// tuple so scanStats can record it; fmt.Errorf is intentionally
		// terse — operators don't need the per-file detail, just the
		// fact that something went wrong during walking.
		return out, files, fmt.Errorf("manifest walk encountered %d errors (permission / vanished entries)", walkErrs)
	}
	return out, files, nil
}

func indexParsedManifestComponents(comps []lockparse.Component, fallbackEcosystem string) map[string]map[string]string {
	if len(comps) == 0 {
		return nil
	}
	out := map[string]map[string]string{}
	for _, c := range comps {
		name := strings.ToLower(strings.TrimSpace(c.Name))
		if name == "" {
			continue
		}
		eco := strings.ToLower(strings.TrimSpace(c.Ecosystem))
		if eco == "" {
			eco = strings.ToLower(strings.TrimSpace(fallbackEcosystem))
		}
		if eco == "" {
			continue
		}
		if _, ok := out[eco]; !ok {
			out[eco] = map[string]string{}
		}
		if existing := out[eco][name]; existing == "" {
			out[eco][name] = c.Version
		}
	}
	return out
}

func parsedManifestComponentVersion(index map[string]map[string]string, ecosystem, name string) (string, bool) {
	if len(index) == 0 {
		return "", false
	}
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", false
	}
	if eco := strings.ToLower(strings.TrimSpace(ecosystem)); eco != "" {
		if components := index[eco]; components != nil {
			version, ok := components[name]
			return version, ok
		}
		return "", false
	}
	for _, components := range index {
		if version, ok := components[name]; ok {
			return version, true
		}
	}
	return "", false
}

// aggregateManifestSignalsByProjectRoot collapses N near-identical
// signals from one project into ONE signal per (signature,
// component, workspace) tuple. This is the second half of Fix B
// alongside `projectRootForManifest`: walking up to the project
// root gave us a stable wsHash per project, but the fingerprint
// in `signalFromEvidenceWithComponent` still depends on the per-
// path `evidenceHash`, so two transitive manifests that resolve
// to the same SDK still produced two signals.
//
// We re-key by `(sigID, componentKey, wsHash, ecosystem, version)`
// and merge the per-path evidence into one combined evidence
// slice, then re-emit through `signalFromEvidenceWithComponent`
// so the fingerprint, evidence hash, and downstream wire shape
// stay consistent. Result: 358 transitive `package.json` hits
// for `ai` become ~5 signals (one per real project).
//
// Component-less signals (legacy catch-all packs) and signals
// from other detectors are left untouched -- this is a manifest-
// detector-specific dedup.
// manifestAggKey is the (signature, component, workspace, version,
// category) tuple `aggregateManifestSignalsByProjectRoot` folds
// emissions on. Promoted to package scope so the new signal's
// fingerprint string can be built from its fields without a
// method-on-anonymous-struct workaround.
type manifestAggKey struct {
	sigID    string
	compKey  string
	wsHash   string
	version  string
	category string
}

func aggregateManifestSignalsByProjectRoot(raw []AISignal) []AISignal {
	if len(raw) == 0 {
		return nil
	}
	type bucket struct {
		first    AISignal
		evidence []AIEvidence
		paths    map[string]bool
	}
	by := map[manifestAggKey]*bucket{}
	order := []manifestAggKey{}
	passthrough := []AISignal{}
	for _, sig := range raw {
		// Only fold rows that have a component AND a wsHash --
		// without those we can't safely declare two rows
		// equivalent. Catch-all (component-less) rows pass
		// through unchanged so legacy packs don't regress.
		if sig.Component == nil || sig.WorkspaceHash == "" {
			passthrough = append(passthrough, sig)
			continue
		}
		k := manifestAggKey{
			sigID: sig.SignatureID,
			compKey: strings.ToLower(sig.Component.Ecosystem) + "/" +
				strings.ToLower(sig.Component.Name),
			wsHash:   sig.WorkspaceHash,
			version:  sig.Version,
			category: sig.Category,
		}
		b, ok := by[k]
		if !ok {
			b = &bucket{
				first: sig,
				paths: map[string]bool{},
			}
			by[k] = b
			order = append(order, k)
		}
		// Dedupe evidence rows by `(type, pathHash, valueHash)`
		// so the same manifest contributing twice (e.g. parsed
		// once as JSON and once as raw text in a future detector
		// extension) doesn't grow the evidence slice unbounded.
		for _, ev := range sig.Evidence {
			key := ev.Type + "|" + ev.PathHash + "|" + ev.ValueHash
			if b.paths[key] {
				continue
			}
			b.paths[key] = true
			b.evidence = append(b.evidence, ev)
		}
	}
	out := make([]AISignal, 0, len(by)+len(passthrough))
	for _, k := range order {
		b := by[k]
		// Re-stamp the signal: keep the first emit's identity
		// (product/vendor/component/version) and rebuild the
		// fingerprint so the SAME merged (sig, component,
		// project) produces the SAME fingerprint across scans
		// -- otherwise the inventory store would treat each
		// scan as a brand-new signal and lifecycle (`new` /
		// `seen` / `gone`) tracking would break.
		merged := b.first
		merged.Evidence = b.evidence
		merged.PathHashes = nil
		merged.Basenames = nil
		merged.EvidenceTypes = nil
		for _, ev := range b.evidence {
			if ev.Type != "" {
				merged.EvidenceTypes = appendUnique(merged.EvidenceTypes, ev.Type)
			}
			if ev.PathHash != "" {
				merged.PathHashes = appendUnique(merged.PathHashes, ev.PathHash)
			}
			if ev.Basename != "" {
				merged.Basenames = appendUnique(merged.Basenames, ev.Basename)
			}
		}
		sort.Strings(merged.EvidenceTypes)
		sort.Strings(merged.PathHashes)
		sort.Strings(merged.Basenames)
		fpInputs := []string{
			merged.SignatureID,
			k.category,
			merged.Detector,
			"component:" + k.compKey,
			"ws:" + k.wsHash,
			"v:" + k.version,
		}
		merged.Fingerprint = hashValue(strings.Join(fpInputs, "|"))
		merged.EvidenceHash = hashEvidence(b.evidence)
		out = append(out, merged)
	}
	out = append(out, passthrough...)
	return out
}

// matchManifestEntry resolves every catalog signature against one
// manifest body. When the matched package resolves to a declared
// component on the signature, the emitted signal carries the
// component's framework label and any co-located lockfile version.
//
// Backward compatibility: signatures without `components` keep their
// previous "first match wins" behaviour (emitting the catch-all
// signature row), so this change is purely additive for old packs.
func (s *ContinuousDiscoveryService) matchManifestEntry(entry pkgManifestEntry, versions map[string]map[string]string) []AISignal {
	var out []AISignal
	for _, sig := range s.catalog {
		emittedComponents := map[string]bool{}
		emittedFallback := false
		for _, pkg := range sig.PackageNames {
			pkgLower := strings.ToLower(strings.TrimSpace(pkg))
			if pkgLower == "" {
				continue
			}
			component := sig.resolveComponent(pkgLower, entry.ecosystem)
			if component == nil {
				if !strings.Contains(entry.bodyLower, pkgLower) {
					continue
				}
				// CRITICAL: when the signature DOES declare components
				// but the matched package didn't resolve to any of
				// them for THIS ecosystem, we MUST drop the match.
				// Otherwise a 2-character npm package name like "ai"
				// substring-matches the body of a Cargo.toml /
				// pyproject.toml / build.gradle.kts and the
				// catch-all emit attributes the hit to "Vercel AI
				// SDK" with the wrong basename + ecosystem on the
				// wire. Real-world repro that landed this guard:
				// 685 "Vercel AI SDK" rows on a fresh scan, 209 of
				// which were Cargo.toml hits (Rust files) and only
				// ~365 actual npm manifests.
				//
				// Legacy signatures without `components` keep their
				// historical "first match wins" catch-all behaviour
				// so the wire shape doesn't regress for old packs.
				if len(sig.Components) > 0 {
					continue
				}
				if emittedFallback {
					continue
				}
				ev := AIEvidence{
					Type:          "package",
					Basename:      entry.basename,
					PathHash:      entry.pathHash,
					WorkspaceHash: entry.wsHash,
					ValueHash:     hashValue(pkgLower),
					// Catch-all: we matched a package-name *substring*
					// inside the manifest body without resolving to a
					// declared component. Treat it as a substring
					// match with reduced quality so the engine
					// down-weights legacy catch-all packs.
					Quality:   0.6,
					MatchKind: MatchKindSubstring,
				}
				out = append(out, s.signalFromEvidence(sig, SignalPackageDependency, "package_manifest", []AIEvidence{ev}))
				emittedFallback = true
				continue
			}
			version, ok := parsedManifestComponentVersion(entry.parsedComponents, component.Ecosystem, component.Name)
			if !ok {
				continue
			}
			componentKey := strings.ToLower(component.Ecosystem) + "/" + strings.ToLower(component.Name)
			if emittedComponents[componentKey] {
				continue
			}
			emittedComponents[componentKey] = true
			// Enrich with the parsed lockfile version when available.
			if eco := strings.ToLower(component.Ecosystem); eco != "" {
				if vs, ok := versions[eco]; ok {
					if v := vs[strings.ToLower(component.Name)]; v != "" {
						version = v
					}
				}
			}
			if version == "" {
				// Fallback: search across all collected ecosystems
				// (handles the case where a lockfile didn't tag its
				// ecosystem precisely).
				for _, vs := range versions {
					if v := vs[strings.ToLower(component.Name)]; v != "" {
						version = v
						break
					}
				}
			}
			resolved := AIComponent{
				Ecosystem: component.Ecosystem,
				Name:      component.Name,
				Framework: component.Framework,
				Version:   version,
			}
			// Apply the per-component vendor override too: when the
			// catalog component declares its own vendor (e.g.
			// `OpenAI` for the `openai` package), it wins over the
			// signature-level "Multiple" catch-all.
			componentSig := sig
			if component.Vendor != "" {
				componentSig.Vendor = component.Vendor
			}
			// Component-resolved match: the package name in the
			// manifest body matched a declared component
			// (e.g. `openai`). Treat this as the strongest possible
			// manifest evidence (Quality=1.0, MatchKind=exact).
			// When a co-located lockfile pinned a version, we have
			// even more certainty -- the engine adds a small bonus
			// internally for "version present", but the Quality
			// stamp remains 1.0 so old policies stay calibrated.
			ev := AIEvidence{
				Type:          "package",
				Basename:      entry.basename,
				PathHash:      entry.pathHash,
				WorkspaceHash: entry.wsHash,
				ValueHash:     hashValue(componentKey),
				Quality:       1.0,
				MatchKind:     MatchKindExact,
			}
			out = append(out, s.signalFromEvidenceWithComponent(componentSig, SignalPackageDependency, "package_manifest", []AIEvidence{ev}, &resolved))
		}
	}
	return out
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
				// M-2: the evidence ID is a *stable identity* for "this
				// signature's pattern matched in this history file". The
				// previous implementation hashed the entire history tail
				// into the ValueHash, so every additional shell command
				// the user ran shifted the fingerprint and the signal
				// looked like a fresh detection on every scan. That
				// broke deduplication, NewSignals counts, and downstream
				// alert "since last seen" semantics. Identity should
				// only depend on what was detected (signature + pattern
				// + which history file), not on how many other commands
				// happen to live in the tail.
				ev := AIEvidence{
					Type:      "history",
					Basename:  filepath.Base(path),
					PathHash:  hashPath(path),
					ValueHash: hashValue(sig.ID + ":" + pattern),
					// Shell-history matches are a substring scan
					// over a flat command log -- there is no
					// structured guarantee that the pattern was
					// invoked as a real command (it could appear in
					// a comment, an env-var expansion, or a `grep`
					// argument). Quality 0.5 + heuristic kind tells
					// the engine to treat this as weak corroborating
					// evidence rather than a primary signal.
					Quality:   0.5,
					MatchKind: MatchKindHeuristic,
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
	out := s.signalFromEvidence(sig, category, detector, []AIEvidence{ev})
	// "Last active" for path-evidence detectors (config / binary /
	// MCP / extension) defaults to the file's modification time when
	// available. That's a meaningful liveness proxy: an `~/.codex/`
	// config touched 30 seconds ago indicates current use; one
	// stale for 6 months indicates dormant install. Process and
	// package_manifest detectors override this with their own
	// timestamps.
	if st, err := os.Stat(path); err == nil {
		mt := st.ModTime().UTC()
		out.LastActiveAt = &mt
	}
	return out
}

func (s *ContinuousDiscoveryService) signalFromValue(sig AISignature, category, detector, value string) AISignal {
	ev := AIEvidence{Type: detector, ValueHash: hashValue(value)}
	return s.signalFromEvidence(sig, category, detector, []AIEvidence{ev})
}

func (s *ContinuousDiscoveryService) signalFromEvidence(sig AISignature, category, detector string, evidence []AIEvidence) AISignal {
	return s.signalFromEvidenceWithComponent(sig, category, detector, evidence, nil)
}

// signalFromEvidenceWithComponent is the per-component variant: when the
// caller resolved the matched value (e.g. the package name in a
// manifest body) to a known signature component, the resulting signal
// carries that identity in `Component`, overrides `Product`/`Vendor`
// with the component's framework labels, and folds the component name
// into the fingerprint so per-component rows from the same signature
// (`openai` vs `langchain` vs `llama-index` under `ai-sdks`) get
// distinct, stable fingerprints.
func (s *ContinuousDiscoveryService) signalFromEvidenceWithComponent(sig AISignature, category, detector string, evidence []AIEvidence, component *AIComponent) AISignal {
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].Type+evidence[i].PathHash+evidence[i].ValueHash < evidence[j].Type+evidence[j].PathHash+evidence[j].ValueHash
	})
	evidenceHash := hashEvidence(evidence)
	fpInputs := []string{sig.ID, category, detector, evidenceHash}
	if component != nil && component.Name != "" {
		// Component name (lowercased ecosystem-qualified) participates
		// in the fingerprint so the same manifest matching multiple
		// AI SDK packages produces distinct, stable per-package rows.
		fpInputs = append(fpInputs, "component:"+strings.ToLower(component.Ecosystem)+"/"+strings.ToLower(component.Name))
	}
	fp := hashValue(strings.Join(fpInputs, "|"))
	product := sig.Name
	vendor := sig.Vendor
	if component != nil && component.Framework != "" {
		product = component.Framework
	}
	// Component-level vendor override is applied by the *caller*
	// (detectPackageManifests) on a copy of `sig` before invoking
	// this helper, since the runtime AIComponent view does not
	// carry the catalog Vendor field. See signalFromEvidenceWithComponent
	// callers in detectPackageManifests for the exact pattern.
	out := AISignal{
		Fingerprint:        fp,
		SignatureID:        sig.ID,
		Name:               sig.Name,
		Vendor:             vendor,
		Product:            product,
		Category:           category,
		SupportedConnector: sig.SupportedConnector,
		Confidence:         sig.Confidence,
		Detector:           detector,
		Source:             "sidecar",
		EvidenceHash:       evidenceHash,
		Evidence:           evidence,
		Component:          component,
	}
	if component != nil && component.Version != "" {
		// Surface the parsed lockfile version on the existing
		// `version` field too so older API/TUI clients that don't
		// know about `component.version` still get the data.
		out.Version = component.Version
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

func (s *ContinuousDiscoveryService) emitTelemetry(ctx context.Context, report AIDiscoveryReport, snap componentRollupSnapshot) {
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
		// Telemetry emission stays delta-focused to avoid flooding
		// log sinks on every full scan now that report.Signals
		// includes steady-state `seen` entries (so the API can
		// render full inventory). New / changed / gone are still
		// emitted because those are real lifecycle events.
		if sig.State != AIStateNew && sig.State != AIStateChanged && sig.State != AIStateGone {
			continue
		}
		s.otel.RecordAIDiscoverySignal(ctx, sig.Category, sig.Vendor, sig.Product, sig.State, sig.Detector, sig.Confidence)
		s.otel.EmitAIDiscoverySignalLog(ctx, sig.Category, sig.Vendor, sig.Product, sig.State, sig.Detector, sig.Confidence)
	}
	// Component-level emission off the SHARED snapshot so every
	// downstream consumer sees byte-identical identity / presence
	// numbers. Cardinality is bounded by the discovered component
	// set, not by signal volume. Logs only fire when at least one
	// signal in the group experienced a lifecycle change so we
	// don't flood SIEMs with duplicate "AI component confidence"
	// rows for a steady-state monorepo.
	policyVersion := s.confidenceParams.Policy.Version
	for _, g := range snap.Groups {
		conf, ok := snap.ScoreFor(g)
		if !ok {
			continue
		}
		attrs := buildComponentConfidenceAttrs(g, conf, policyVersion)
		s.otel.RecordAIComponentConfidence(ctx, attrs)
		if g.HasLifecycleChange {
			s.otel.EmitAIComponentConfidenceLog(ctx, attrs)
		}
	}
}

func (s *ContinuousDiscoveryService) emitGatewayEvents(ctx context.Context, report AIDiscoveryReport, snap componentRollupSnapshot) {
	if s.events == nil {
		return
	}
	opts := s.opts
	// snap.Scores is non-nil only when DisableRedaction is true
	// (see fanoutReport). When redaction is on, every per-signal
	// payload ships without Confidence anyway, so a nil Scores
	// map is the correct skip-the-lookup signal.
	for _, sig := range report.Signals {
		if sig.State != AIStateNew && sig.State != AIStateChanged && sig.State != AIStateGone {
			continue
		}
		payload := BuildAIDiscoveryPayload(sig, report.Summary.ScanID, PayloadOpts{
			DisableRedaction:   opts.DisableRedaction,
			StoreRawLocalPaths: opts.StoreRawLocalPaths,
			Confidence:         snap.LookupSignal(sig),
		})
		s.events.Emit(gatewaylog.Event{
			EventType:   gatewaylog.EventAIDiscovery,
			Severity:    gatewaylog.SeverityInfo,
			AIDiscovery: payload,
		})
	}
}

// componentSignalGroup is one rollup row's worth of state used by
// the OTel emitter. Capturing the canonical ecosystem / name
// strings (first non-empty wins, matching gateway.rollupComponents)
// keeps the OTel labels stable across scans even when a later
// signal in the same group has the field zeroed.
type componentSignalGroup struct {
	Ecosystem          string
	Name               string
	Framework          string
	Signals            []AISignal
	WorkspaceCount     int
	HasLifecycleChange bool
}

// componentKey is the dedupe key for AI components. Lowercased
// ecosystem + name so the OTel emitter and the API rollup
// (gateway.rollupComponents) always agree on which signals belong
// to the same SDK regardless of detector capitalization.
//
// We intentionally use a struct (rather than a delimited string)
// so untrusted input can't collide via an embedded NUL byte.
type componentKey struct {
	ecosystem string
	name      string
}

func keyForComponent(c *AIComponent) (componentKey, bool) {
	if c == nil || c.Name == "" {
		return componentKey{}, false
	}
	return componentKey{
		ecosystem: strings.ToLower(c.Ecosystem),
		name:      strings.ToLower(c.Name),
	}, true
}

// productKey is the secondary dedupe key for AI products that
// don't map to an (ecosystem, name) component -- CLI binaries
// (Claude Code, Cursor, Codex), desktop apps (Claude Desktop),
// MCP-only entries (Hermes Agent), and shell-history-derived
// products (Open WebUI, LocalAI). The confidence engine still
// computes one score per product so the API / CLI / TUI can
// surface high-fidelity identity / presence on those rows the
// same way they do for component-bearing SDKs.
//
// Lowercased so vendor casing inconsistencies in the catalog
// (e.g. "Anysphere" vs "anysphere") don't fragment the rollup.
// Vendor is part of the key so two different vendors that ship a
// product with the same name (rare but possible) stay separate.
type productKey struct {
	vendor  string
	product string
}

// keyForProduct extracts the (vendor, product) pair from a
// signal. Returns ok=false when EITHER side is empty -- those
// signals stay un-enriched on the wire (the engine has no
// stable identity to attach the score to). The catch-all
// "AI SDKs" / "Multiple" rollup signal does have both fields, so
// it gets a score too even though it's not super meaningful;
// the alternative (special-casing it) was deemed worse than the
// occasional misleading number.
func keyForProduct(sig AISignal) (productKey, bool) {
	v := strings.ToLower(strings.TrimSpace(sig.Vendor))
	p := strings.ToLower(strings.TrimSpace(sig.Product))
	if v == "" || p == "" {
		return productKey{}, false
	}
	return productKey{vendor: v, product: p}, true
}

// productSignalGroup is the product-keyed analogue of
// componentSignalGroup. Kept separate so the OTel emission path
// can continue to iterate `Groups` (component-only) without
// suddenly producing per-product metric series -- expanding OTel
// cardinality is a separate decision from extending the
// API/CLI/TUI confidence surface, which is what the operator
// actually asked for.
type productSignalGroup struct {
	Vendor             string
	Product            string
	Signals            []AISignal
	WorkspaceCount     int
	HasLifecycleChange bool
}

// componentRollupSnapshot bundles the per-(ecosystem, name)
// signal grouping and the matching scored confidence into one
// pass-by-value blob. Built ONCE per scan in fanoutReport so the
// OTel metrics, OTel logs, and gateway-events fanout all share
// the same numbers (would drift otherwise because each emitter
// would call ComputeComponentConfidence with its own
// time.Now()-derived recency factor). When the consumer doesn't
// need scores (default-config installs with redaction on), the
// Scores map is left nil so emitters know to skip the lookup
// and the rollup work is itself skipped at the call site.
//
// `ProductGroups` / `ProductScores` carry the parallel
// per-(vendor, product) rollup for signals that do NOT have a
// component (CLI binaries, desktop apps, MCP entries, etc.).
// These exist so the API / CLI / TUI can surface confidence on
// every row -- including Claude Code / Cursor / Codex -- not
// just SDK rows. They are intentionally NOT consumed by the
// OTel emitter so per-product cardinality doesn't leak into
// metric series without an explicit decision.
type componentRollupSnapshot struct {
	Groups        []componentSignalGroup
	Scores        map[componentKey]*ConfidenceResult
	ProductGroups []productSignalGroup
	ProductScores map[productKey]*ConfidenceResult
}

// ScoreFor returns the precomputed confidence for one group.
// ok=false means the snapshot was built without scores (because
// no consumer needed them) or the engine produced no result for
// this key (defensive — should never happen in practice).
func (s componentRollupSnapshot) ScoreFor(g componentSignalGroup) (ConfidenceResult, bool) {
	if s.Scores == nil {
		return ConfidenceResult{}, false
	}
	c, ok := s.Scores[componentKey{
		ecosystem: strings.ToLower(g.Ecosystem),
		name:      strings.ToLower(g.Name),
	}]
	if !ok || c == nil {
		return ConfidenceResult{}, false
	}
	return *c, true
}

// LookupSignal returns the score pointer for the component this
// signal belongs to. Falls through to the per-(vendor, product)
// rollup when the signal has no component block so non-SDK
// rows (Claude Code, Cursor, Codex, ...) get confidence on the
// API / CLI / TUI surfaces too. Returns nil only for signals
// that have neither a component nor a vendor+product pair --
// nil is the documented signal to BuildAIDiscoveryPayload that
// the wire payload should not carry confidence fields.
func (s componentRollupSnapshot) LookupSignal(sig AISignal) *ConfidenceResult {
	if k, ok := keyForComponent(sig.Component); ok && s.Scores != nil {
		if c, found := s.Scores[k]; found && c != nil {
			return c
		}
	}
	if s.ProductScores != nil {
		if k, ok := keyForProduct(sig); ok {
			return s.ProductScores[k]
		}
	}
	return nil
}

// groupSignalsForRollup buckets signals by lowercased (ecosystem,
// name) -- matching gateway.rollupComponents so a single
// "openai" emission covers PyPI's openai package no matter how
// many manifests / processes contributed. Workspace and lifecycle
// metadata is summarized inline to avoid a second pass.
func groupSignalsForRollup(signals []AISignal) []componentSignalGroup {
	type bucket struct {
		group      componentSignalGroup
		workspaces map[string]struct{}
	}
	by := map[componentKey]*bucket{}
	order := []componentKey{}
	for _, sig := range signals {
		if sig.State == AIStateGone {
			continue
		}
		k, ok := keyForComponent(sig.Component)
		if !ok {
			continue
		}
		b := by[k]
		if b == nil {
			b = &bucket{
				group: componentSignalGroup{
					Ecosystem: sig.Component.Ecosystem,
					Name:      sig.Component.Name,
					Framework: sig.Component.Framework,
				},
				workspaces: map[string]struct{}{},
			}
			by[k] = b
			order = append(order, k)
		}
		// First-non-empty wins for Framework so the OTel label
		// matches the API rollup even when the first signal in
		// the group lacks the field.
		if b.group.Framework == "" && sig.Component.Framework != "" {
			b.group.Framework = sig.Component.Framework
		}
		if sig.WorkspaceHash != "" {
			b.workspaces[sig.WorkspaceHash] = struct{}{}
		}
		if sig.State == AIStateNew || sig.State == AIStateChanged || sig.State == AIStateGone {
			b.group.HasLifecycleChange = true
		}
		b.group.Signals = append(b.group.Signals, sig)
	}
	out := make([]componentSignalGroup, 0, len(by))
	for _, k := range order {
		b := by[k]
		b.group.WorkspaceCount = len(b.workspaces)
		out = append(out, b.group)
	}
	return out
}

// groupSignalsByProduct buckets signals WITHOUT a component
// block by lowercased (vendor, product). Signals that DO have a
// component are deliberately excluded -- they're already scored
// by `groupSignalsForRollup`, and double-counting them via a
// product-keyed group would inflate the LR sum. Workspace and
// lifecycle metadata is summarized inline (mirrors
// `groupSignalsForRollup`) so the per-product OTel attrs we may
// add in the future have the same shape as the per-component
// ones.
func groupSignalsByProduct(signals []AISignal) []productSignalGroup {
	type bucket struct {
		group      productSignalGroup
		workspaces map[string]struct{}
	}
	by := map[productKey]*bucket{}
	order := []productKey{}
	for _, sig := range signals {
		if sig.State == AIStateGone {
			continue
		}
		// Skip component-bearing signals -- those are already
		// covered by the per-component rollup and adding them
		// here would double-count their LR contributions.
		if _, hasComp := keyForComponent(sig.Component); hasComp {
			continue
		}
		k, ok := keyForProduct(sig)
		if !ok {
			continue
		}
		b := by[k]
		if b == nil {
			b = &bucket{
				group: productSignalGroup{
					Vendor:  sig.Vendor,
					Product: sig.Product,
				},
				workspaces: map[string]struct{}{},
			}
			by[k] = b
			order = append(order, k)
		}
		if sig.WorkspaceHash != "" {
			b.workspaces[sig.WorkspaceHash] = struct{}{}
		}
		if sig.State == AIStateNew || sig.State == AIStateChanged || sig.State == AIStateGone {
			b.group.HasLifecycleChange = true
		}
		b.group.Signals = append(b.group.Signals, sig)
	}
	out := make([]productSignalGroup, 0, len(by))
	for _, k := range order {
		b := by[k]
		b.group.WorkspaceCount = len(b.workspaces)
		out = append(out, b.group)
	}
	return out
}

// buildComponentRollupSnapshot is the single source of truth for
// per-component AND per-(vendor, product) scoring during one
// scan. Both the OTel emitter and the gateway-events fanout
// consume the component half of the result so they publish
// byte-identical numbers. The product half is consumed by
// `EnrichSignalsWithComponentConfidence` so the API / CLI / TUI
// surface confidence on rows that don't have a component (CLI
// binaries, desktop apps, MCP entries, etc.). `now` is captured
// ONCE so the recency factor in ComputeComponentConfidence is
// the same across every group's presence calculation in this
// scan -- otherwise an SDK row computed at t and a CLI row
// computed at t+ε could differ by tenths of a percent and the
// "engine numbers must agree across surfaces" invariant breaks.
func buildComponentRollupSnapshot(signals []AISignal, params ConfidenceParams) componentRollupSnapshot {
	groups := groupSignalsForRollup(signals)
	productGroups := groupSignalsByProduct(signals)
	// Both empty: nothing to score. Returning the zero value
	// preserves the documented "snap.Scores == nil means skip
	// emission" contract for downstream emitters.
	if len(groups) == 0 && len(productGroups) == 0 {
		return componentRollupSnapshot{}
	}
	now := time.Now().UTC()
	var scores map[componentKey]*ConfidenceResult
	if len(groups) > 0 {
		scores = make(map[componentKey]*ConfidenceResult, len(groups))
		for i := range groups {
			// Index into the slice (rather than using a copy
			// via `for _, g := range groups`) so the entry we
			// put in the map points at storage owned by this
			// snapshot. Go 1.22+ already gives per-iteration
			// variable scope so taking &conf would be safe;
			// keeping the slice indexing makes the lifetime
			// explicit anyway.
			g := &groups[i]
			conf := ComputeComponentConfidence(g.Signals, now, params)
			scores[componentKey{
				ecosystem: strings.ToLower(g.Ecosystem),
				name:      strings.ToLower(g.Name),
			}] = &conf
		}
	}
	var productScores map[productKey]*ConfidenceResult
	if len(productGroups) > 0 {
		productScores = make(map[productKey]*ConfidenceResult, len(productGroups))
		for i := range productGroups {
			g := &productGroups[i]
			conf := ComputeComponentConfidence(g.Signals, now, params)
			productScores[productKey{
				vendor:  strings.ToLower(g.Vendor),
				product: strings.ToLower(g.Product),
			}] = &conf
		}
	}
	return componentRollupSnapshot{
		Groups:        groups,
		Scores:        scores,
		ProductGroups: productGroups,
		ProductScores: productScores,
	}
}

// EnrichSignalsWithComponentConfidence stamps the per-component
// (or per-product, when there is no component) identity /
// presence scores + bands onto each signal in-place. It is safe
// to call on a clone returned from Snapshot() (the API path) but
// DO NOT call it on data that gets persisted -- the fields are
// intentionally left zero on the in-memory state and on disk so
// the engine output is the single source of truth and no stale
// snapshot can drift.
//
// Signals that have neither a Component block nor a vendor +
// product pair keep zero scores and bands; `omitempty` then
// hides them on the wire so legacy consumers don't see noisy
// nulls. The same `componentRollupSnapshot` the OTel +
// gateway-events fanout uses is built here so the CLI
// (`agent usage --detail`), the API (`/api/v1/ai-usage`), the
// metrics histogram, and the per-signal payloads on the events
// bus all report byte-identical numbers for one scan -- with
// the explicit caveat that the OTel emitter intentionally only
// publishes per-COMPONENT scores (not per-product) so we don't
// quietly expand metric cardinality.
func EnrichSignalsWithComponentConfidence(signals []AISignal, params ConfidenceParams) {
	if len(signals) == 0 {
		return
	}
	snap := buildComponentRollupSnapshot(signals, params)
	// Skip enrichment only when BOTH score maps are empty --
	// otherwise a workspace with only CLI / process products
	// (no SDK manifests) would silently lose the new
	// per-product scores, which is exactly what we just added
	// this codepath for.
	if snap.Scores == nil && snap.ProductScores == nil {
		return
	}
	for i := range signals {
		conf := snap.LookupSignal(signals[i])
		if conf == nil {
			continue
		}
		signals[i].IdentityScore = clampPayloadScore(conf.IdentityScore)
		signals[i].IdentityBand = conf.IdentityBand
		signals[i].PresenceScore = clampPayloadScore(conf.PresenceScore)
		signals[i].PresenceBand = conf.PresenceBand
	}
}

func buildComponentConfidenceAttrs(g componentSignalGroup, conf ConfidenceResult, policyVersion int) telemetry.AIComponentConfidenceAttrs {
	return telemetry.AIComponentConfidenceAttrs{
		Ecosystem:      g.Ecosystem,
		Name:           g.Name,
		Framework:      g.Framework,
		IdentityScore:  conf.IdentityScore,
		IdentityBand:   conf.IdentityBand,
		PresenceScore:  conf.PresenceScore,
		PresenceBand:   conf.PresenceBand,
		InstallCount:   len(g.Signals),
		WorkspaceCount: g.WorkspaceCount,
		PolicyVersion:  policyVersion,
		DetectorCount:  len(conf.Detectors),
	}
}

// PayloadOpts is the privacy-flag bundle threaded into
// BuildAIDiscoveryPayload. Two flags compose: extended fields ride
// on DisableRedaction; raw paths additionally require
// StoreRawLocalPaths so an operator who set DisableRedaction = true
// but kept StoreRawLocalPaths = false (the default) still gets
// scrubbed RawPath values on the wire.
//
// Confidence is the optional per-component confidence result
// shared across every signal in the same (ecosystem, name) group.
// When set and DisableRedaction is true, the helper stamps the
// identity / presence score, band, factors, and detector list on
// the wire payload so downstream OTel + webhook receivers can
// dedupe and alert on the engine output without re-running it.
type PayloadOpts struct {
	DisableRedaction   bool
	StoreRawLocalPaths bool
	Confidence         *ConfidenceResult
}

// BuildAIDiscoveryPayload renders an AISignal into the wire-format
// gatewaylog.AIDiscoveryPayload, applying the privacy-flag
// composition described on AIDiscoveryPayload. Exposed as a
// standalone helper (rather than a method) so external integrations
// (test harnesses, sample event generators, eBPF probes) can build
// payloads identical to what the sidecar emits.
func BuildAIDiscoveryPayload(sig AISignal, scanID string, opts PayloadOpts) *gatewaylog.AIDiscoveryPayload {
	out := &gatewaylog.AIDiscoveryPayload{
		ScanID:        scanID,
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
	}
	if !sig.LastSeen.IsZero() {
		out.LastSeen = sig.LastSeen.UTC().Format(time.RFC3339)
	}
	if !opts.DisableRedaction {
		// Redacted mode: ship only the minimal set above. Extended
		// fields stay zero so omitempty hides them from receivers.
		return out
	}
	// Extended mode: every field below ships so downstream OTel /
	// webhook consumers can do their own confidence rendering and
	// dedupe on (component.ecosystem, component.name).
	out.Detector = sig.Detector
	if sig.Component != nil {
		out.Component = &gatewaylog.AIDiscoveryComponent{
			Ecosystem: sig.Component.Ecosystem,
			Name:      sig.Component.Name,
			Version:   sig.Component.Version,
			Framework: sig.Component.Framework,
		}
	}
	if sig.Runtime != nil {
		started := ""
		if !sig.Runtime.StartedAt.IsZero() {
			started = sig.Runtime.StartedAt.UTC().Format(time.RFC3339)
		}
		out.Runtime = &gatewaylog.AIDiscoveryRuntime{
			PID:       sig.Runtime.PID,
			PPID:      sig.Runtime.PPID,
			StartedAt: started,
			UptimeSec: sig.Runtime.UptimeSec,
			User:      sig.Runtime.User,
			Comm:      sig.Runtime.Comm,
		}
	}
	if sig.LastActiveAt != nil && !sig.LastActiveAt.IsZero() {
		out.LastActiveAt = sig.LastActiveAt.UTC().Format(time.RFC3339)
	}
	if len(sig.Evidence) > 0 {
		evidence := make([]gatewaylog.AIDiscoveryEvidence, 0, len(sig.Evidence))
		var rawPaths []string
		for _, ev := range sig.Evidence {
			row := gatewaylog.AIDiscoveryEvidence{
				Type:          ev.Type,
				Basename:      ev.Basename,
				PathHash:      ev.PathHash,
				ValueHash:     ev.ValueHash,
				WorkspaceHash: ev.WorkspaceHash,
				Quality:       ev.Quality,
				MatchKind:     ev.MatchKind,
			}
			if opts.StoreRawLocalPaths {
				row.RawPath = ev.RawPath
				if ev.RawPath != "" {
					rawPaths = append(rawPaths, ev.RawPath)
				}
			}
			evidence = append(evidence, row)
		}
		out.Evidence = evidence
		if len(rawPaths) > 0 {
			out.RawPaths = rawPaths
		}
	}
	if opts.Confidence != nil {
		conf := opts.Confidence
		// Engine output is in [0,1] but we don't trust callers
		// to have validated; clamp on the wire so a corrupt
		// snapshot can't ship NaN to a downstream histogram.
		out.IdentityScore = clampPayloadScore(conf.IdentityScore)
		out.IdentityBand = conf.IdentityBand
		out.PresenceScore = clampPayloadScore(conf.PresenceScore)
		out.PresenceBand = conf.PresenceBand
		if len(conf.IdentityFactors) > 0 {
			out.IdentityFactors = wireFactors(conf.IdentityFactors)
		}
		if len(conf.PresenceFactors) > 0 {
			out.PresenceFactors = wireFactors(conf.PresenceFactors)
		}
		if len(conf.Detectors) > 0 {
			detectors := make([]string, len(conf.Detectors))
			copy(detectors, conf.Detectors)
			out.Detectors = detectors
		}
	}
	return out
}

// clampPayloadScore mirrors the OTel-side clamp so the wire
// payload and the metrics never disagree on the score range. Kept
// in this package (rather than imported from telemetry) so the
// inventory package stays free of telemetry's dependency tree --
// matters for unit tests that build payloads without spinning up
// an OTel provider.
func clampPayloadScore(v float64) float64 {
	if v != v { // NaN
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// wireFactors renders ConfidenceFactor rows into the JSON wire
// shape downstream sinks expect. We allocate a fresh slice (rather
// than aliasing) so a downstream sink that mutates its received
// payload can't poison the engine's in-memory result.
func wireFactors(in []ConfidenceFactor) []gatewaylog.AIDiscoveryFactor {
	out := make([]gatewaylog.AIDiscoveryFactor, 0, len(in))
	for _, f := range in {
		out = append(out, gatewaylog.AIDiscoveryFactor{
			Detector:    f.Detector,
			EvidenceID:  f.EvidenceID,
			MatchKind:   f.MatchKind,
			Quality:     f.Quality,
			Specificity: f.Specificity,
			LR:          f.LR,
			LogitDelta:  f.LogitDelta,
		})
	}
	return out
}

// AISourceExternal is the value forcibly written into AIDiscoveryReport
// summary.source / signal.source whenever IngestExternalReport accepts a
// report. The internal sidecar scanner uses "sidecar" (see
// signalFromEvidence and runScan); keeping the two values distinct
// means downstream OTel queries can filter on a source the CLI cannot
// forge.
const AISourceExternal = "external"

// IngestExternalReport validates and records sanitized reports from external
// discovery clients. It does not merge raw evidence into local state.
//
// SECURITY (M-5): the CLI controls the entire report body, including
// summary.source and per-signal source. The previous implementation
// trusted both, so a malicious CLI could send {"summary":{"source":
// "sidecar"}, "signals":[{"source":"sidecar", ...}]} and the gateway
// would emit OTel + gateway events that looked indistinguishable from
// signals the local sidecar scanner produced. We now force-attribute
// every external report to AISourceExternal before any telemetry or
// audit fanout runs, so the "sidecar" attribution stays unforgeable.
//
// The report is taken by pointer so the rewrite is visible to callers
// (handleAIUsageDiscovery passes its decoded body directly here, and
// any subsequent reuse of the same struct must observe the forced
// attribution).
func (s *ContinuousDiscoveryService) IngestExternalReport(ctx context.Context, report *AIDiscoveryReport) error {
	if s == nil {
		return errors.New("ai discovery disabled")
	}
	if report == nil {
		return errors.New("missing report")
	}
	if err := ValidateSanitizedAIDiscoveryReport(*report); err != nil {
		return err
	}
	report.Summary.Source = AISourceExternal
	for i := range report.Signals {
		report.Signals[i].Source = AISourceExternal
	}
	s.fanoutReport(ctx, *report)
	return nil
}

func ValidateSanitizedAIDiscoveryReport(report AIDiscoveryReport) error {
	if strings.TrimSpace(report.Summary.ScanID) == "" {
		return errors.New("scan_id is required")
	}
	// Cap raised from 256 → 4096 because the v2 detector emits one
	// signal per matched component rather than one per signature, so
	// reports from realistic monorepos legitimately carry hundreds to
	// low thousands of rows. The cap still bounds adversarial input.
	if len(report.Signals) > 4096 {
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
		// Phase-2 evidence bounds: keep the per-signal Evidence
		// list finite and reject obviously hostile rows. We still
		// allow Quality > 1 / < 0 to be normalized later by the
		// engine, so the only hard failure is the count cap.
		if len(sig.Evidence) > maxEvidencePerSignal {
			return fmt.Errorf("signal %q has %d evidence rows (max %d)", sig.SignalID, len(sig.Evidence), maxEvidencePerSignal)
		}
		for _, ev := range sig.Evidence {
			if ev.PathHash != "" && !isSHA256Hash(ev.PathHash) {
				return errors.New("evidence path_hash must be sha256:<64 hex>")
			}
			if ev.Basename != "" && (strings.Contains(ev.Basename, "/") || strings.Contains(ev.Basename, "\\")) {
				return errors.New("evidence basename must not contain path separators")
			}
		}
	}
	return nil
}

// SanitizeEvidenceForWire scrubs every AISignal.Evidence row to
// match the operator's privacy stance:
//
//   - When `disableRedaction` is false (the default), RawPath is
//     unconditionally cleared and Quality / MatchKind are kept (those
//     are not sensitive).
//   - When `disableRedaction` is true, RawPath is preserved only when
//     `storeRawLocalPaths` is also true -- the two flags compose so a
//     casual `disable_redaction: true` does not silently start
//     shipping local paths on the wire if the operator has not
//     explicitly opted into raw-path storage.
//
// The function operates in-place on the slice header but copies each
// AIEvidence value before mutating, so the caller's underlying slice
// data is not modified.
func SanitizeEvidenceForWire(signals []AISignal, disableRedaction, storeRawLocalPaths bool) {
	for i := range signals {
		if len(signals[i].Evidence) == 0 {
			continue
		}
		out := make([]AIEvidence, len(signals[i].Evidence))
		for j, ev := range signals[i].Evidence {
			if !(disableRedaction && storeRawLocalPaths) {
				ev.RawPath = ""
			}
			out[j] = ev
		}
		signals[i].Evidence = out
	}
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
	// v1 → v2 migration: v1 had no per-stored EvidenceHash on disk
	// (the field was `json:"-"` on AISignal so the JSON encoder dropped
	// it). We accept v1 files transparently — entries land with empty
	// EvidenceHash, and `classifyAndPersist` skips the hash comparison
	// when the stored side is empty so the upgrade does not flood the
	// operator with spurious "changed" rows.
	//
	// Future / unknown versions are surfaced as errors so a forward-
	// version state file (e.g. written by a newer gateway and then
	// read by an older one) doesn't silently look like an empty
	// inventory and produce spurious "all new" change events.
	if out.Version != 1 && out.Version != aiDiscoveryStateVersion {
		return aiStateFile{}, fmt.Errorf("ai-discovery state file at %s has unsupported version %d (expected 1 or %d)", s.path, out.Version, aiDiscoveryStateVersion)
	}
	if out.Signals == nil {
		out.Signals = map[string]aiStoredSignal{}
	}
	// Rehydrate the in-memory AISignal.{EvidenceHash,Evidence} from
	// their stored mirrors so the rest of the code path can keep
	// reading those struct fields (the rest of the service is unaware
	// that they live on the stored wrapper).
	for fp, stored := range out.Signals {
		if stored.AISignal.EvidenceHash == "" && stored.StoredEvidenceHash != "" {
			stored.AISignal.EvidenceHash = stored.StoredEvidenceHash
		}
		if len(stored.AISignal.Evidence) == 0 && len(stored.StoredEvidence) > 0 {
			stored.AISignal.Evidence = stored.StoredEvidence
		}
		out.Signals[fp] = stored
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
	// Mirror the in-memory hash/evidence onto the stored wrapper so
	// they actually persist (the AISignal fields themselves are
	// `json:"-"`). This is the write half of the v2 migration above.
	for fp, stored := range state.Signals {
		if stored.StoredEvidenceHash == "" && stored.AISignal.EvidenceHash != "" {
			stored.StoredEvidenceHash = stored.AISignal.EvidenceHash
		}
		if len(stored.StoredEvidence) == 0 && len(stored.AISignal.Evidence) > 0 {
			stored.StoredEvidence = stored.AISignal.Evidence
		}
		state.Signals[fp] = stored
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

// processInfo is the per-process snapshot record returned by
// processSnapshot(). It carries enough fidelity to render in CLI/TUI
// "active processes" views (PID, start time, uptime, user) without
// ever exporting a full argv (which can contain secrets, prompts, or
// workspace paths). Full argv stays gated behind StoreRawLocalPaths
// via the existing per-evidence raw path mechanism.
type processInfo struct {
	PID       int
	PPID      int
	User      string
	Comm      string
	StartedAt time.Time
}

// processNames is kept for backward compatibility with existing
// callers and tests that only care about the process basename. The
// new code path (detectProcesses) uses processSnapshot() instead.
func processNames() ([]string, error) {
	infos, err := processSnapshot()
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(infos))
	for _, p := range infos {
		out = append(out, p.Comm)
	}
	return out, nil
}

// processSnapshot returns one record per running process on POSIX
// systems via `ps`, or an empty slice on Windows (the equivalent
// `tasklist` parse is intentionally TODO'd; falling back to empty is
// safe — discovery just won't emit `process` signals on Windows).
//
// The fields requested are: pid, ppid, user, comm, etime — exactly
// what's needed to compute uptime + a "last invoked" timestamp without
// reading proc internals or pulling in a third-party process library.
//
// Privacy posture: we deliberately do NOT request `args` or `command`
// here. The full command line can carry secrets (API keys passed as
// CLI flags), prompts, or local paths. Operators who explicitly want
// argv must enable `StoreRawLocalPaths`, at which point `comm` plus
// the per-evidence `RawPath` already cover the legitimate use cases.
func processSnapshot() ([]processInfo, error) {
	if runtime.GOOS == "windows" {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// `etime` is requested last because some `ps` builds emit a
	// trailing space-padded value; we tokenise on whitespace and the
	// last column captures the entire etime string.
	cmd := exec.CommandContext(ctx, "ps", "-axo", "pid=,ppid=,user=,comm=,etime=")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var infos []processInfo
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		ppid, _ := strconv.Atoi(fields[1])
		user := fields[2]
		// `comm` may itself contain spaces (rare but legal); join
		// everything between user and the trailing etime token.
		comm := strings.ToLower(filepath.Base(strings.Join(fields[3:len(fields)-1], " ")))
		etime := fields[len(fields)-1]
		started := now.Add(-parsePsEtime(etime))
		infos = append(infos, processInfo{
			PID:       pid,
			PPID:      ppid,
			User:      user,
			Comm:      comm,
			StartedAt: started,
		})
	}
	return infos, nil
}

// parsePsEtime parses the elapsed-time format ps emits with
// `-o etime=`: `[[dd-]hh:]mm:ss`. Returns zero on parse failure so
// downstream code degrades gracefully (we just don't have a start
// time for that process).
func parsePsEtime(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	days := 0
	if idx := strings.IndexByte(value, '-'); idx >= 0 {
		d, err := strconv.Atoi(value[:idx])
		if err != nil {
			return 0
		}
		days = d
		value = value[idx+1:]
	}
	parts := strings.Split(value, ":")
	if len(parts) == 0 || len(parts) > 3 {
		return 0
	}
	var hours, minutes, seconds int
	switch len(parts) {
	case 3:
		hours, _ = strconv.Atoi(parts[0])
		minutes, _ = strconv.Atoi(parts[1])
		seconds, _ = strconv.Atoi(parts[2])
	case 2:
		minutes, _ = strconv.Atoi(parts[0])
		seconds, _ = strconv.Atoi(parts[1])
	case 1:
		seconds, _ = strconv.Atoi(parts[0])
	}
	return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second
}

// processCommExactlyEquals reports whether `have` is byte-for-byte
// equal (after path-stripping and case-folding) to `want`. The
// confidence engine uses this to distinguish "exact" matches (which
// get full Quality=1.0) from substring matches that succeed via the
// fall-through in processNameMatches.
func processCommExactlyEquals(have, want string) bool {
	have = strings.ToLower(strings.TrimSpace(filepath.Base(have)))
	want = strings.ToLower(strings.TrimSpace(filepath.Base(want)))
	if have == "" || want == "" {
		return false
	}
	return have == want
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

// projectRootForManifest walks UP from a manifest file path to the
// nearest enclosing project root, treating dependency-cache
// directories as opaque. The intent is to give the operator
// per-project counts ("ai (npm) installed in 5 projects") instead
// of per-manifest counts ("685 package.json hits") -- the latter
// is dominated by transitive `node_modules/<dep>/package.json`
// records that all describe ONE installation.
//
// Heuristic, in order:
//
//  1. If any ancestor is a known dependency-cache segment
//     (`node_modules`, `vendor`, `site-packages`, `.venv`,
//     `venv`, `.cargo/registry`, `__pypackages__`, `bower_components`,
//     `.pnpm-store`, `.yarn/cache`), return the ancestor IMMEDIATELY
//     ABOVE that segment. That's the project that pulled the dep
//     in transitively, regardless of how deep the cache nests.
//
//  2. Otherwise, return the manifest's immediate dir (status quo).
//
// We deliberately don't try to find a `.git` root -- monorepos and
// embedded sub-projects make that ambiguous, and the cache-segment
// heuristic above already captures the 99% case.
func projectRootForManifest(path string) string {
	// Single-segment cache directories that mark "we are now
	// inside a transitive install tree owned by the parent
	// project". Lowercased for case-insensitive match.
	cacheSegments := map[string]bool{
		"node_modules":     true,
		"vendor":           true,
		"site-packages":    true,
		".venv":            true,
		"venv":             true,
		"__pypackages__":   true,
		"bower_components": true,
		".pnpm-store":      true,
	}
	dir := filepath.Dir(path)
	parts := strings.Split(filepath.ToSlash(dir), "/")
	// Walk SHALLOW → DEEP and stop at the FIRST cache segment.
	// The project root is everything ABOVE that segment. This
	// direction is critical: it makes nested caches like
	// `proj/node_modules/foo/node_modules/bar/...` return
	// `proj` (the OUTERMOST owner), and Python site-packages
	// trees like `proj/.venv/lib/python3.12/site-packages/...`
	// return `proj` (the project that owns the venv) rather
	// than `.venv` itself.
	for i := 1; i < len(parts); i++ {
		seg := strings.ToLower(parts[i])
		// Two-segment caches first so a project with a literal
		// `cache` subdir (legitimate for some build tools)
		// isn't mistaken for `.yarn/cache`. We anchor on the
		// PRECEDING segment so this only fires for the well-
		// known combo.
		if seg == "registry" && i > 0 && strings.ToLower(parts[i-1]) == ".cargo" {
			// Project root is the dir CONTAINING `.cargo` --
			// for `~/.cargo/registry/...` that's the user's
			// home, the natural attribution for global crates.
			return strings.Join(parts[:i-1], "/")
		}
		if seg == "cache" && i > 0 && strings.ToLower(parts[i-1]) == ".yarn" {
			return strings.Join(parts[:i-1], "/")
		}
		if cacheSegments[seg] {
			return strings.Join(parts[:i], "/")
		}
	}
	return dir
}

// shouldSkipDiscoveryDir is the universal "do not descend" rule used
// by the package_manifest detector's filepath.WalkDir.
//
// We deliberately removed `node_modules`, `venv`, `.venv`, and
// `vendor` from the skip-list so the detector can find *installed*
// versions (not just declared ones) in:
//   - Python virtualenvs: `…/site-packages/<pkg>/METADATA` style trees
//     contain the canonical installed version, which `pip freeze`
//     reflects as `pkg==X.Y.Z`.
//   - Node projects: `node_modules/<pkg>/package.json` is the resolved
//     install record; the lockfile alone is brittle (workspaces, peer
//     deps).
//   - Go vendor directories: `vendor/modules.txt` is the canonical
//     resolved-modules list.
//
// We still skip caches, build outputs, and `.git` history. The walker
// is bounded by `opts.MaxFilesPerScan`, so even on large monorepos it
// can't run away — at the cap, the walker short-circuits gracefully.
//
// `__pycache__` and `library` (macOS) stay skipped because they never
// contain manifest data we care about.
func shouldSkipDiscoveryDir(name string) bool {
	switch strings.ToLower(name) {
	case ".git", ".cache", "cache", "dist", "build", "target", "__pycache__", "library":
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

// scanIDCounter is a process-local monotonic counter used as a
// uniqueness fallback when crypto/rand fails. Even if two scans
// collide on time.Now().UnixNano() (rare; doable on virtualized
// clocks) and rand.Read returns an error, the counter guarantees
// every newScanID() call produces a different ID inside a single
// process. atomic so concurrent callers don't trample each other.
var scanIDCounter atomic.Uint64

func newScanID() string {
	var b [8]byte
	pid := os.Getpid()
	count := scanIDCounter.Add(1)
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read failure is exceptional; mix the PID and a
		// monotonic counter into the fallback so collisions
		// across two processes (or two scans inside one) remain
		// impossible. Logging the underlying error helps operators
		// catch entropy starvation.
		fmt.Fprintf(os.Stderr, "[ai-discovery] rand.Read failed; using deterministic fallback scan ID: %v\n", err)
		return fmt.Sprintf("scan-%d-%d-%d", time.Now().UnixNano(), pid, count)
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
