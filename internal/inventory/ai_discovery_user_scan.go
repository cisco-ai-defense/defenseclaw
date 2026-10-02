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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Per-user scans (standalone enterprise profile, Linux and macOS).
//
// The gateway runs as a service account whose sandbox hides every user home
// and every other account's processes, so its own static scan cannot see a
// user's agents, MCP servers, skills, plugins or shell history. The root hook
// guardian therefore starts a worker as each enrolled user that scans only
// that user's home and sees only that user's processes (ScanUserHome). The
// guardian validates the report (SanitizeUserScanReport) and writes it, with
// the account it started the worker for, to a root-owned spool the gateway
// reads through its group (UserScanRecord). The gateway ingests each record
// into its own state on every full scan (detectUserScans), attributing the
// signals to the account named by the guardian, never by the report.

const (
	// AISourceUserScan is the source of every signal a per-user scan found.
	AISourceUserScan = "user_scan"
	// UserScanDirName is the spool directory inside the guardian's
	// authorization directory.
	UserScanDirName = "ai-discovery"
	// UserScanRecordVersion is the spool record schema.
	UserScanRecordVersion = 1
	// MaxUserScanSignals bounds one user's report.
	MaxUserScanSignals = 1024

	maxUserScanRecordBytes = 16 << 20
	maxUserScanField       = 256
	userScanProcessNote    = "provided by per-user scans"
	// localModelArtifactSignatureID is the model_file detector's own
	// signature, which no catalog lists.
	localModelArtifactSignatureID = "local-model-artifact"
)

// UserScanOptions are the discovery settings a per-user scan runs with. The
// guardian takes them from the administrator's config, which the worker
// cannot read.
type UserScanOptions struct {
	Mode                    string   `json:"mode,omitempty"`
	ScanRoots               []string `json:"scan_roots,omitempty"`
	IncludeShellHistory     bool     `json:"include_shell_history,omitempty"`
	IncludePackageManifests bool     `json:"include_package_manifests,omitempty"`
	MaxFilesPerScan         int      `json:"max_files_per_scan,omitempty"`
	MaxFileBytes            int64    `json:"max_file_bytes,omitempty"`
	StoreRawLocalPaths      bool     `json:"store_raw_local_paths,omitempty"`
}

// UserScanOptionsFromConfig keeps the privacy settings of ai_discovery and
// only its home-relative scan roots: a per-user scan reads nothing outside
// the user's home.
func UserScanOptionsFromConfig(cfg *config.Config) UserScanOptions {
	ad := cfg.AIDiscovery
	return UserScanOptions{
		Mode:                    ad.Mode,
		ScanRoots:               homeRelativeScanRoots(ad.ScanRoots),
		IncludeShellHistory:     ad.IncludeShellHistory,
		IncludePackageManifests: ad.IncludePackageManifests,
		MaxFilesPerScan:         ad.MaxFilesPerScan,
		MaxFileBytes:            int64(ad.MaxFileBytes),
		StoreRawLocalPaths:      ad.StoreRawLocalPaths,
	}
}

func homeRelativeScanRoots(roots []string) []string {
	var out []string
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "~" || strings.HasPrefix(root, "~/") {
			out = append(out, root)
		}
	}
	if len(out) == 0 {
		out = []string{"~"}
	}
	return out
}

// UserScanDirForConfig is the spool of the standalone profile on Linux and
// macOS, and empty everywhere else.
func UserScanDirForConfig(cfg *config.Config) string {
	if cfg == nil || !cfg.StandaloneEnterprise() || runtime.GOOS == "windows" {
		return ""
	}
	return filepath.Join(managed.HookGuardianAuthorizationDir(cfg.DataDir), UserScanDirName)
}

// UserScanRecord is one user's spool file, <uid>.json. The guardian writes
// UID and User from the account it started the scan for.
type UserScanRecord struct {
	Version   int               `json:"version"`
	UID       int               `json:"uid"`
	User      string            `json:"user"`
	UpdatedAt time.Time         `json:"updated_at"`
	Report    AIDiscoveryReport `json:"report"`
}

// UserScanPassName is the guardian's pass record in the spool, next to the
// <uid>.json records.
const UserScanPassName = "pass.json"

// maxUserScanPassExtension bounds how long a pass record keeps the users'
// records current, so a guardian that stopped mid-pass cannot keep them
// forever.
const maxUserScanPassExtension = 24 * time.Hour

// UserScanPass is the guardian's record of its scan passes: when the current
// (or last) pass started, whether it is still running, and how long the last
// complete pass took. A pass over many homes can take longer than a record's
// lifetime; the gateway keeps each record current for that much longer, so a
// user's items do not show as gone and then new again while the pass is on
// its way back to them.
type UserScanPass struct {
	Version         int       `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	Running         bool      `json:"running"`
	LastPassSeconds int64     `json:"last_pass_seconds"`
}

// extension is how much longer than the usual lifetime a record stays
// current: the last complete pass's duration, or the running pass's age if
// that is longer.
func (p UserScanPass) extension(now time.Time) time.Duration {
	ext := time.Duration(p.LastPassSeconds) * time.Second
	if p.Running {
		if age := now.Sub(p.StartedAt); age > ext {
			ext = age
		}
	}
	switch {
	case ext < 0:
		return 0
	case ext > maxUserScanPassExtension:
		return maxUserScanPassExtension
	}
	return ext
}

// ReadUserScanPass reads the guardian's pass record; a missing record is the
// zero pass.
func ReadUserScanPass(path string) (UserScanPass, error) {
	var pass UserScanPass
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return pass, nil
	}
	if err != nil {
		return pass, err
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return pass, errors.New("not a regular record within the size limit")
	}
	if err := userScanFileTrustCheck(path); err != nil {
		return pass, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return pass, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pass); err != nil {
		return UserScanPass{}, fmt.Errorf("parse pass record: %w", err)
	}
	if pass.Version != UserScanRecordVersion || pass.LastPassSeconds < 0 {
		return UserScanPass{}, errors.New("unsupported pass record")
	}
	return pass, nil
}

// ScanUserHome runs one full scan of home, as the account that owns it, with
// no state store, history or telemetry. It keeps only evidence inside home
// and the account's own processes; machine-wide surfaces (system binaries,
// application folders, loopback endpoints, the process environment) are
// left to the gateway's own scan.
func ScanUserHome(ctx context.Context, home, account string, uid int, opts UserScanOptions, catalog []AISignature) AIDiscoveryReport {
	start := time.Now()
	home = filepath.Clean(home)
	// The model file detector reports paths with symlinks resolved.
	homeRoots := []string{home}
	if resolved, err := filepath.EvalSymlinks(home); err == nil && filepath.Clean(resolved) != home {
		homeRoots = append(homeRoots, filepath.Clean(resolved))
	}
	svc := &ContinuousDiscoveryService{
		opts: normalizeAIDiscoveryOptions(AIDiscoveryOptions{
			Enabled:                 true,
			Mode:                    opts.Mode,
			ScanRoots:               homeRelativeScanRoots(opts.ScanRoots),
			IncludeShellHistory:     opts.IncludeShellHistory,
			IncludePackageManifests: opts.IncludePackageManifests,
			MaxFilesPerScan:         opts.MaxFilesPerScan,
			MaxFileBytes:            opts.MaxFileBytes,
			// Raw paths decide which evidence lies inside the home; they
			// leave this process only when the administrator keeps them.
			StoreRawLocalPaths: true,
			// Never written: this service has no state store.
			DataDir:  filepath.Join(home, ".defenseclaw"),
			HomeDir:  home,
			HomeDirs: []string{home},
		}),
		catalog:       catalog,
		processOwners: map[string]bool{account: true, strconv.Itoa(uid): true},
	}
	scanID := newScanID()
	signals, stats := svc.scanSignals(ctx, scanID, &aiDiscoveryScanObservation{}, true, nil)
	out := make([]AISignal, 0, len(signals))
	for _, sig := range signals {
		if sig.Detector == "application" || !evidenceInsideHome(sig.Evidence, homeRoots) {
			continue
		}
		if !opts.StoreRawLocalPaths {
			sig.Evidence = evidenceWithoutRawPaths(sig.Evidence)
		}
		// Keep within ValidateUserScanReport: a monorepo can fold more
		// manifests into one package signal than a report may carry.
		if len(sig.Evidence) > maxEvidencePerSignal {
			sig.Evidence = sig.Evidence[:maxEvidencePerSignal]
			sig.Partial, sig.CoverageReason = true, CoverageReasonCapExceeded
		}
		sig.PathHashes = boundedUserScanList(sig.PathHashes)
		sig.Basenames = boundedUserScanList(sig.Basenames)
		sig.SignalID = stableSignalID(sig.Fingerprint)
		sig.Source = AISourceUserScan
		sig.State = AIStateSeen
		out = append(out, sig)
	}
	if len(out) > MaxUserScanSignals {
		out = out[:MaxUserScanSignals]
		stats.Errors++
		stats.DetectorErrors["user_scan"] = "signal limit reached"
	}
	if ctx.Err() != nil {
		stats.Errors++
		stats.DetectorErrors["user_scan"] = "scan time limit reached"
	}
	summary := AIDiscoverySummary{
		ScanID:            scanID,
		ScannedAt:         time.Now().UTC(),
		DurationMs:        time.Since(start).Milliseconds(),
		PrivacyMode:       svc.opts.Mode,
		Source:            AISourceUserScan,
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
	return AIDiscoveryReport{Summary: summary, Signals: out}
}

func boundedUserScanList(values []string) []string {
	if len(values) > maxUserScanField {
		return values[:maxUserScanField]
	}
	return values
}

func evidenceInsideHome(evidence []AIEvidence, homes []string) bool {
	for _, ev := range evidence {
		if ev.RawPath == "" {
			continue
		}
		inside := false
		for _, home := range homes {
			rel, err := filepath.Rel(home, filepath.Clean(ev.RawPath))
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			return false
		}
	}
	return true
}

func evidenceWithoutRawPaths(evidence []AIEvidence) []AIEvidence {
	out := make([]AIEvidence, len(evidence))
	for i, ev := range evidence {
		ev.RawPath = ""
		out[i] = ev
	}
	return out
}

// SanitizeUserScanReport validates a report the scanned user can influence
// and prepares it for the spool: the account it belongs to is the spool
// record's, never the report's.
func SanitizeUserScanReport(report *AIDiscoveryReport, catalog []AISignature, keepRawPaths bool) error {
	if report == nil {
		return errors.New("missing report")
	}
	if err := ValidateUserScanReport(*report, catalog); err != nil {
		return err
	}
	report.Summary.Source = AISourceUserScan
	for i := range report.Signals {
		sig := &report.Signals[i]
		sig.Source = AISourceUserScan
		sig.UserID, sig.UserName = "", ""
		if !keepRawPaths {
			sig.Evidence = evidenceWithoutRawPaths(sig.Evidence)
		}
	}
	return nil
}

// ValidateUserScanReport bounds a per-user report: sanitized-report rules,
// signatures from the catalog it was scanned with, digest fingerprints and
// short printable fields.
func ValidateUserScanReport(report AIDiscoveryReport, catalog []AISignature) error {
	if err := ValidateSanitizedAIDiscoveryReport(report); err != nil {
		return err
	}
	if len(report.Signals) > MaxUserScanSignals {
		return fmt.Errorf("%d signals exceed the per-user limit of %d", len(report.Signals), MaxUserScanSignals)
	}
	if len(report.Summary.DetectorErrors) > maxUserScanField || len(report.Summary.DetectorDurations) > maxUserScanField {
		return errors.New("too many detector entries")
	}
	for name, detail := range report.Summary.DetectorErrors {
		if !userScanText(name, maxUserScanField) || !userScanText(detail, 1024) {
			return errors.New("detector errors must be short printable text")
		}
	}
	known := make(map[string]bool, len(catalog))
	for _, sig := range catalog {
		known[sig.ID] = true
	}
	for _, sig := range report.Signals {
		if !known[sig.SignatureID] && (sig.SignatureID != localModelArtifactSignatureID || sig.Detector != "model_file") {
			return errors.New("signal names a signature outside the scan catalog")
		}
		if !isSHA256Hash(sig.Fingerprint) {
			return errors.New("signal fingerprint must be a sha256 digest")
		}
		fields := []string{sig.Name, sig.Vendor, sig.Product, sig.Detector, sig.Version, sig.SupportedConnector, sig.State, sig.CoverageReason}
		if sig.Runtime != nil {
			if sig.Runtime.PID < 0 || sig.Runtime.PPID < 0 {
				return errors.New("process ids must be non-negative")
			}
			fields = append(fields, sig.Runtime.Comm, sig.Runtime.User)
		}
		if sig.Component != nil {
			fields = append(fields, sig.Component.Ecosystem, sig.Component.Name, sig.Component.Version, sig.Component.Framework)
		}
		if len(sig.Basenames) > maxUserScanField || len(sig.EvidenceTypes) > maxUserScanField || len(sig.PathHashes) > maxUserScanField {
			return errors.New("signal lists are too long")
		}
		fields = append(fields, sig.Basenames...)
		fields = append(fields, sig.EvidenceTypes...)
		for _, ev := range sig.Evidence {
			fields = append(fields, ev.Type, ev.Basename, ev.MatchKind, ev.Origin, ev.ValueHash)
			if !userScanText(ev.RawPath, 4096) {
				return errors.New("evidence paths must be printable")
			}
		}
		for _, value := range fields {
			if !userScanText(value, maxUserScanField) {
				return fmt.Errorf("signal fields must be at most %d printable characters", maxUserScanField)
			}
		}
	}
	return nil
}

func userScanText(value string, limit int) bool {
	return len(value) <= limit && !containsUnicodeControl(value)
}

// userScanFileTrustCheck requires a root-owned record in a root-owned
// directory chain; replaceable in tests.
var userScanFileTrustCheck = func(path string) error {
	return managed.ValidateTrustedFilePath(path, "AI discovery user scan")
}

// detectUserScans reads the spool. A record older than three scan intervals
// (at least 15 minutes), plus the time the guardian's passes take, is
// skipped, so the signals of a user the guardian no longer scans age out as
// gone while a slow pass keeps the others current.
func (s *ContinuousDiscoveryService) detectUserScans(now time.Time) ([]AISignal, int, map[string]string) {
	entries, err := os.ReadDir(s.opts.UserScanDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, map[string]string{"user_scan": err.Error()}
	}
	ttl := 3 * s.opts.ScanInterval
	if ttl < 15*time.Minute {
		ttl = 15 * time.Minute
	}
	var out []AISignal
	files := 0
	errs := map[string]string{}
	if pass, err := ReadUserScanPass(filepath.Join(s.opts.UserScanDir, UserScanPassName)); err != nil {
		errs["user_scan:pass"] = err.Error()
	} else {
		ttl += pass.extension(now)
	}
	for _, entry := range entries {
		uid, ok := strings.CutSuffix(entry.Name(), ".json")
		if !ok || uid == "" || strings.Trim(uid, "0123456789") != "" {
			continue
		}
		record, err := readUserScanRecord(filepath.Join(s.opts.UserScanDir, entry.Name()))
		if err == nil && strconv.Itoa(record.UID) != uid {
			err = errors.New("the record names another uid")
		}
		if err == nil && (record.User == "" || !userScanText(record.User, maxUserScanField) || strings.ContainsAny(record.User, `/\`)) {
			err = errors.New("the record names no valid user")
		}
		if err == nil {
			err = ValidateUserScanReport(record.Report, s.catalog)
		}
		if err != nil {
			errs["user_scan:"+uid] = err.Error()
			continue
		}
		if age := now.Sub(record.UpdatedAt); age > ttl || age < -5*time.Minute {
			continue
		}
		files += record.Report.Summary.FilesScanned
		if record.Report.Summary.Result != "ok" {
			errs["user_scan:"+record.User] = "partial scan: " + userScanDetectorNames(record.Report.Summary.DetectorErrors)
		}
		for _, sig := range record.Report.Signals {
			out = append(out, s.attributeUserScanSignal(sig, uid, record.User))
		}
	}
	return out, files, errs
}

// ReadUserScanRecord reads one spool record (<uid>.json) with the checks the
// gateway applies: a root-owned regular file within the size limit, the
// current schema, and the uid its file name gives. The administrator's
// discovery view reads the spool with it.
func ReadUserScanRecord(path string) (UserScanRecord, error) {
	record, err := readUserScanRecord(path)
	if err == nil && strconv.Itoa(record.UID)+".json" != filepath.Base(path) {
		err = errors.New("the record names another uid")
	}
	return record, err
}

func readUserScanRecord(path string) (UserScanRecord, error) {
	var record UserScanRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxUserScanRecordBytes {
		return record, errors.New("not a regular record within the size limit")
	}
	if err := userScanFileTrustCheck(path); err != nil {
		return record, err
	}
	file, err := os.Open(path)
	if err != nil {
		return record, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxUserScanRecordBytes+1))
	if err != nil {
		return record, err
	}
	if len(data) > maxUserScanRecordBytes {
		return record, errors.New("record exceeds the size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("parse record: %w", err)
	}
	if record.Version != UserScanRecordVersion {
		return record, fmt.Errorf("unsupported record version %d", record.Version)
	}
	return record, nil
}

func userScanDetectorNames(detectorErrors map[string]string) string {
	names := map[string]bool{}
	for name := range detectorErrors {
		name, _, _ = strings.Cut(name, ":")
		names[name] = true
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// attributeUserScanSignal binds a spooled signal to its account. Hashes are
// re-derived in the account's namespace with this installation's key, so two
// users' identical files stay distinct and no digest leaves the gateway in
// the unkeyed form the worker computed.
func (s *ContinuousDiscoveryService) attributeUserScanSignal(sig AISignal, uid, user string) AISignal {
	namespace := func(value string) string {
		if value == "" {
			return ""
		}
		input := "ai-discovery/user-scan/v1\x00" + uid + "\x00" + value
		if key := currentPathHashKey(); len(key) > 0 {
			return "hmac-sha256:" + keyedHashHex(key, input)
		}
		return "sha256:" + hashHex(input)
	}
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
	sig.Source = AISourceUserScan
	sig.UserID, sig.UserName = uid, user
	sig.ModelAPISourceHash = ""
	if sig.Runtime != nil {
		runtimeInfo := *sig.Runtime
		runtimeInfo.User = user
		sig.Runtime = &runtimeInfo
	}
	if sig.Model != nil {
		// Provenance claims are catalog-controlled, as for external reports.
		model := *sig.Model
		model.Provenance = nil
		enrichLocalModelProvenance(&model, modelProvenanceHints{})
		sig.Model = &model
	}
	return sig
}
