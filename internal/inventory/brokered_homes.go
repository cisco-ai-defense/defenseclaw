// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enforce"
)

// Brokered home reads (Cowork VM sensor split mode, cowork-1-0-8 GAP-0008).
//
// In the Claude Cowork VM the gateway runs as the unprivileged account
// defenseclaw-cowork and the session users' homes (/sessions/<name>, 0750)
// are closed to it, so its own config, MCP, skill, rule and plugin detectors
// find nothing there. The root sensor helper, which has no network, serves
// one fieldless request for it (acquire.OpDiscovery): it reads a fixed
// allowlist inside the homes its own root-owned configuration names and
// answers with the facts these detectors need, never a file's contents.
//
//   - The allowlist is the home-relative config, MCP, skill, rule and plugin
//     paths of the embedded signature catalog (NewBrokeredHomeAllowlist),
//     fixed when the helper starts. The request names no path.
//   - A home is read only when it is a real folder owned by an account whose
//     passwd entry names it as that account's home (uid 1000 and up).
//   - Every path is opened one element at a time from the home with
//     O_NOFOLLOW, so a link anywhere is refused, not followed; every element
//     must belong to the home's account, and a file must have a single link,
//     so a hard link to another account's file is refused too.
//   - Only regular files and folders count. Only MCP configs are read, within
//     per-file, per-home and per-request byte caps, and only their server
//     names leave the helper; ~/.claude.json is walked for its names, never
//     decoded whole. Folders give their child names; everything else gives
//     its presence and modification time. Past a home's or the request's
//     share of the answer, an entry keeps its presence and drops its names
//     (cap_exceeded), so the answer always fits the helper's frame.
//
// The gateway checks the answer against the same allowlist and builds the
// signals with the detectors' own constructors (signalFromPath,
// mcpSignalFromNames, directoryChildEvidence), so a brokered config has the
// fingerprint a direct read gives it and the existing redaction rules
// (hashed paths, sanitized basenames, raw paths only with
// store_raw_local_paths) apply unchanged. Brokered signals name the home's
// account and carry source sensor_helper.

const (
	// BrokeredHomeReportVersion is the OpDiscovery body schema. A gateway
	// refuses another version; fields are only ever added.
	BrokeredHomeReportVersion = 1
	// AISourceSensorHelper is the source of every signal a brokered read
	// found.
	AISourceSensorHelper = "sensor_helper"
	brokeredHomeDetector = "sensor_helper"

	maxBrokeredHomes = 256
	// maxBrokeredChildren bounds the child names of one folder, enough for
	// the detectors' own cap of maxEvidencePerSignal rows after filtering.
	maxBrokeredChildren = 2 * maxEvidencePerSignal
	// maxBrokeredPathElements bounds an allowlisted path's depth.
	maxBrokeredPathElements = 8
	// maxBrokeredEntries and maxBrokeredMCPShapes bound one home's answer
	// whatever catalog the helper was built with; the gateway uses only the
	// entries and shapes its own catalog names.
	maxBrokeredEntries      = 4096
	maxBrokeredMCPShapes    = 16
	brokeredHomeReadTimeout = 2 * time.Minute
)

// BrokeredHomeReport is the OpDiscovery body.
type BrokeredHomeReport struct {
	Version int            `json:"version"`
	Homes   []BrokeredHome `json:"homes,omitempty"`
	// FilesRead counts the MCP configs read.
	FilesRead int `json:"files_read,omitempty"`
	// Truncated is a read the home cap, the byte budget or the time limit
	// cut short.
	Truncated bool `json:"truncated,omitempty"`
}

// BrokeredHome is one home the helper read.
type BrokeredHome struct {
	Home    string              `json:"home"`
	UID     int                 `json:"uid"`
	User    string              `json:"user"`
	Entries []BrokeredHomeEntry `json:"entries,omitempty"`
	// Refused counts allowlisted paths the helper would not read: a link,
	// an element another account owns, a file with more than one link, or
	// something that is not a regular file or a folder.
	Refused int `json:"refused,omitempty"`
}

// BrokeredHomeEntry is one allowlisted path that exists in the home.
type BrokeredHomeEntry struct {
	// Path is the allowlist path, relative to the home.
	Path            string `json:"path"`
	Dir             bool   `json:"dir,omitempty"`
	ModTimeUnixNano int64  `json:"mtime_ns,omitempty"`
	// Children are a skills, rules or plugins folder's entries, by name.
	Children          []BrokeredHomeChild `json:"children,omitempty"`
	ChildrenTruncated bool                `json:"children_truncated,omitempty"`
	// MCP is an MCP config's server names, once per config shape the
	// catalog reads it as.
	MCP []BrokeredMCPConfig `json:"mcp,omitempty"`
}

// BrokeredHomeChild is a folder entry.
type BrokeredHomeChild struct {
	Name    string `json:"name"`
	Regular bool   `json:"regular,omitempty"`
}

// BrokeredMCPConfig is the server names of one MCP config.
type BrokeredMCPConfig struct {
	Shape   string   `json:"shape"`
	Servers []string `json:"servers,omitempty"`
	// Partial is the coverage reason of a read that did not name every
	// server: parse_error, or cap_exceeded for a config over the byte caps.
	Partial string `json:"partial,omitempty"`
}

// BrokeredHomeAllowlist is the fixed set of home-relative paths a brokered
// read may open, with what it may learn from each.
type BrokeredHomeAllowlist map[string]brokeredAllowance

type brokeredAllowance struct {
	// MCPShapes are the config shapes the catalog reads the path as.
	MCPShapes []string
	// Children: the path is a skills, rules or plugins folder.
	Children bool
}

// NewBrokeredHomeAllowlist derives the allowlist from catalog: the config,
// MCP, skill, rule and plugin paths under ~ and the relative (project) ones,
// which a scan root of ~ places at the home's top. Paths with a variable, a
// glob or a parent step are left out.
func NewBrokeredHomeAllowlist(catalog []AISignature) BrokeredHomeAllowlist {
	allow := BrokeredHomeAllowlist{}
	add := func(candidate string, mcpConnector *string, children bool) {
		rel, ok := brokeredRelativePath(candidate)
		if !ok {
			return
		}
		entry := allow[rel]
		if mcpConnector != nil {
			shape := brokeredMCPShape(rel, *mcpConnector)
			if !slices.Contains(entry.MCPShapes, shape) {
				entry.MCPShapes = append(entry.MCPShapes, shape)
				sort.Strings(entry.MCPShapes)
			}
		}
		entry.Children = entry.Children || children
		allow[rel] = entry
	}
	for _, sig := range catalog {
		connector := sig.SupportedConnector
		for _, candidate := range sig.ConfigPaths {
			add(candidate, nil, false)
		}
		for _, candidate := range sig.MCPPaths {
			add(candidate, &connector, false)
		}
		for _, paths := range [][]string{sig.SkillPaths, sig.RulePaths, sig.PluginPaths} {
			for _, candidate := range paths {
				add(candidate, nil, true)
			}
		}
	}
	return allow
}

// Paths returns the allowlist in order.
func (a BrokeredHomeAllowlist) Paths() []string {
	out := make([]string, 0, len(a))
	for rel := range a {
		out = append(out, rel)
	}
	sort.Strings(out)
	return out
}

// brokeredRelativePath is a catalog candidate as a path relative to a home:
// ~/x is x, and a relative x is x.
func brokeredRelativePath(candidate string) (string, bool) {
	candidate = strings.TrimSpace(candidate)
	if strings.ContainsAny(candidate, "$*?[\\") {
		return "", false
	}
	switch {
	case strings.HasPrefix(candidate, "~/"):
		candidate = strings.TrimPrefix(candidate, "~/")
	case strings.HasPrefix(candidate, "~"), strings.HasPrefix(candidate, "/"):
		return "", false
	}
	rel := path.Clean(candidate)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") ||
		strings.Count(rel, "/")+1 > maxBrokeredPathElements {
		return "", false
	}
	return rel, true
}

// brokeredMCPShape is the shape signalFromMCPConfigPath reads the MCP config
// at path as outside Secure Client, which never brokers.
func brokeredMCPShape(path, connector string) string {
	if strings.EqualFold(filepath.Base(path), ".claude.json") {
		return mcpShapeClaudeState
	}
	return mcpConfigShape(path, connector)
}

// The gateway's reader of the sensor helper, installed by the gateway when it
// brokers through a root helper (SetBrokeredHomeReader).
var brokeredHomes struct {
	sync.Mutex
	generation uint64
	reader     func(context.Context) (BrokeredHomeReport, error)
}

// ErrBrokeredHomesUnsupported is a sensor helper that predates OpDiscovery.
var ErrBrokeredHomesUnsupported = errors.New("the sensor helper does not serve discovery reads")

// SetBrokeredHomeReader installs reader for later full scans. The returned
// function removes it again unless a later call replaced it.
func SetBrokeredHomeReader(reader func(context.Context) (BrokeredHomeReport, error)) func() {
	brokeredHomes.Lock()
	defer brokeredHomes.Unlock()
	brokeredHomes.generation++
	generation := brokeredHomes.generation
	brokeredHomes.reader = reader
	return func() {
		brokeredHomes.Lock()
		defer brokeredHomes.Unlock()
		if brokeredHomes.generation == generation {
			brokeredHomes.reader = nil
		}
	}
}

func brokeredHomeReaderSnapshot() func(context.Context) (BrokeredHomeReport, error) {
	brokeredHomes.Lock()
	defer brokeredHomes.Unlock()
	return brokeredHomes.reader
}

// brokeredHomesApply: the gateway's own scan. A per-user scan, a sandbox
// scan, the standalone profile (its guardian's per-user scans read the homes)
// and Secure Client never broker.
func (s *ContinuousDiscoveryService) brokeredHomesApply() bool {
	return !s.userHomeScan && s.sandbox == nil && !s.opts.SecureClient && s.opts.UserScanDir == ""
}

// brokeredHomeReadable reports a home the gateway can list itself; its own
// detectors already read a listed home like that. A seam for tests.
var brokeredHomeReadable = func(home string) bool {
	f, err := os.Open(home) // #nosec G304 -- a home from the helper's root-owned configuration
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	return err == nil || errors.Is(err, io.EOF)
}

// detectBrokeredHomes asks the sensor helper for the homes this process
// cannot read and builds their signals. note summarizes the read for the
// scan's detector notes.
func (s *ContinuousDiscoveryService) detectBrokeredHomes(
	ctx context.Context, reader func(context.Context) (BrokeredHomeReport, error),
) (out []AISignal, files int, note string, err error) {
	readCtx, cancel := context.WithTimeout(ctx, brokeredHomeReadTimeout)
	defer cancel()
	report, err := reader(readCtx)
	if errors.Is(err, ErrBrokeredHomesUnsupported) {
		return nil, 0, err.Error(), nil
	}
	if err != nil {
		return nil, 0, "", fmt.Errorf("sensor helper read: %w", err)
	}
	allow := NewBrokeredHomeAllowlist(s.catalog)
	dropped, err := validateBrokeredHomeReport(&report, allow)
	if err != nil {
		return nil, 0, "", fmt.Errorf("sensor helper report refused: %w", err)
	}
	homes, refused := 0, 0
	for _, home := range report.Homes {
		if discoveryHomeListed(s.homesToScan(), home.Home) && brokeredHomeReadable(home.Home) {
			continue
		}
		homes++
		refused += home.Refused
		out = append(out, s.brokeredHomeSignals(home)...)
	}
	note = fmt.Sprintf("%d homes read through the sensor helper", homes)
	if refused > 0 {
		note += fmt.Sprintf("; %d paths refused (a link, an entry another account owns, a hard-linked file or not a regular file)", refused)
	}
	if dropped > 0 {
		note += fmt.Sprintf("; %d entries outside the allowlist ignored", dropped)
	}
	if report.Truncated {
		note += "; the read was cut short by its limits"
	}
	return out, report.FilesRead, note, nil
}

// validateBrokeredHomeReport bounds the helper's answer and drops entries the
// allowlist does not name (a helper built with another catalog). It returns
// how many it dropped.
func validateBrokeredHomeReport(report *BrokeredHomeReport, allow BrokeredHomeAllowlist) (int, error) {
	if report.Version != BrokeredHomeReportVersion {
		return 0, fmt.Errorf("report version %d, this gateway reads %d", report.Version, BrokeredHomeReportVersion)
	}
	if len(report.Homes) > maxBrokeredHomes {
		return 0, fmt.Errorf("%d homes exceed the limit of %d", len(report.Homes), maxBrokeredHomes)
	}
	dropped := 0
	for i := range report.Homes {
		home := &report.Homes[i]
		if !path.IsAbs(home.Home) || path.Clean(home.Home) != home.Home || home.Home == "/" ||
			!userScanText(home.Home, 4096) {
			return 0, errors.New("a home is not a clean absolute path")
		}
		if home.UID < brokeredHomeMinUID || home.User == "" || !userScanText(home.User, maxUserScanField) ||
			strings.ContainsAny(home.User, `/\`) {
			return 0, fmt.Errorf("home %s names no valid account", home.Home)
		}
		if home.Refused < 0 || len(home.Entries) > maxBrokeredEntries {
			return 0, fmt.Errorf("home %s lists too many entries", home.Home)
		}
		kept := home.Entries[:0]
		for _, entry := range home.Entries {
			if _, ok := allow[entry.Path]; !ok {
				dropped++
				continue
			}
			if len(entry.Children) > maxBrokeredChildren || len(entry.MCP) > maxBrokeredMCPShapes ||
				(len(entry.Children) > 0 && !entry.Dir) {
				return 0, fmt.Errorf("home %s: entry %s is out of bounds", home.Home, entry.Path)
			}
			for _, child := range entry.Children {
				if sanitizeBasenameValue(child.Name) != child.Name {
					return 0, fmt.Errorf("home %s: entry %s has an invalid child name", home.Home, entry.Path)
				}
			}
			for _, cfg := range entry.MCP {
				if entry.Dir || !userScanText(cfg.Shape, maxUserScanField) || len(cfg.Servers) > maxEvidencePerSignal ||
					(cfg.Partial != "" && cfg.Partial != CoverageReasonParseError && cfg.Partial != CoverageReasonCapExceeded) {
					return 0, fmt.Errorf("home %s: entry %s has an invalid MCP read", home.Home, entry.Path)
				}
				for _, name := range cfg.Servers {
					if sanitizeBasenameValue(name) != name {
						return 0, fmt.Errorf("home %s: entry %s has an invalid server name", home.Home, entry.Path)
					}
				}
			}
			kept = append(kept, entry)
		}
		home.Entries = kept
	}
	return dropped, nil
}

// brokeredHomeMinUID is the lowest account uid whose home a brokered read
// covers: system accounts own no agent configuration. A seam for tests.
var brokeredHomeMinUID = 1000

// brokeredHomeSignals builds the config, MCP, skill, rule and plugin signals
// of one brokered home as the direct detectors would.
func (s *ContinuousDiscoveryService) brokeredHomeSignals(home BrokeredHome) []AISignal {
	entries := make(map[string]BrokeredHomeEntry, len(home.Entries))
	for _, entry := range home.Entries {
		entries[entry.Path] = entry
	}
	uid := strconv.Itoa(home.UID)
	var out []AISignal
	emit := func(sig AISignal, entry BrokeredHomeEntry) {
		if entry.ModTimeUnixNano > 0 {
			mt := time.Unix(0, entry.ModTimeUnixNano).UTC()
			sig.LastActiveAt = &mt
		}
		sig.UserID, sig.UserName = uid, home.User
		sig.Source = AISourceSensorHelper
		out = append(out, sig)
	}
	for _, sig := range s.catalog {
		for _, candidate := range sig.ConfigPaths {
			for _, rel := range s.brokeredCandidateRels(candidate) {
				if entry, ok := entries[rel]; ok {
					category := SignalWorkspaceArtifact
					if sig.SupportedConnector != "" {
						category = SignalSupportedConnector
					}
					emit(s.signalFromPath(sig, category, "config", filepath.Join(home.Home, rel)), entry)
				}
			}
		}
		for _, candidate := range sig.MCPPaths {
			for _, rel := range s.brokeredCandidateRels(candidate) {
				entry, ok := entries[rel]
				if !ok || entry.Dir {
					continue
				}
				path := filepath.Join(home.Home, rel)
				shape := brokeredMCPShape(path, sig.SupportedConnector)
				for _, cfg := range entry.MCP {
					if cfg.Shape != shape {
						continue
					}
					// A config that declares no server is no MCP server
					// (GAP-2337), as in detectMCPPaths.
					if signal := s.mcpSignalFromNames(sig, path, cfg.Servers, cfg.Partial); declaresMCPServer(signal) {
						emit(signal, entry)
					}
				}
			}
		}
		for _, surface := range []struct {
			paths              []string
			category, detector string
		}{
			{sig.SkillPaths, SignalSkill, "skill"},
			{sig.RulePaths, SignalRule, "rule"},
			{sig.PluginPaths, SignalPlugin, "plugin"},
		} {
			for _, candidate := range surface.paths {
				for _, rel := range s.brokeredCandidateRels(candidate) {
					entry, ok := entries[rel]
					// dirHasEntry: a file, or a folder with an entry.
					if !ok || (entry.Dir && len(entry.Children) == 0 && !entry.ChildrenTruncated) {
						continue
					}
					emit(s.brokeredChildrenSignal(sig, surface.category, surface.detector,
						filepath.Join(home.Home, rel), entry), entry)
				}
			}
		}
	}
	return out
}

// brokeredCandidateRels are the home-relative paths the direct detectors
// expand candidate to in a home: ~/x is x, and a relative x sits below every
// scan root under ~.
func (s *ContinuousDiscoveryService) brokeredCandidateRels(candidate string) []string {
	rel, ok := brokeredRelativePath(candidate)
	if !ok {
		return nil
	}
	if strings.HasPrefix(strings.TrimSpace(candidate), "~/") {
		return []string{rel}
	}
	var out []string
	for _, root := range s.opts.ScanRoots {
		root = strings.TrimSpace(root)
		var joined string
		switch {
		case root == "~":
			joined = rel
		case strings.HasPrefix(root, "~/"):
			joined = path.Join(strings.TrimPrefix(root, "~/"), rel)
		default:
			continue
		}
		if !slices.Contains(out, joined) {
			out = append(out, joined)
		}
	}
	return out
}

// brokeredChildrenSignal is signalFromDirectoryChildren for a brokered
// folder. The helper lists one level; the Hermes skill hierarchy and the
// Codex .system container are not expanded, and say so as a partial signal.
func (s *ContinuousDiscoveryService) brokeredChildrenSignal(sig AISignature, category, detector, path string, entry BrokeredHomeEntry) AISignal {
	base := AIEvidence{Type: detector, Basename: filepath.Base(path), PathHash: hashPath(path)}
	if s.keepEvidencePath() {
		base.RawPath = path
	}
	evidence := []AIEvidence{base}
	var partial bool
	var coverageReason string
	if entry.Dir {
		hermesRoot := detector == "skill" && strings.EqualFold(strings.TrimSpace(sig.ID), "hermes") && s.isHermesSkillsRoot(path)
		if hermesRoot {
			partial, coverageReason = true, CoverageReasonReadError
		}
		for _, child := range entry.Children {
			if hermesRoot {
				break
			}
			if len(evidence) >= maxEvidencePerSignal {
				partial, coverageReason = true, CoverageReasonCapExceeded
				break
			}
			name := sanitizeBasenameValue(child.Name)
			if name == "" {
				continue
			}
			// A hidden file beside the skills is the agent's own state
			// (GAP-2263).
			if detector == "skill" && strings.HasPrefix(child.Name, ".") && child.Regular {
				continue
			}
			if detector == "skill" && strings.EqualFold(strings.TrimSpace(sig.ID), "codex") &&
				enforce.IsBundledSkillContainerName(child.Name) {
				partial = true
				if coverageReason == "" {
					coverageReason = CoverageReasonReadError
				}
				continue
			}
			evidence = append(evidence, s.directoryChildEvidence(detector, path, child.Name, name))
		}
		if entry.ChildrenTruncated && !partial {
			partial, coverageReason = true, CoverageReasonCapExceeded
		}
	}
	out := s.signalFromEvidence(sig, category, detector, evidence)
	s.stampHomeOwner(&out, path)
	out.Partial = partial
	out.CoverageReason = coverageReason
	return out
}
