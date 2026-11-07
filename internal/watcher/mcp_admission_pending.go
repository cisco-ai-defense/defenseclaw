// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"database/sql"
	"errors"
	"net/netip"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/mcpkey"
)

// MCPAdmissionQuery names the MCP server a tool call reaches.
type MCPAdmissionQuery struct {
	// Connector is the hook's connector, Server the server name as the
	// tool call spells it (mcp__<server>__<tool>).
	Connector, Server string
	// Home is the caller's home on a gateway that serves several
	// accounts, "" on a per-user gateway. CWD is the agent's working
	// folder, "" when the hook did not send one.
	Home, CWD string
}

// MCPAdmissionStatus is the current admission state of one configured server.
// An empty state means no pending or failed admission applies to this call.
type MCPAdmissionStatus struct {
	Name        string
	Pending     bool
	Failed      bool
	Unavailable bool
	RetryAfter  time.Duration
	// ScanIssue says, for a Failed server, why DefenseClaw cannot scan it
	// when the definition shows it: MCPScanIssueLauncher or
	// MCPScanIssueAddress. "" when the cause is not known from the
	// definition (the hook then points to defenseclaw mcp list).
	ScanIssue string
}

// The definitions a scan refuses, as the hook and mcp list word them.
const (
	// MCPScanIssueLauncher is a local server started by anything but the
	// bare launchers npx or uvx.
	MCPScanIssueLauncher = "launcher"
	// MCPScanIssueAddress is a server URL on a loopback, private,
	// link-local or multicast address, which the scanner never dials.
	MCPScanIssueAddress = "address"
)

// mcpScanIssue names why the scanner refuses server, from its definition
// alone: the scanner stays the judge, this only words the refusal.
func mcpScanIssue(server config.MCPServerEntry) string {
	if rawURL := strings.TrimSpace(server.URL); rawURL != "" {
		if parsed, err := url.Parse(rawURL); err == nil && mcpLocalHost(parsed.Hostname()) {
			return MCPScanIssueAddress
		}
		return ""
	}
	command := strings.TrimSpace(server.Command)
	if command == "" {
		return ""
	}
	base := strings.ToLower(command)
	if strings.ContainsAny(base, `/\`) {
		return MCPScanIssueLauncher
	}
	if base != "npx" && base != "uvx" {
		return MCPScanIssueLauncher
	}
	return ""
}

func mcpLocalHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// failedMCPStatus is the status of a server whose completed admission scan
// failed, with the cause its definition shows.
func failedMCPStatus(server config.MCPServerEntry) MCPAdmissionStatus {
	return MCPAdmissionStatus{Name: server.Name, Failed: true, ScanIssue: mcpScanIssue(server)}
}

// mcpAdmissionOutcome is the latest completed admission of one definition.
type mcpAdmissionOutcome struct {
	hash   string
	failed bool
}

// noteMCPAdmissionOutcome records the outcome of an admission run on snap's
// definition as soon as it is decided, by (key, hash): a scan failure
// reports as failed, and any other completed outcome (an allow after the
// administrator allowed the server, a clean rescan) reports as not failed,
// whether or not the baseline row is written yet, or could be written at
// all. A run the watcher stopping cut off decides nothing.
func (w *InstallWatcher) noteMCPAdmissionOutcome(evt InstallEvent, snap *TargetSnapshot, res AdmissionResult) {
	if evt.Type != InstallMCP || snap == nil || res.Interrupted || w.secureClientActive() {
		return
	}
	failed := mcpScanFailureBlocked(res) ||
		(res.Verdict == VerdictScanError && keptUnscannedMCPReason(res.Reason))
	w.mcpAdmissionMu.Lock()
	defer w.mcpAdmissionMu.Unlock()
	if w.mcpOutcomes == nil {
		w.mcpOutcomes = map[string]mcpAdmissionOutcome{}
	}
	w.mcpOutcomes[evt.Path] = mcpAdmissionOutcome{hash: snap.ContentHash, failed: failed}
}

// mcpOutcome returns the outcome this process completed for the definition
// with this hash at this key, if no baseline has superseded it.
func (w *InstallWatcher) mcpOutcome(path, hash string) (mcpAdmissionOutcome, bool) {
	w.mcpAdmissionMu.RLock()
	defer w.mcpAdmissionMu.RUnlock()
	known, ok := w.mcpOutcomes[path]
	return known, ok && hash != "" && known.hash == hash
}

// noteMCPBaseline keeps the outcome a written baseline records, so the latest
// verdict this process decided or stored for a definition is the one the hook
// reads, whichever route wrote it. persistSnapshot is the only writer of an
// MCP admission baseline.
func (w *InstallWatcher) noteMCPBaseline(path, hash, fingerprint string) {
	if hash == "" || w.secureClientActive() {
		return
	}
	w.mcpAdmissionMu.Lock()
	defer w.mcpAdmissionMu.Unlock()
	if w.mcpOutcomes == nil {
		w.mcpOutcomes = map[string]mcpAdmissionOutcome{}
	}
	w.mcpOutcomes[path] = mcpAdmissionOutcome{hash: hash, failed: mcpFingerprintFailed(fingerprint)}
}

type mcpKnownDefinition struct {
	server config.MCPServerEntry
	hash   string
	// issue is mcpScanIssue of the definition, kept instead of the command
	// and URL themselves.
	issue string
}

const mcpSnapshotIdentityKey = "mcp.snapshot.identity.v1"

// mcpSnapshotIdentity keeps the fields needed to match a call when the source
// list is unavailable and validates versioned snapshot paths.
type mcpSnapshotIdentity mcpkey.Identity

func mcpIdentityForServer(server config.MCPServerEntry) mcpSnapshotIdentity {
	return mcpSnapshotIdentity{server.Name, server.Connector, server.Home, server.Project}
}

func (identity mcpSnapshotIdentity) server() config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: identity.Name, Connector: identity.Connector, Home: identity.Home, Project: identity.Project,
	}
}

// MCPAdmissionPending reports an MCP server with no admission outcome yet
// and queues admission now (GAP-0112). A server whose definition changed
// since its outcome is pending the same way (GAP-0216). The hook applies the
// selected tier to a pending result. The returned name is the configured one.
//
// A server the first rescan cycle lists at start stays with that cycle,
// which admits or baselines it (an upgrade from 0.8.x only baselines), so
// the calls of a server configured before the start are decided as before.
// Nothing is pending where the watcher does not enforce MCP admission
// (take_action off), where it has no MCP source, before it has listed the
// servers present at start, or on Secure Client (issue #1092).
func (w *InstallWatcher) MCPAdmissionPending(q MCPAdmissionQuery) (string, bool) {
	status := w.MCPAdmissionStatus(q)
	return status.Name, status.Pending
}

// MCPAdmissionStatus distinguishes a scan still in progress from a completed
// scan failure for the server's current definition. A failed scan stays
// visible even when the admission policy kept the server installed.
func (w *InstallWatcher) MCPAdmissionStatus(q MCPAdmissionQuery) MCPAdmissionStatus {
	if w == nil || !w.admitNewMCP || w.store == nil || w.secureClientActive() ||
		strings.TrimSpace(q.Server) == "" {
		return MCPAdmissionStatus{}
	}
	firstCycle := !w.firstCycleDone.Load()
	servers, err := w.readMCPServers()
	if err != nil {
		if failed := w.mcpFailedFromLastRead(q); failed.Failed {
			return failed
		}
		return MCPAdmissionStatus{Name: q.Server, Unavailable: true, RetryAfter: defaultScanTimeout}
	}
	var pending []string
	var pendingPath string
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		path := MCPEventPath(server)
		row, err := mcpSnapshotForServer(w.store, server)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return MCPAdmissionStatus{Name: server.Name, Unavailable: true, RetryAfter: defaultScanTimeout}
		}
		matched := err == nil && mcpBaselineMatches(row, server)
		// A verdict this process decided for this exact definition stands
		// before its baseline is written: a failure is not pending, and an
		// allow that replaces a failure is not held by the old failed
		// baseline (GAP-0775, GAP-0778).
		if hash, hashErr := mcpDefinitionHash(server); hashErr == nil {
			if outcome, ok := w.mcpOutcome(path, hash); ok {
				if outcome.failed {
					return failedMCPStatus(server)
				}
				continue
			}
		}
		if matched && mcpSnapshotFailed(row) {
			return failedMCPStatus(server)
		}
		if matched {
			continue
		}
		if firstCycle && (!w.mcpStartupListed.Load() || w.listedAtStartup(path)) {
			continue
		}
		if !w.takeActionFor(InstallEvent{Type: InstallMCP}) {
			continue
		}
		// No outcome yet, or one for another definition of the server:
		// admission says why when it runs.
		pending = append(pending, server.Name)
		if pendingPath == "" {
			pendingPath = path
		}
	}
	if len(pending) == 0 {
		return MCPAdmissionStatus{}
	}
	w.AdmitAddedMCPServers(pending)
	return MCPAdmissionStatus{Name: pending[0], Pending: true, RetryAfter: w.mcpRetryAfter(pendingPath)}
}

// mcpFailedFromLastRead uses a prior successful listing only to keep a
// completed failed scan effective during a source-list outage. The cache
// holds identity and definition hash, not an old allow or pending verdict.
func (w *InstallWatcher) mcpFailedFromLastRead(q MCPAdmissionQuery) MCPAdmissionStatus {
	w.mcpAdmissionMu.RLock()
	known := append([]mcpKnownDefinition(nil), w.mcpAdmissionKnown...)
	listed := w.mcpAdmissionListed
	w.mcpAdmissionMu.RUnlock()
	for _, definition := range known {
		if definition.server.Bundled || !mcpServerServesQuery(definition.server, q) {
			continue
		}
		row, err := mcpSnapshotForServer(w.store, definition.server)
		if err == nil && row != nil && row.ContentHash == definition.hash && mcpSnapshotFailed(row) {
			status := failedMCPStatus(definition.server)
			status.ScanIssue = definition.issue
			return status
		}
	}
	// After a restart the watcher can have durable failed snapshots but no
	// successful source listing yet. Match their scoped paths until a fresh
	// listing establishes the definition identities above.
	if !listed {
		paths, err := w.store.ListTargetSnapshotPaths(string(InstallMCP))
		if err == nil {
			for _, path := range paths {
				row, err := w.store.GetTargetSnapshot(string(InstallMCP), path)
				if err == nil && mcpSnapshotFailed(row) && mcpFailedSnapshotServesQuery(path, row, q) {
					return MCPAdmissionStatus{Name: q.Server, Failed: true}
				}
			}
		}
	}
	return MCPAdmissionStatus{}
}

// A failed baseline is usable only when its stored identity matches its
// versioned key. Older rows cannot establish an account scope.
func mcpFailedSnapshotServesQuery(path string, row *audit.SnapshotRow, q MCPAdmissionQuery) bool {
	identity, ok := mcpStoredSnapshotIdentity(path, row)
	return ok && mcpServerServesQuery(identity.server(), q)
}

func mcpSnapshotFailed(row *audit.SnapshotRow) bool {
	return row != nil && mcpFingerprintFailed(row.ScannerFingerprint)
}

// mcpFingerprintFailed reports a scanner fingerprint that marks a failed
// scan, a refused launcher or a server kept unverified.
func mcpFingerprintFailed(fingerprint string) bool {
	return strings.HasSuffix(fingerprint, mcpScanFailedMark) ||
		strings.HasSuffix(fingerprint, mcpLauncherRefusedMark) ||
		strings.HasSuffix(fingerprint, unverifiedMCPMark)
}

// MCPPublication is what the servers a watcher admits hold for a tool call.
type MCPPublication struct {
	// Entry is the published definition whose launch digest matched.
	Entry config.MCPServerEntry
	// Matched says a published server serving the call has that digest.
	Matched bool
	// Named says a published server serves the call at all, whatever its
	// definition: a definition that is not Matched would override it.
	Named bool
}

// MCPPublished looks, among the servers this watcher admits for the caller
// (q), for the definition the caller's agent runs, named by its launch digest
// (config.MCPLaunchDigest). A managed Windows gateway learns an enrolled
// account's Codex servers only from the record the enumerator publishes; a
// definition the agent runs that is not in it was never scanned. The digest
// covers the whole definition (URL, command, every argument, environment), so
// a bounded hook fact cannot make a changed or oversized definition look like
// the scanned one, and the published entry it returns is the complete one to
// judge (GAP-0686).
func (w *InstallWatcher) MCPPublished(q MCPAdmissionQuery, digest string) MCPPublication {
	var out MCPPublication
	if w == nil {
		return out
	}
	servers, err := w.readMCPServers()
	if err != nil {
		return out
	}
	digest = strings.ToLower(strings.TrimSpace(digest))
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		out.Named = true
		if digest != "" && config.MCPLaunchDigest(server) == digest {
			out.Entry, out.Matched = server, true
			return out
		}
	}
	return out
}

// mcpBaselineMatches reports whether the baseline admission recorded for an
// MCP server is for its current definition. A verdict is for a definition,
// not a name: a server whose command, arguments, folder or environment
// changed under the same name keeps nothing of the old verdict until
// admission has run on the new one (GAP-0216).
func mcpBaselineMatches(row *audit.SnapshotRow, server config.MCPServerEntry) bool {
	hash, err := mcpDefinitionHash(server)
	return err == nil && row != nil && row.ContentHash != "" && row.ContentHash == hash
}

// mcpServerServesQuery reports whether a watched server can be the one the
// tool call reaches: same connector and name, the caller's own server on a
// gateway of several accounts, and a project server only for an agent
// working in that project.
func mcpServerServesQuery(server config.MCPServerEntry, q MCPAdmissionQuery) bool {
	if c := strings.TrimSpace(server.Connector); c != "" && !strings.EqualFold(c, strings.TrimSpace(q.Connector)) {
		return false
	}
	if !config.SameMCPToolServer(q.Connector, server.Name, q.Server) {
		return false
	}
	if q.Home != "" && server.Home != "" && !sameMCPFolder(server.Home, q.Home) {
		return false
	}
	if q.CWD != "" && server.Project != "" && !mcpFolderWithin(q.CWD, server.Project) {
		return false
	}
	return true
}

func mcpFolderKey(dir string) string {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if runtime.GOOS == "windows" {
		return strings.ToLower(dir)
	}
	return dir
}

func sameMCPFolder(a, b string) bool { return mcpFolderKey(a) == mcpFolderKey(b) }

// mcpFolderWithin reports whether dir is root or a folder inside it.
func mcpFolderWithin(dir, root string) bool {
	rel, err := filepath.Rel(mcpFolderKey(root), mcpFolderKey(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
