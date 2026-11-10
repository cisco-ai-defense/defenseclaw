// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/mcpkey"
	"github.com/defenseclaw/defenseclaw/internal/mcplocal"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
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
	// when the definition shows it: MCPScanIssueLauncher,
	// MCPScanIssueArguments or MCPScanIssueAddress. "" when the cause is not known from the
	// definition (the hook then points to defenseclaw mcp list).
	ScanIssue string
	// Revoked marks a Failed status that is not the listed definition of
	// the server but an earlier one the agent may still run (the entry was
	// edited or removed after an admission no scan stood behind, and the
	// allow or setting that gave it is gone). An allow written for the
	// definition the agent config lists now does not answer it: the hook
	// names the server, not the connection (GAP-0920).
	Revoked bool
	// Admitted is the listed definition serving the query that an allow
	// admitted before any scan, when there is one: a definition the agent
	// runs on the administrator's word, not on a verdict. The agent keeps its
	// connection to it after the entry is edited or the allow is withdrawn,
	// and the entry carries the config scope that listed it (Project), so the
	// hook can hold it for the session whatever directory a later call reports
	// (GAP-1018).
	Admitted *config.MCPServerEntry
}

// The definitions a scan refuses, as the hook and mcp list word them.
const (
	// MCPScanIssueLauncher is a local server started by anything but the
	// bare launchers npx or uvx.
	MCPScanIssueLauncher = "launcher"
	// MCPScanIssueArguments is a local server started by npx or uvx whose
	// arguments the scanner refuses: an execution flag, or no package.
	MCPScanIssueArguments = "arguments"
	// MCPScanIssueAddress is a server URL on a loopback, private,
	// link-local or multicast address, which the scanner never dials.
	MCPScanIssueAddress = "address"
)

// MCPLocalRefused reports a local server the scanner refuses from its
// definition alone: a launcher but the bare npx or uvx, or npx or uvx with an
// execution flag or without a package. The refusal is a function of the
// definition, so nothing has to start for a gateway that cannot start the
// server as its user to record it.
func MCPLocalRefused(server config.MCPServerEntry) bool {
	return strings.TrimSpace(server.URL) == "" && MCPScanRefused(server)
}

// MCPScanRefused reports a definition the scanner refuses from the definition
// alone: a local server MCPLocalRefused names, or a URL the scanner refuses
// from its text (scanner.MCPScanTargetRefusal: a loopback, private,
// link-local or multicast address, a loopback alias or the metadata host,
// inline credentials, or no host), which it never dials. A managed gateway
// that cannot read the agent config of its users keeps such a definition for
// the session that met it (GAP-0925).
func MCPScanRefused(server config.MCPServerEntry) bool {
	if rawURL := strings.TrimSpace(server.URL); rawURL != "" && scanner.MCPScanTargetRefusal(rawURL) != scanner.MCPTargetRefusalNone {
		return true
	}
	return mcpScanIssue(server) != ""
}

// mcpScanIssue names why the scanner refuses server, from its definition
// alone: the scanner stays the judge, this only words the refusal.
func mcpScanIssue(server config.MCPServerEntry) string {
	if rawURL := strings.TrimSpace(server.URL); rawURL != "" {
		if scanner.MCPScanTargetRefusal(rawURL) == scanner.MCPTargetRefusalAddress {
			return MCPScanIssueAddress
		}
		if parsed, err := url.Parse(rawURL); err == nil && mcpLocalHost(parsed.Hostname()) {
			return MCPScanIssueAddress
		}
		return ""
	}
	command := strings.TrimSpace(server.Command)
	if command == "" {
		return ""
	}
	switch class, _ := mcplocal.Judge(command, server.Args, server.LocalRefusal); class {
	case mcplocal.Launcher:
		return MCPScanIssueLauncher
	case mcplocal.Arguments:
		return MCPScanIssueArguments
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

// FailedMCPStatus is the status of a server whose completed admission scan
// failed, with the cause its definition shows.
func FailedMCPStatus(server config.MCPServerEntry) MCPAdmissionStatus {
	return MCPAdmissionStatus{Name: server.Name, Failed: true, ScanIssue: mcpScanIssue(server)}
}

// mcpAdmissionOutcome is the latest completed admission of one definition.
type mcpAdmissionOutcome struct {
	hash   string
	failed bool
	// withoutScan says the definition was allowed before any scan, by an
	// allow rule or a setting that skips the scan. Such an allow stands only
	// while that rule or setting does (mcpUnscannedAdmissionLapsed).
	withoutScan bool
}

// noteMCPAdmissionOutcome records the outcome of an admission run on snap's
// definition as soon as it is decided, by (key, hash): a scan failure
// reports as failed, and any other completed outcome (an allow after the
// administrator allowed the server, a clean rescan) reports as not failed,
// whether or not the baseline row is written yet, or could be written at
// all. A run the watcher stopping cut off decides nothing.
func (w *InstallWatcher) noteMCPAdmissionOutcome(evt InstallEvent, snap *TargetSnapshot, res AdmissionResult) {
	if evt.Type != InstallMCP || snap == nil || res.Interrupted || w.secureClientActive() ||
		!w.mcpDefinitionIsSnapshot(evt, snap) {
		return
	}
	failed := mcpScanFailureBlocked(res) ||
		(res.Verdict == VerdictScanError && keptUnscannedMCPReason(res.Reason))
	w.mcpAdmissionMu.Lock()
	defer w.mcpAdmissionMu.Unlock()
	if w.mcpOutcomes == nil {
		w.mcpOutcomes = map[string]mcpAdmissionOutcome{}
	}
	w.mcpOutcomes[evt.Path] = mcpAdmissionOutcome{hash: snap.ContentHash, failed: failed,
		withoutScan: res.Verdict == VerdictAllowed && res.ScanID == ""}
}

// mcpDefinitionIsSnapshot reports whether the server still has the definition
// snap hashed. The scanner reads the definition by name when it runs, so an
// agent config rewritten between the snapshot and the scan makes the verdict
// one for a definition the snapshot does not name. Such a verdict is neither
// kept nor stored as the baseline of the snapshot: the server stays without an
// outcome (pending) and the next cycle admits the definition it has now. A
// listing that cannot be read decides nothing either.
func (w *InstallWatcher) mcpDefinitionIsSnapshot(evt InstallEvent, snap *TargetSnapshot) bool {
	hash, err := w.mcpDefinitionHashOf(evt)
	return err == nil && hash == snap.ContentHash
}

// mcpDefinitionHashOf is the hash of the definition the server has now.
func (w *InstallWatcher) mcpDefinitionHashOf(evt InstallEvent) (string, error) {
	entry, err := w.lookupMCPServer(evt)
	if err != nil {
		return "", err
	}
	return mcpDefinitionHash(*entry)
}

// mcpDefinitionMoved reports an MCP admission whose server no longer has the
// definition it was started for (evt.definitionHash), or is no longer listed
// or readable. The scanner reads a server by name, so a definition rewritten
// after the snapshot would get its verdict applied under the old definition:
// an ordinary server disabled for another definition high finding, or a
// protective block released by another definition clean scan. Such an
// admission decides nothing: the earlier protection stays until the
// definition the server has admits for itself. An event bound to no
// definition, and Secure Client, are never moved.
func (w *InstallWatcher) mcpDefinitionMoved(evt InstallEvent) bool {
	if evt.Type != InstallMCP || evt.definitionHash == "" || w.secureClientActive() {
		return false
	}
	hash, err := w.mcpDefinitionHashOf(evt)
	return err != nil || hash != evt.definitionHash
}

// mcpMovedAdmission is the result of an admission that mcpDefinitionMoved
// stopped: nothing decided, nothing enforced, no baseline.
func (w *InstallWatcher) mcpMovedAdmission(evt InstallEvent) AdmissionResult {
	fmt.Fprintf(os.Stderr, "[watch] mcp %s: its definition changed during admission; nothing was decided, the next cycle admits the definition it has\n", evt.Name)
	return AdmissionResult{Event: evt, Verdict: VerdictScanError, Interrupted: true,
		Reason: "definition changed during admission; the next cycle admits it"}
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
	w.mcpOutcomes[path] = mcpAdmissionOutcome{hash: hash, failed: mcpFingerprintFailed(fingerprint),
		withoutScan: strings.HasSuffix(fingerprint, admittedWithoutScanMark)}
}

type mcpKnownDefinition struct {
	// server holds the identity and how the server starts (URL, command,
	// arguments, transport), never its environment or headers.
	server config.MCPServerEntry
	hash   string
	// path is MCPEventPath of server.
	path string
	// issue is mcpScanIssue of the definition.
	issue string
}

// mcpDepartedMax bounds mcpAdmissionDeparted.
const mcpDepartedMax = 256

// mcpLostKeysMax bounds the definitions mcpAdmissionLost notes in all.
const mcpLostKeysMax = 4096

// mcpLostScope is what the departed servers of one connector and account
// that did not fit leave behind: the definitions that were dropped (keys),
// so listing one again clears its note, and all once even those did not fit.
// The scope with no connector and no home covers every caller.
type mcpLostScope struct {
	connector, home string
	keys            map[string]struct{}
	all             bool
}

// mcpDepartedKey names a definition: the server key and its hash, so an edit
// of the entry keeps the earlier definition apart from the one that replaced it.
func mcpDepartedKey(definition mcpKnownDefinition) string {
	return definition.path + "\x00" + definition.hash
}

// settledDepartingMCP names, by definition key, the servers prev had that
// now do not list, or list under another definition, and whose admission no
// policy revocation can reach: one a scan decided, or one with no outcome.
// Only a server admitted before any scan is worth holding after its entry
// leaves the agent config or is edited (GAP-0920), so ordinary config churn
// never fills, or evicts from, the departed servers. It reads the store, so
// call it without mcpAdmissionMu held; a definition it does not name is held.
func (w *InstallWatcher) settledDepartingMCP(prev, now []mcpKnownDefinition) map[string]bool {
	if len(prev) == 0 || w.store == nil {
		return nil
	}
	listed := make(map[string]bool, len(now))
	for _, definition := range now {
		listed[mcpDepartedKey(definition)] = true
	}
	var settled map[string]bool
	for _, definition := range prev {
		if definition.server.Bundled || listed[mcpDepartedKey(definition)] {
			continue
		}
		row, err := mcpSnapshotForServer(w.store, definition.server)
		if err != nil {
			row = nil
		}
		_, decided, unscanned := w.mcpDecidedAdmission(definition.path, definition.hash, row)
		if decided && unscanned {
			continue
		}
		if settled == nil {
			settled = map[string]bool{}
		}
		settled[mcpDepartedKey(definition)] = true
	}
	return settled
}

// rememberDepartedMCP notes, for each server prev had that now does not
// list (or lists under another definition) and settled does not name, that
// the agent config dropped it, and forgets a definition now lists again. One
// that does not fit is not lost silently: noteLostMCP makes a call that
// names no listed or held server of its connector and account fail like any
// admission no scan stands behind. Call with mcpAdmissionMu held.
func (w *InstallWatcher) rememberDepartedMCP(prev, now []mcpKnownDefinition, settled map[string]bool) {
	if len(prev) == 0 && len(w.mcpAdmissionDeparted) == 0 && len(w.mcpAdmissionLost) == 0 {
		return
	}
	listed := make(map[string]bool, len(now))
	for _, definition := range now {
		key := mcpDepartedKey(definition)
		listed[key] = true
		delete(w.mcpAdmissionDeparted, key)
		w.forgetLostMCP(key)
	}
	for _, definition := range prev {
		key := mcpDepartedKey(definition)
		if definition.server.Bundled || listed[key] || settled[key] {
			continue
		}
		if _, held := w.mcpAdmissionDeparted[key]; !held && len(w.mcpAdmissionDeparted) >= mcpDepartedMax {
			w.noteLostMCP(definition, key)
			continue
		}
		if w.mcpAdmissionDeparted == nil {
			w.mcpAdmissionDeparted = map[string]mcpKnownDefinition{}
		}
		w.mcpAdmissionDeparted[key] = definition
	}
}

// noteLostMCP records a departed definition that did not fit, under its
// connector and account. Call with mcpAdmissionMu held.
func (w *InstallWatcher) noteLostMCP(definition mcpKnownDefinition, key string) {
	connector, home := strings.TrimSpace(definition.server.Connector), definition.server.Home
	scopeKey := strings.ToLower(connector) + "\x00"
	if home != "" {
		scopeKey += mcpFolderKey(home)
	}
	scope := w.mcpAdmissionLost[scopeKey]
	if scope == nil {
		scope = &mcpLostScope{connector: connector, home: home}
		if w.mcpAdmissionLostKeys >= mcpLostKeysMax {
			// Out of room for another scope: any caller may be the lost one.
			scopeKey, scope = "", &mcpLostScope{}
			if known := w.mcpAdmissionLost[scopeKey]; known != nil {
				scope = known
			}
		}
		if w.mcpAdmissionLost == nil {
			w.mcpAdmissionLost = map[string]*mcpLostScope{}
		}
		w.mcpAdmissionLost[scopeKey] = scope
	}
	if _, noted := scope.keys[key]; noted || scope.all {
		return
	}
	if w.mcpAdmissionLostKeys >= mcpLostKeysMax {
		scope.all = true
		return
	}
	if scope.keys == nil {
		scope.keys = map[string]struct{}{}
	}
	scope.keys[key] = struct{}{}
	w.mcpAdmissionLostKeys++
}

// forgetLostMCP clears the note of a definition that lists again, and a
// scope that has nothing left to note. Call with mcpAdmissionMu held.
func (w *InstallWatcher) forgetLostMCP(key string) {
	for scopeKey, scope := range w.mcpAdmissionLost {
		if _, noted := scope.keys[key]; !noted {
			continue
		}
		delete(scope.keys, key)
		w.mcpAdmissionLostKeys--
		if len(scope.keys) == 0 && !scope.all {
			delete(w.mcpAdmissionLost, scopeKey)
		}
	}
}

// lostMCPServes reports whether a departed definition that did not fit may
// be the server a call reaches: a note of its connector and account. Call
// with mcpAdmissionMu held.
func (w *InstallWatcher) lostMCPServes(q MCPAdmissionQuery) bool {
	for _, scope := range w.mcpAdmissionLost {
		if scope.connector != "" && !strings.EqualFold(scope.connector, strings.TrimSpace(q.Connector)) {
			continue
		}
		if q.Home != "" && scope.home != "" && !sameMCPFolder(scope.home, q.Home) {
			continue
		}
		return true
	}
	return false
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
	var admitted *config.MCPServerEntry
	status := w.mcpAdmissionStatus(q, &admitted)
	status.Admitted = admitted
	return status
}

func (w *InstallWatcher) mcpAdmissionStatus(q MCPAdmissionQuery, admitted **config.MCPServerEntry) MCPAdmissionStatus {
	if w == nil || !w.admitNewMCP || w.store == nil || w.secureClientActive() ||
		strings.TrimSpace(q.Server) == "" {
		return MCPAdmissionStatus{}
	}
	firstCycle := !w.firstCycleDone.Load()
	servers, err := w.readMCPServers()
	if err != nil {
		// The earlier definitions the agent may still run are remembered, not
		// listed, so an unreadable source does not forget which of them
		// failed: they come before the failed scan of the last listing.
		if revoked := w.mcpDepartedRevoked(q, nil, false); revoked.Failed {
			return revoked
		}
		if failed := w.mcpFailedFromLastRead(q); failed.Failed {
			return failed
		}
		return MCPAdmissionStatus{Name: q.Server, Unavailable: true, RetryAfter: defaultScanTimeout}
	}
	var pending []string
	var pendingPath string
	var refused *config.MCPServerEntry
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		path := MCPEventPath(server)
		row, err := mcpSnapshotForServer(w.store, server)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return MCPAdmissionStatus{Name: server.Name, Unavailable: true, RetryAfter: defaultScanTimeout}
		}
		hash, _ := mcpDefinitionHash(server)
		failed, decided, unscanned := w.mcpDecidedAdmission(path, hash, row)
		if failed {
			if w.admitsMCPWithoutScan(context.Background(), InstallEvent{Type: InstallMCP, Name: server.Name, Path: path, Connector: server.Connector}) {
				// The allow that came after the failure ends it: admission runs
				// now, so the block it left is released for the next session.
				w.AdmitAddedMCPServers([]string{server.Name})
			}
			// The most restrictive verdict of the definitions the agent may
			// still run: a revoked earlier one beats the listed one, whose
			// allow cannot speak for it.
			if revoked := w.mcpDepartedRevoked(q, servers, true); revoked.Failed {
				return revoked
			}
			return FailedMCPStatus(server)
		}
		// An allow given before any scan is the policy that gave it, not a
		// verdict on the definition: once the allow rule or the setting is
		// gone the server has no admission and is pending again, whatever
		// its baseline or outcome says (GAP-0920).
		lapsed := decided && unscanned &&
			w.mcpUnscannedAdmissionLapsed(InstallEvent{Type: InstallMCP, Name: server.Name, Path: path, Connector: server.Connector})
		if decided && !lapsed {
			if unscanned && *admitted == nil {
				listed := server
				*admitted = &listed
			}
			continue
		}
		if !lapsed && firstCycle && (!w.mcpStartupListed.Load() || w.listedAtStartup(path)) {
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
		if refused == nil && server.LocalRefusal != "" && MCPLocalRefused(server) {
			refused = &server
		}
	}
	if len(pending) == 0 {
		return w.mcpDepartedRevoked(q, servers, true)
	}
	w.AdmitAddedMCPServers(pending)
	if refused != nil {
		// A hook stated the scanner verdict from the complete definition and it
		// is a refusal, so the admission that starts can only record it and
		// there is nothing to wait for: the call that lists the server gets the
		// cause and the next step the later calls get, not a retry message
		// (GAP-0925). A definition the watcher read itself stays pending until
		// its own admission. A revoked earlier definition the agent may still
		// run is the more restrictive verdict and comes first (GAP-0920).
		if revoked := w.mcpDepartedRevoked(q, servers, true); revoked.Failed {
			return revoked
		}
		return FailedMCPStatus(*refused)
	}
	return MCPAdmissionStatus{Name: pending[0], Pending: true, RetryAfter: w.mcpRetryAfter(pendingPath)}
}

// mcpDecidedAdmission reads what the admission of the definition with this
// hash decided: the verdict this process decided stands before its baseline
// is written (a failure is not pending, and an allow that replaces a failure
// is not held by the old failed baseline: GAP-0775, GAP-0778), else the
// stored baseline row when it is for this definition.
func (w *InstallWatcher) mcpDecidedAdmission(path, hash string, row *audit.SnapshotRow) (failed, decided, unscanned bool) {
	if hash == "" {
		return false, false, false
	}
	if outcome, ok := w.mcpOutcome(path, hash); ok {
		return outcome.failed, true, !outcome.failed && outcome.withoutScan
	}
	if row == nil || row.ContentHash != hash {
		return false, false, false
	}
	if mcpSnapshotFailed(row) {
		return true, true, false
	}
	return false, true, strings.HasSuffix(row.ScannerFingerprint, admittedWithoutScanMark)
}

// mcpDepartedRevoked is the status of a call to a server the agent config no
// longer lists, or lists under another definition, whose admission was the
// policy that gave it (an allow rule or scan_on_install false) and that
// policy is gone. The agent can keep its connection after the entry is
// removed or edited, so the revoked admission reaches that call too: the
// server has no scan to stand on and cannot be scanned, which is the failed
// admission of a definition that no scan admits, so strict and managed
// refuse it and the default tiers warn. A server whose allow still stands,
// or that a scan admitted, or that was never seen, has no status here
// (GAP-0920). While the agent config lists that very definition (servers) it
// decides, as for any listed server; a replacement listed under the same name
// decides for itself and never for the live connection of the earlier one. A call that names no listed
// and no held server may be one that did not fit (mcpAdmissionLost) when a
// note of its connector and account says so, and fails the same way rather
// than being allowed. servers is the agent config listing; listingRead false
// says the listing could not be read: the held definitions are then judged as
// departed (the last listing did not have them), and a call naming no held
// server is left to the unavailable-source handling of the caller.
func (w *InstallWatcher) mcpDepartedRevoked(q MCPAdmissionQuery, servers []config.MCPServerEntry, listingRead bool) MCPAdmissionStatus {
	w.mcpAdmissionMu.RLock()
	if len(w.mcpAdmissionDeparted) == 0 && len(w.mcpAdmissionLost) == 0 {
		w.mcpAdmissionMu.RUnlock()
		return MCPAdmissionStatus{}
	}
	var gone []mcpKnownDefinition
	for _, definition := range w.mcpAdmissionDeparted {
		if mcpServerServesQuery(definition.server, q) {
			gone = append(gone, definition)
		}
	}
	lost := w.lostMCPServes(q)
	w.mcpAdmissionMu.RUnlock()
	if len(gone) == 0 && !lost {
		return MCPAdmissionStatus{}
	}
	// A listed definition stands for itself only: a replacement listed under
	// the same name and path, admitted or not, is another definition and
	// does not speak for the live connection of the earlier one.
	listed := map[string]bool{}
	for _, server := range servers {
		if server.Bundled || !mcpServerServesQuery(server, q) {
			continue
		}
		hash, _ := mcpDefinitionHash(server)
		listed[mcpDepartedKey(mcpKnownDefinition{path: MCPEventPath(server), hash: hash})] = true
	}
	for _, definition := range gone {
		server := definition.server
		// Only a server admitted before any scan is held; the allow or the
		// setting that gave that admission is the one to ask.
		if listed[mcpDepartedKey(definition)] || !w.mcpUnscannedAdmissionLapsed(InstallEvent{
			Type: InstallMCP, Name: server.Name, Path: definition.path, Connector: server.Connector, remembered: &server}) {
			continue
		}
		status := FailedMCPStatus(server)
		status.ScanIssue = definition.issue
		status.Revoked = true
		return status
	}
	if listingRead && lost && len(listed) == 0 && len(gone) == 0 {
		return MCPAdmissionStatus{Name: q.Server, Failed: true, Revoked: true}
	}
	return MCPAdmissionStatus{}
}

// mcpUnscannedAdmissionLapsed reports an MCP server admitted before any scan
// (an asset_policy.mcp.allowed rule or admission.mcp.scan_on_install false)
// that admission no longer allows without one. The allow came from the
// policy, so removing the rule takes it back at once: the server is admitted
// again, by a scan that blocks it in a tier that fails closed. Secure Client
// keeps main (issue #1092).
func (w *InstallWatcher) mcpUnscannedAdmissionLapsed(evt InstallEvent) bool {
	return evt.Type == InstallMCP && !w.secureClientActive() && !w.admitsMCPWithoutScan(context.Background(), evt)
}

// mcpBaselineLapsed is mcpUnscannedAdmissionLapsed for a stored baseline: it
// records an admission without a scan whose policy is gone.
func (w *InstallWatcher) mcpBaselineLapsed(evt InstallEvent, baseline *audit.SnapshotRow) bool {
	return baseline != nil && strings.HasSuffix(baseline.ScannerFingerprint, admittedWithoutScanMark) &&
		w.mcpUnscannedAdmissionLapsed(evt)
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
			status := FailedMCPStatus(definition.server)
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

// mcpFailureAllowed reports an unchanged MCP server whose baseline records a
// failed admission (a scan that failed, a refused launcher, a server kept
// unverified) of a definition that an allow rule now admits without a scan.
// The allow was written after the failure, so nothing but this check sends the
// definition to admission again: a refused launcher is never retried, and the
// block and runtime disable the failure left would outlive the exact allow of
// that very definition for every session that starts after it.
func (w *InstallWatcher) mcpFailureAllowed(evt InstallEvent, baseline *audit.SnapshotRow) bool {
	return baseline != nil && mcpSnapshotFailed(baseline) && w.admitsMCPWithoutScan(context.Background(), evt)
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
