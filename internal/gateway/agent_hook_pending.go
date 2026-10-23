// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/google/uuid"
)

// A receipt-capable managed hook can act on an answer before the gateway's
// terminal audit write. This private spool is durable before the answer is
// offered. It contains only the facts needed to recover an unconfirmed
// occurrence; no raw hook body, tool arguments, or response output is stored.
const (
	pendingHookDirName         = "pending-hook-decisions"
	maxPendingHookBytes        = 128 << 10
	pendingHookRecoveredReason = "managed hook receipt recovered after gateway restart"
)

type pendingHookRequest struct {
	ConnectorName          string
	HookEventName          string
	SessionID              string
	TurnID                 string
	AgentID                string
	AgentName              string
	AgentType              string
	ToolInvocationID       string
	ToolName               string
	CorrelationUnavailable bool
}

func pendingRequest(req agentHookRequest) pendingHookRequest {
	return pendingHookRequest{
		ConnectorName: req.ConnectorName, HookEventName: req.HookEventName,
		SessionID: req.SessionID, TurnID: req.TurnID,
		AgentID: req.AgentID, AgentName: req.AgentName, AgentType: req.AgentType,
		ToolInvocationID: req.ToolInvocationID, ToolName: req.ToolName,
		CorrelationUnavailable: req.CorrelationUnavailable,
	}
}

func (p pendingHookRequest) request(id string, bodyBytes int64) agentHookRequest {
	return agentHookRequest{
		ConnectorName: p.ConnectorName, HookEventName: p.HookEventName,
		SessionID: p.SessionID, TurnID: p.TurnID,
		AgentID: p.AgentID, AgentName: p.AgentName, AgentType: p.AgentType,
		ToolInvocationID: p.ToolInvocationID, ToolName: p.ToolName,
		CorrelationUnavailable: p.CorrelationUnavailable,
		pendingOccurrenceID:    id, pendingBodyBytes: bodyBytes, pendingRecovery: true,
	}
}

type pendingHookResponse struct {
	Action           string
	RawAction        string
	Severity         string
	Mode             string
	WouldBlock       bool
	EvaluationID     string
	RuleIDs          []string
	RedactionEnabled *bool
}

func pendingResponse(resp agentHookResponse) pendingHookResponse {
	return pendingHookResponse{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Mode: resp.Mode, WouldBlock: resp.WouldBlock,
		EvaluationID: resp.EvaluationID, RuleIDs: resp.RuleIDs,
		RedactionEnabled: resp.RedactionEnabled,
	}
}

func (p pendingHookResponse) response() agentHookResponse {
	reason := pendingHookRecoveredReason
	if p.Action == hookActionUnconfirmed {
		reason = hookexec.ManagedGatewayNoAnswerReason
	}
	return agentHookResponse{
		Action: p.Action, RawAction: p.RawAction, Severity: p.Severity,
		Mode: p.Mode, Reason: reason, SourceReason: reason,
		WouldBlock: p.WouldBlock, EvaluationID: p.EvaluationID,
		RuleIDs: p.RuleIDs, RedactionEnabled: p.RedactionEnabled,
	}
}

type pendingHookOccurrence struct {
	ID           string
	Request      pendingHookRequest
	Unconfirmed  pendingHookResponse
	Final        *pendingHookResponse
	Envelope     audit.CorrelationEnvelope
	Identity     AgentIdentity
	RawEventIDs  []string
	Extra        map[string]string
	BodyBytes    int64
	ElapsedNanos int64
	Panicked     bool
	path         string
}

func (a *APIServer) pendingHookDir() string {
	dir := a.configDataDir()
	if dir == "" && a != nil && a.store != nil {
		dir = filepath.Dir(a.store.DatabasePath())
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, pendingHookDirName)
}

// beginPendingHookOccurrence makes the occurrence durable before its answer
// is offered. With an error it also returns the occurrence when a failed
// write could not be undone durably: the caller still owns it and audits the
// call under its IDs.
func (a *APIServer) beginPendingHookOccurrence(
	ctx context.Context, req agentHookRequest, proposed agentHookResponse,
	rawEventIDs []string, bodyBytes int64, elapsed time.Duration,
	panicked bool, extra map[string]string,
) (*pendingHookOccurrence, error) {
	if a == nil || a.store == nil || a.logger == nil || !a.store.Ready() {
		return nil, errors.New("hook audit store is unavailable")
	}
	dir := a.pendingHookDir()
	if dir == "" {
		return nil, errors.New("hook pending state directory is unavailable")
	}
	id := uuid.NewString()
	p := &pendingHookOccurrence{
		ID: id, Request: pendingRequest(req),
		Unconfirmed: pendingResponse(unconfirmedHookDelivery(proposed)),
		Envelope:    audit.EnvelopeFromContext(ctx), Identity: AgentIdentityFromContext(ctx),
		RawEventIDs: rawEventIDs, Extra: extra, BodyBytes: bodyBytes,
		ElapsedNanos: int64(elapsed), Panicked: panicked,
		path: filepath.Join(dir, id+".json"),
	}
	// The handler owns its occurrence from before it is published until it
	// returns; recovery in this process leaves it alone.
	livePendingHooks.claim(p.path)
	if _, err := p.publish(); err != nil {
		// A write that failed late can still have published the file. This
		// call is answered 503 and audited by the caller, so the removal is
		// made durable: a file a crash brings back would be audited again.
		if removeErr := p.remove(); removeErr != nil {
			// The file can outlive this process. The caller keeps the
			// occurrence and audits the call under its IDs.
			return p, errors.Join(err, removeErr)
		}
		livePendingHooks.release(p.path)
		return nil, err
	}
	return p, nil
}

// pendingHookPublish is how far a publish got.
type pendingHookPublish int

const (
	// pendingHookNotWritten: the file on disk does not carry this version,
	// or it could not be read back.
	pendingHookNotWritten pendingHookPublish = iota
	// pendingHookWritten: the file carries this version, but a crash can
	// still bring back the earlier one or lose the file.
	pendingHookWritten
	// pendingHookDurable: this version survives a crash.
	pendingHookDurable
)

// publish writes the occurrence and makes it durable: the file, its
// directory entry, and the entry of each directory the write created. A
// failed write can still have replaced the file, so the file is read back.
// The error is set whenever a step failed, also when the result is durable.
func (p *pendingHookOccurrence) publish() (pendingHookPublish, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return pendingHookNotWritten, err
	}
	if len(data) > maxPendingHookBytes {
		return pendingHookNotWritten, fmt.Errorf("hook pending occurrence exceeds %d bytes", maxPendingHookBytes)
	}
	dir := filepath.Dir(p.path)
	created := missingPendingHookDirs(dir)
	writeErr := safefile.WritePrivate(p.path, data)
	if writeErr != nil && !p.carries(data) {
		return pendingHookNotWritten, writeErr
	}
	if err := makePendingHookDirDurable(dir, created); err != nil {
		return pendingHookWritten, errors.Join(writeErr, err)
	}
	return pendingHookDurable, writeErr
}

// carries reports whether the occurrence file on disk holds data.
func (p *pendingHookOccurrence) carries(data []byte) bool {
	got, err := pendingHookFS().read(p.path, maxPendingHookBytes)
	return err == nil && bytes.Equal(got, data)
}

// setFinal records the answer the hook took and reports whether the
// occurrence carries it durably, which is what recovery will audit. A final
// answer that is on disk but not synced is not durable: a crash can bring
// back the unconfirmed one.
func (p *pendingHookOccurrence) setFinal(resp agentHookResponse, elapsed time.Duration) (bool, error) {
	next := *p
	final := pendingResponse(resp)
	next.Final = &final
	next.ElapsedNanos = int64(elapsed)
	state, err := next.publish()
	if state == pendingHookDurable {
		*p = next
		return true, err
	}
	return false, err
}

// publishedResponse is the answer this process can stand behind for the
// occurrence: its durable final answer, else the unconfirmed one.
func (p *pendingHookOccurrence) publishedResponse() agentHookResponse {
	if p.Final != nil {
		return p.Final.response()
	}
	return p.Unconfirmed.response()
}

// responseMatching is the occurrence's answer whose decision is action, the
// decision a terminal record of this occurrence already holds: its final
// answer, its unconfirmed answer, or the closed fallback of a call answered
// 503. ok is false for an action no record states (none, other).
func (p *pendingHookOccurrence) responseMatching(action string) (agentHookResponse, bool) {
	want := normalizeHookActionLabel(action)
	if want == "none" || want == "other" {
		return agentHookResponse{}, false
	}
	if p.Final != nil && normalizeHookActionLabel(p.Final.Action) == want {
		return p.Final.response(), true
	}
	resp := p.Unconfirmed.response()
	switch {
	case normalizeHookActionLabel(resp.Action) == want:
		return resp, true
	case want == "block" && normalizeHookActionLabel(resp.RawAction) != "block":
		// The closed fallback the hook took when the gateway answered 503.
		return failedClosedHookDelivery(resp, hookexec.ManagedGatewayNoAnswerReason), true
	}
	// A final answer whose rewrite a crash undid.
	resp.Action = want
	resp.Reason, resp.SourceReason = pendingHookRecoveredReason, pendingHookRecoveredReason
	return resp, true
}

// remove deletes the occurrence and makes the removal durable. A file or
// directory that is not there is already removed.
func (p *pendingHookOccurrence) remove() error {
	if err := os.Remove(p.path); err != nil && !pendingHookPathAbsent(err) {
		return err
	}
	if err := pendingHookFS().syncDir(filepath.Dir(p.path)); err != nil && !pendingHookPathAbsent(err) {
		return err
	}
	return nil
}

func pendingHookPathAbsent(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR)
}

// missingPendingHookDirs is dir and each of its ancestors that does not
// exist yet, deepest first: the directories a write into dir creates.
func missingPendingHookDirs(dir string) []string {
	var missing []string
	current := dir
	for {
		if _, err := os.Lstat(current); !errors.Is(err, fs.ErrNotExist) {
			return missing
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			return missing
		}
		current = parent
	}
}

// pendingHookDurableDirs holds, per pending directory, the directory whose
// entry in its parent this process has made durable. A directory removed
// and created again while the gateway runs is a different directory.
var pendingHookDurableDirs = struct {
	mu   sync.Mutex
	dirs map[string]os.FileInfo
}{dirs: map[string]os.FileInfo{}}

// makePendingHookDirDurable syncs dir, so a file renamed into it survives a
// crash, and the parent of each directory the write created, so the
// directories themselves survive. The first publish of a process also syncs
// the parent of dir: an earlier process can have created it and stopped
// before its parent was synced.
func makePendingHookDirDurable(dir string, created []string) error {
	ops := pendingHookFS()
	if err := ops.syncDir(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	pendingHookDurableDirs.mu.Lock()
	known := pendingHookDurableDirs.dirs[dir]
	pendingHookDurableDirs.mu.Unlock()
	if len(created) == 0 && known != nil && os.SameFile(known, info) {
		return nil
	}
	parents := []string{filepath.Dir(dir)}
	for _, made := range created {
		if parent := filepath.Dir(made); parent != parents[len(parents)-1] {
			parents = append(parents, parent)
		}
	}
	for _, parent := range parents {
		if err := ops.syncDir(parent); err != nil {
			return err
		}
	}
	pendingHookDurableDirs.mu.Lock()
	pendingHookDurableDirs.dirs[dir] = info
	pendingHookDurableDirs.mu.Unlock()
	return nil
}

// pendingHookFileOps are the file operations of the pending spool that can
// fail for reasons outside the gateway. Tests replace them to inject those
// failures.
type pendingHookFileOps struct {
	syncDir  func(string) error
	validate func(string) error
	read     func(string, int64) ([]byte, error)
}

var (
	defaultPendingHookFileOps = pendingHookFileOps{
		syncDir: syncDaemonDir, validate: safefile.ValidatePrivateFile, read: safefile.ReadRegularFileBounded,
	}
	pendingHookFileOpsOverride atomic.Pointer[pendingHookFileOps]
)

func pendingHookFS() *pendingHookFileOps {
	if ops := pendingHookFileOpsOverride.Load(); ops != nil {
		return ops
	}
	return &defaultPendingHookFileOps
}

// release ends the handler's ownership. An occurrence it could not audit
// stays on disk for recovery.
func (p *pendingHookOccurrence) release() {
	if p != nil {
		livePendingHooks.release(p.path)
	}
}

// pendingHookOwners is the set of pending occurrences a goroutine of this
// process is working on: a live handler between its offer and its terminal
// audit, or a recovery pass. A config reload builds a new APIServer while
// the old server's handlers can still be running, so ownership is per
// process, not per server.
type pendingHookOwners struct {
	mu    sync.Mutex
	paths map[string]struct{}
}

var livePendingHooks = pendingHookOwners{paths: map[string]struct{}{}}

func (o *pendingHookOwners) claim(path string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, owned := o.paths[path]; owned {
		return false
	}
	o.paths[path] = struct{}{}
	return true
}

func (o *pendingHookOwners) release(path string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.paths, path)
}

const (
	// defaultPendingHookRetryInterval is how often recovery looks again for
	// occurrences nobody could audit yet: the audit store was not ready or
	// not writable, at startup or for a live handler.
	defaultPendingHookRetryInterval = 30 * time.Second
	// A listener waits for the first recovery pass at most this long, and
	// only until the pass has handled this many entries. The rest is
	// recovered while the gateway serves.
	defaultPendingHookStartupBudget  = 2 * time.Second
	defaultPendingHookStartupEntries = 64
)

// pendingHookQuarantineSuffix marks an occurrence file recovery refused. It
// is kept for inspection and no longer read.
const pendingHookQuarantineSuffix = ".invalid"

// pendingHookReported keeps one finding per problem per process, so a retry
// loop or an API restart does not repeat the same alert.
var pendingHookReported = struct {
	mu   sync.Mutex
	seen map[string]struct{}
}{seen: map[string]struct{}{}}

// ensurePendingHookRecovery starts this server's recovery and gives its
// first pass a bounded head start before the listener serves: until the pass
// has handled defaultPendingHookStartupEntries entries or
// defaultPendingHookStartupBudget has passed, whichever is first. A large
// backlog or a busy audit store never holds a listener longer. Recovery never
// stops the gateway: a foreign entry is skipped and one proven invalid or
// untrusted is quarantined, each with a finding, and an entry it cannot read
// or audit yet stays on disk for a later pass.
func (a *APIServer) ensurePendingHookRecovery(ctx context.Context) {
	a.pendingHookRecoveryOnce.Do(func() {
		budget := a.pendingHookStartupBudget
		if budget <= 0 {
			budget = defaultPendingHookStartupBudget
		}
		a.pendingHookStartup = make(chan struct{})
		a.pendingHookStartupDeadline = time.Now().Add(budget)
		go a.runPendingHookRecovery(ctx, a.pendingHookStartup)
	})
	wait := time.NewTimer(time.Until(a.pendingHookStartupDeadline))
	defer wait.Stop()
	select {
	case <-a.pendingHookStartup:
	case <-wait.C:
	case <-ctx.Done():
	}
}

// runPendingHookRecovery runs the first pass, opening startup after its
// startup share of entries, then looks again every retry interval while the
// server runs: an occurrence a live handler could not audit (the store was
// busy or not writable) is recovered then, without a restart.
func (a *APIServer) runPendingHookRecovery(ctx context.Context, startup chan struct{}) {
	var opened sync.Once
	open := func() { opened.Do(func() { close(startup) }) }
	defer open()
	limit := a.pendingHookStartupEntries
	if limit <= 0 {
		limit = defaultPendingHookStartupEntries
	}
	handled := 0
	a.recoverPendingHookOccurrences(ctx, func() {
		if handled++; handled >= limit {
			open()
		}
	})
	open()
	if a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return
	}
	interval := a.pendingHookRetryInterval
	if interval <= 0 {
		interval = defaultPendingHookRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		a.recoverPendingHookOccurrences(ctx, nil)
	}
}

// reportPendingHookProblem records a recovery finding once per process: a
// gateway error line and a HIGH alert row when the audit store accepts it.
func (a *APIServer) reportPendingHookProblem(kind, entry string, err error) {
	key := kind + "\x00" + entry + "\x00" + err.Error()
	pendingHookReported.mu.Lock()
	_, seen := pendingHookReported.seen[key]
	pendingHookReported.seen[key] = struct{}{}
	pendingHookReported.mu.Unlock()
	if seen {
		return
	}
	fmt.Fprintf(os.Stderr, "[gateway] hook pending recovery %s entry=%q: %v\n", kind, entry, err)
	if a.logger != nil {
		_ = a.logger.LogAlert("hook-audit", "HIGH",
			"managed hook pending decision recovery: "+kind,
			map[string]any{"entry": entry, "problem": kind, "error": err.Error()})
	}
}

// recoverPendingHookOccurrences audits the occurrences an earlier process,
// an earlier server of this process or a handler that could not finish left
// behind. A pending entry with no durable receipt outcome is deliberately
// unconfirmed: a restart cannot infer what the previous process's
// confirmation reached. entryDone, when set, runs after each entry. An entry
// that is not audited yet stays on disk for the next pass.
func (a *APIServer) recoverPendingHookOccurrences(ctx context.Context, entryDone func()) {
	if a == nil || a.scannerCfg == nil || !a.scannerCfg.StandaloneEnterprise() {
		return
	}
	dir := a.pendingHookDir()
	if dir == "" {
		return
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		a.reportPendingHookProblem("unreadable directory", pendingHookDirName, err)
		return
	}
	if err := safefile.ValidatePrivateDirectory(dir); err != nil {
		// Nothing in a directory that is not private is trusted. Its
		// entries wait until the directory is repaired.
		a.reportPendingHookProblem("directory protection drift", pendingHookDirName, err)
		return
	}
	for _, entry := range entries {
		if ctx.Err() != nil {
			return
		}
		a.recoverPendingHookEntry(ctx, dir, entry)
		if entryDone != nil {
			entryDone()
		}
	}
}

// recoverPendingHookEntry handles one directory entry. A panic in one entry
// is a finding, never a gateway exit.
func (a *APIServer) recoverPendingHookEntry(ctx context.Context, dir string, entry fs.DirEntry) {
	name := entry.Name()
	// An interrupted atomic rewrite can leave its unpublished temp. The last
	// published JSON file is still the recovery authority.
	if strings.HasPrefix(name, ".safefile-") || strings.HasSuffix(name, pendingHookQuarantineSuffix) {
		return
	}
	id, ok := strings.CutSuffix(name, ".json")
	if !ok || uuid.Validate(id) != nil {
		// Not ours (a Finder or editor file, a subdirectory): left alone.
		a.reportPendingHookProblem("foreign entry skipped", name, errors.New("not a pending occurrence"))
		return
	}
	path := filepath.Join(dir, name)
	if !livePendingHooks.claim(path) {
		// A handler of this process still owns it, or another recovery
		// pass is replaying it.
		return
	}
	defer livePendingHooks.release(path)
	defer func() {
		if recovered := recover(); recovered != nil {
			a.reportPendingHookProblem("recovery panic", name, fmt.Errorf("%v", recovered))
		}
	}()
	p, err := readPendingHookOccurrence(path, id, entry)
	var unreadable *pendingHookUnreadableError
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Finalized and removed after this pass listed the directory.
		return
	case errors.As(err, &unreadable):
		// Valid as far as anyone knows: kept for the next pass.
		a.reportPendingHookProblem("unreadable occurrence kept for retry", name, err)
		return
	case err != nil:
		a.quarantinePendingHookOccurrence(path, name, err)
		return
	}
	req := p.Request.request(p.ID, p.BodyBytes)
	resp, err := a.pendingHookRecoveryResponse(ctx, p)
	if err != nil {
		a.reportPendingHookProblem("audit lookup failed", name, err)
		return
	}
	persistCtx := audit.ContextWithEnvelope(ctx, p.Envelope)
	persistCtx = ContextWithAgentIdentity(persistCtx, p.Identity)
	persistCtx = enrichAgentHookContext(persistCtx, req)
	persistCtx = withRedactionDecision(persistCtx, resp.RedactionEnabled)
	result := a.finalizeAgentHook(persistCtx, req.ConnectorName, req, resp,
		p.RawEventIDs, nil, time.Duration(p.ElapsedNanos), p.Panicked, p.Extra)
	if !result.AuditPersisted || !result.DecisionSettled {
		// Kept on disk: stable IDs make a later pass skip whichever
		// record already landed.
		a.reportPendingHookProblem("audit not persisted yet", name,
			fmt.Errorf("audit=%t hook_decision=%t", result.AuditPersisted, result.DecisionSettled))
		return
	}
	if err := p.remove(); err != nil {
		a.reportPendingHookProblem("cleanup failed", name, err)
	}
}

// pendingHookRecoveryResponse is the answer recovery audits. A terminal
// record of the occurrence that is already stored is the authority for its
// missing companion: the file can be older than that record (a final
// rewrite a crash undid), and the two records of one call never disagree.
// With neither record stored, the occurrence file is the authority.
func (a *APIServer) pendingHookRecoveryResponse(ctx context.Context, p *pendingHookOccurrence) (agentHookResponse, error) {
	if a.store == nil {
		return p.publishedResponse(), nil
	}
	for _, id := range []string{p.ID, p.ID + "-decision"} {
		action, found, err := a.store.StoredHookDecisionAction(ctx, id)
		if err != nil {
			return agentHookResponse{}, err
		}
		if !found {
			continue
		}
		if resp, ok := p.responseMatching(action); ok {
			return resp, nil
		}
	}
	return p.publishedResponse(), nil
}

// pendingHookUnreadableError is an occurrence recovery could not read for
// an operating-system reason (too many open files, an I/O error, a sharing
// violation, a replace during the read). Nothing proves it invalid, so it
// is kept and read again by a later pass.
type pendingHookUnreadableError struct{ err error }

func (e *pendingHookUnreadableError) Error() string { return e.err.Error() }
func (e *pendingHookUnreadableError) Unwrap() error { return e.err }

// readPendingHookOccurrence reads one occurrence. Only a file proven
// invalid (not a regular file, too large, not an occurrence) or untrusted
// (its protection drifted) is refused; any other failure is a
// *pendingHookUnreadableError.
func readPendingHookOccurrence(path, id string, entry fs.DirEntry) (*pendingHookOccurrence, error) {
	if !entry.Type().IsRegular() {
		return nil, fmt.Errorf("entry type %s is not a regular file", entry.Type())
	}
	ops := pendingHookFS()
	if err := ops.validate(path); err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return nil, &pendingHookUnreadableError{err: err}
		}
		return nil, err
	}
	data, err := ops.read(path, maxPendingHookBytes)
	if err != nil {
		if info, statErr := os.Lstat(path); statErr == nil &&
			(!info.Mode().IsRegular() || info.Size() > maxPendingHookBytes) {
			return nil, err
		}
		return nil, &pendingHookUnreadableError{err: err}
	}
	var p pendingHookOccurrence
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.ID != id || p.Request.ConnectorName == "" || p.Request.HookEventName == "" ||
		p.BodyBytes < 0 || p.BodyBytes > apiRequestBodyMaxBytes {
		return nil, errors.New("occurrence fields are invalid")
	}
	p.path = path
	return &p, nil
}

// quarantinePendingHookOccurrence renames an occurrence recovery refused, so
// later passes skip it, and records the finding. A failed rename is tried
// again by the next pass.
func (a *APIServer) quarantinePendingHookOccurrence(path, name string, cause error) {
	a.reportPendingHookProblem("invalid occurrence quarantined", name, cause)
	if err := os.Rename(path, path+pendingHookQuarantineSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
		a.reportPendingHookProblem("quarantine failed", name, err)
		return
	}
	_ = pendingHookFS().syncDir(filepath.Dir(path))
}
