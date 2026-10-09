// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	hookChildThreadMaxEntries = 1024
	hookChildThreadTTL        = time.Hour
	hookSpawnIntentMaxEntries = 1024
	hookSpawnIntentTTL        = 2 * time.Minute
	hookSpawnAliasMaxBytes    = 512
	hookSpawnDocumentMaxBytes = 64 * 1024
	hookSpawnAliasMaxCount    = 32
)

type hookSpawnIntentPhase uint8

const (
	hookSpawnIntentRequested hookSpawnIntentPhase = iota + 1
	hookSpawnIntentCompleted
	hookSpawnIntentFailed
)

type hookSpawnIntent struct {
	key            string
	toolKey        string
	parent         llmEventMeta
	aliases        map[string]struct{}
	createdAt      time.Time
	updatedAt      time.Time
	resultObserved bool
	ambiguous      bool
}

// scoredHookSpawnIntent is one candidate intent of takeHookSpawnIntentAt.
type scoredHookSpawnIntent struct {
	key   string
	score int
	ready bool
}

var hookSpawnTaskPattern = regexp.MustCompile(`(?i)(?:task[_-]?name|agent[_-]?name|child[_-]?(?:name|role))\s*[:=]\s*["']?([A-Za-z0-9_./:-]{1,512})`)

func hookSpawnIntentToolKey(meta llmEventMeta) string {
	source := strings.ToLower(strings.TrimSpace(meta.Source))
	sessionID := strings.TrimSpace(meta.SessionID)
	toolID := strings.TrimSpace(meta.ToolID)
	if source == "" || sessionID == "" || toolID == "" {
		return ""
	}
	return strings.Join([]string{source, sessionID, meta.AgentIdentityID, toolID}, "\x00")
}

func hookSpawnIntentScope(meta llmEventMeta) string {
	return strings.ToLower(strings.TrimSpace(meta.Source)) + "\x00" + strings.TrimSpace(meta.SessionID) + "\x00" + meta.AgentIdentityID
}

// Empty identities retain the pre-identity correlation used by Secure Client.
func sameHookIdentity(parent, child llmEventMeta) bool {
	if parent.AgentIdentityID != child.AgentIdentityID {
		return false
	}
	return parent.AgentIdentityID == "" || parent.UserID == "" || child.UserID == "" || parent.UserID == child.UserID
}

func hookSpawnNormalizeAlias(value string) []string {
	value = strings.TrimSpace(strings.Trim(value, "\"'`"))
	value = strings.TrimSuffix(value, "/")
	if value == "" || len(value) > hookSpawnAliasMaxBytes {
		return nil
	}
	value = strings.ToLower(value)
	aliases := []string{value}
	if base := path.Base(value); base != "." && base != "/" && base != value {
		aliases = append(aliases, base)
	}
	return aliases
}

func hookSpawnAddAlias(aliases map[string]struct{}, value string) {
	if len(aliases) >= hookSpawnAliasMaxCount {
		return
	}
	for _, alias := range hookSpawnNormalizeAlias(value) {
		if len(aliases) >= hookSpawnAliasMaxCount {
			return
		}
		aliases[alias] = struct{}{}
	}
}

func hookSpawnCollectAliases(aliases map[string]struct{}, value any, key string, depth int) {
	if depth > 5 || len(aliases) >= hookSpawnAliasMaxCount {
		return
	}
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for childKey := range typed {
			keys = append(keys, childKey)
		}
		sort.Strings(keys)
		for _, childKey := range keys {
			hookSpawnCollectAliases(aliases, typed[childKey], childKey, depth+1)
		}
	case []any:
		for index, child := range typed {
			if index >= 64 {
				break
			}
			hookSpawnCollectAliases(aliases, child, key, depth+1)
		}
	case string:
		switch canonicalEvent(key) {
		case "taskname", "agentname", "childname", "childrole", "task":
			hookSpawnAddAlias(aliases, typed)
		case "name":
			if depth <= 2 {
				hookSpawnAddAlias(aliases, typed)
			}
		}
	}
}

func hookSpawnAliasesFromDocuments(documents ...string) map[string]struct{} {
	aliases := make(map[string]struct{})
	for _, document := range documents {
		document = strings.TrimSpace(document)
		if document == "" {
			continue
		}
		if len(document) > hookSpawnDocumentMaxBytes {
			document = document[:hookSpawnDocumentMaxBytes]
		}
		var decoded any
		if json.Unmarshal([]byte(document), &decoded) == nil {
			hookSpawnCollectAliases(aliases, decoded, "", 0)
		}
		for _, match := range hookSpawnTaskPattern.FindAllStringSubmatch(document, hookSpawnAliasMaxCount) {
			if len(match) > 1 {
				hookSpawnAddAlias(aliases, match[1])
			}
		}
	}
	return aliases
}

func hookSpawnAliasesFromChild(meta llmEventMeta, payload map[string]any) map[string]struct{} {
	aliases := make(map[string]struct{})
	hookSpawnCollectAliases(aliases, payload, "", 0)
	name := strings.TrimSpace(meta.AgentName)
	if name != "" && !strings.EqualFold(name, meta.Source) && !strings.EqualFold(name, meta.AgentType) &&
		!strings.EqualFold(name, "subagent") {
		hookSpawnAddAlias(aliases, name)
	}
	return aliases
}

func hookSpawnMergeAliases(target, source map[string]struct{}) {
	for alias := range source {
		if len(target) >= hookSpawnAliasMaxCount {
			return
		}
		target[alias] = struct{}{}
	}
}

func hookSpawnAliasScore(child, intent map[string]struct{}) int {
	score := 0
	for alias := range child {
		if _, ok := intent[alias]; !ok {
			continue
		}
		weight := 1
		if strings.Contains(alias, "/") {
			weight = 3
		}
		if weight > score {
			score = weight
		}
	}
	return score
}

func (a *APIServer) canonicalHookSpawnParent(meta llmEventMeta) llmEventMeta {
	if a == nil {
		return meta
	}
	if snapshot, ok := a.hookSessionStateSnapshot(meta.Source, meta.SessionID, meta.AgentID); ok {
		parent := snapshot.meta
		parent.ToolID = meta.ToolID
		parent.ToolName = meta.ToolName
		parent.OperationID = meta.OperationID
		return parent
	}
	return meta
}

func (a *APIServer) rememberHookSpawnIntent(
	meta llmEventMeta,
	tool string,
	phase hookSpawnIntentPhase,
	documents ...string,
) {
	a.rememberHookSpawnIntentAt(meta, tool, phase, time.Now().UTC(), documents...)
}

func (a *APIServer) rememberHookSpawnIntentAt(
	meta llmEventMeta,
	tool string,
	phase hookSpawnIntentPhase,
	now time.Time,
	documents ...string,
) {
	if a == nil || !isAgentSpawnerTool(tool) || strings.TrimSpace(meta.Source) == "" ||
		strings.TrimSpace(meta.SessionID) == "" || strings.TrimSpace(meta.AgentID) == "" {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	parent := a.canonicalHookSpawnParent(meta)
	aliases := hookSpawnAliasesFromDocuments(documents...)
	toolKey := hookSpawnIntentToolKey(meta)
	scope := hookSpawnIntentScope(meta)

	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.evictHookSpawnIntentsLocked(now)
	if a.hookSpawnIntents == nil {
		a.hookSpawnIntents = make(map[string]hookSpawnIntent)
	}

	if phase == hookSpawnIntentFailed {
		a.discardHookSpawnIntentLocked(scope, toolKey, parent.AgentID, aliases)
		return
	}

	if toolKey != "" {
		if existing, ok := a.hookSpawnIntents[toolKey]; ok {
			if existing.parent.AgentID != parent.AgentID || existing.parent.ExecutionID != parent.ExecutionID {
				existing.ambiguous = true
				existing.updatedAt = now
				a.hookSpawnIntents[toolKey] = existing
				return
			}
			hookSpawnMergeAliases(existing.aliases, aliases)
			existing.updatedAt = now
			existing.resultObserved = existing.resultObserved || phase == hookSpawnIntentCompleted
			a.hookSpawnIntents[toolKey] = existing
			a.touchHookSpawnIntentLocked(toolKey)
			return
		}
		a.insertHookSpawnIntentLocked(hookSpawnIntent{
			key: toolKey, toolKey: toolKey, parent: parent, aliases: aliases,
			createdAt: now, updatedAt: now, resultObserved: phase == hookSpawnIntentCompleted,
		})
		return
	}

	candidates := a.hookSpawnIntentCandidatesLocked(scope, parent.AgentID, aliases)
	if phase == hookSpawnIntentCompleted && len(candidates) == 1 {
		existing := a.hookSpawnIntents[candidates[0]]
		hookSpawnMergeAliases(existing.aliases, aliases)
		existing.updatedAt = now
		existing.resultObserved = true
		a.hookSpawnIntents[candidates[0]] = existing
		a.touchHookSpawnIntentLocked(candidates[0])
		return
	}
	if phase == hookSpawnIntentCompleted && len(candidates) > 1 {
		return
	}
	seedAliases := make([]string, 0, len(aliases))
	for alias := range aliases {
		seedAliases = append(seedAliases, alias)
	}
	sort.Strings(seedAliases)
	key := stableLLMEventID(
		"spawn-intent", scope, parent.AgentID, parent.ExecutionID,
		firstNonEmpty(meta.OperationID, meta.TurnID), strings.Join(seedAliases, ","),
	)
	if existing, exists := a.hookSpawnIntents[key]; exists && meta.OperationID != "" &&
		existing.parent.OperationID == meta.OperationID && existing.parent.AgentID == parent.AgentID {
		hookSpawnMergeAliases(existing.aliases, aliases)
		existing.updatedAt = now
		existing.resultObserved = existing.resultObserved || phase == hookSpawnIntentCompleted
		a.hookSpawnIntents[key] = existing
		a.touchHookSpawnIntentLocked(key)
		return
	} else if exists {
		key = stableLLMEventID(key, now.Format(time.RFC3339Nano))
	}
	a.insertHookSpawnIntentLocked(hookSpawnIntent{
		key: key, parent: parent, aliases: aliases,
		createdAt: now, updatedAt: now, resultObserved: phase == hookSpawnIntentCompleted,
	})
}

// forgetHookSpawnIntent drops the spawn intent of meta's tool call, if one
// is left.
func (a *APIServer) forgetHookSpawnIntent(meta llmEventMeta) {
	key := hookSpawnIntentToolKey(meta)
	if a == nil || key == "" {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.removeHookSpawnIntentLocked(key)
}

// hookChildThread is a session a parent agent's spawn tool call started: the
// parent as it was when the call returned the child's thread id.
type hookChildThread struct {
	parent    llmEventMeta
	createdAt time.Time
}

var codexThreadIDPattern = regexp.MustCompile(`"threadId"\s*:\s*"([A-Za-z0-9][A-Za-z0-9._-]{7,127})"`)

// isCodexThreadSpawnTool reports whether tool is the Codex TUI's
// create_thread. Codex 0.160 runs a spawned agent as a thread of its own: it
// hooks as a session with its own id, fires no SubagentStart, and names the
// child only in this call's result, as {"threadId": "..."} (GAP-0179).
func isCodexThreadSpawnTool(tool string) bool {
	return strings.EqualFold(strings.TrimSpace(tool), "mcp__codex_tui__create_thread")
}

func hookChildThreadKey(meta llmEventMeta) string {
	return strings.ToLower(strings.TrimSpace(meta.Source)) + "\x00" + strings.TrimSpace(meta.SessionID) + "\x00" + meta.AgentIdentityID
}

// A thread can hook before the create_thread call that started it returns:
// Codex starts the thread, then runs the PostToolUse hook of the call. On a
// managed Linux host the thread SessionStart reached the gateway 100 ms before
// the call result, so the thread was recorded as a root at depth 0
// (GAP-0179). A create_thread call in flight is therefore noted at
// PreToolUse, and the first hook of a Codex session not seen before, of the
// same agent identity and user, is taken as its thread while every call in
// flight has one parent. The result, when it arrives first, names the thread.
const (
	codexPendingThreadTTL = 2 * time.Minute
	codexPendingThreadMax = 256
)

type codexPendingThread struct {
	toolID    string
	parent    llmEventMeta
	child     string
	createdAt time.Time
}

// noteCodexThreadCall remembers a create_thread call in flight.
func (a *APIServer) noteCodexThreadCall(meta llmEventMeta, tool string) {
	// Secure Client keeps the lineage of main (issue #1092).
	if a == nil || a.managedAIDOnly() || !isCodexThreadSpawnTool(tool) || meta.AgentIdentityID == "" {
		return
	}
	parent := a.canonicalHookSpawnParent(meta)
	if strings.TrimSpace(parent.AgentID) == "" || parent.AgentDepth < 0 || parent.AgentDepth >= 64 {
		return
	}
	now := time.Now().UTC()
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.pruneCodexPendingThreadsLocked(now)
	for len(a.codexPendingThreads) >= codexPendingThreadMax {
		a.codexPendingThreads = a.codexPendingThreads[1:]
	}
	a.codexPendingThreads = append(a.codexPendingThreads, codexPendingThread{toolID: meta.ToolID, parent: parent, createdAt: now})
}

// pruneCodexPendingThreadsLocked drops the expired calls. Caller holds
// a.llmPromptMu.
func (a *APIServer) pruneCodexPendingThreadsLocked(now time.Time) {
	kept := a.codexPendingThreads[:0]
	for _, pending := range a.codexPendingThreads {
		if now.Sub(pending.createdAt) <= codexPendingThreadTTL {
			kept = append(kept, pending)
		}
	}
	a.codexPendingThreads = kept
}

// finishCodexThreadCallLocked drops the call that returned: the one of its
// tool call id, or else the oldest of its session. Caller holds a.llmPromptMu.
func (a *APIServer) finishCodexThreadCallLocked(toolID, session string) {
	match := -1
	for i, pending := range a.codexPendingThreads {
		if pending.parent.SessionID != session {
			continue
		}
		if toolID != "" && pending.toolID == toolID {
			match = i
			break
		}
		if match < 0 {
			match = i
		}
	}
	if match >= 0 {
		a.codexPendingThreads = append(a.codexPendingThreads[:match], a.codexPendingThreads[match+1:]...)
	}
}

// claimCodexPendingThread links the first hook of a new Codex session to the
// create_thread call in flight that started it, when the call result has not
// named the thread yet.
func (a *APIServer) claimCodexPendingThread(meta llmEventMeta) llmEventMeta {
	if a == nil || a.managedAIDOnly() || meta.Source != "codex" || meta.AgentIdentityID == "" ||
		strings.TrimSpace(meta.SessionID) == "" || meta.LineageProvenance == "reported" || meta.ParentAgentReported ||
		strings.TrimSpace(meta.ParentAgentID) != "" || strings.TrimSpace(meta.ParentSessionID) != "" || meta.AgentDepth != 0 {
		return meta
	}
	if _, seen := a.hookSessionStateSnapshot(meta.Source, meta.SessionID, ""); seen {
		return meta
	}
	now := time.Now().UTC()
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if _, linked := a.hookChildThreads[hookChildThreadKey(meta)]; linked {
		return meta
	}
	a.pruneCodexPendingThreadsLocked(now)
	claimed := -1
	for i, pending := range a.codexPendingThreads {
		if pending.child != "" || pending.parent.SessionID == meta.SessionID || !sameHookIdentity(pending.parent, meta) {
			continue
		}
		if claimed >= 0 && (pending.parent.SessionID != a.codexPendingThreads[claimed].parent.SessionID ||
			pending.parent.AgentID != a.codexPendingThreads[claimed].parent.AgentID) {
			return meta // calls in flight under two parents: the thread of either
		}
		if claimed < 0 {
			claimed = i
		}
	}
	if claimed >= 0 {
		a.codexPendingThreads[claimed].child = meta.SessionID
		a.storeHookChildThreadLocked(meta, a.codexPendingThreads[claimed].parent, now)
	}
	return meta
}

// rememberHookChildThread records the thread a completed create_thread call
// started, so the first hook of that session is linked to the calling agent.
func (a *APIServer) rememberHookChildThread(meta llmEventMeta, tool, response string) {
	// Secure Client keeps the lineage of main (issue #1092).
	if a == nil || a.managedAIDOnly() || !isCodexThreadSpawnTool(tool) {
		return
	}
	a.llmPromptMu.Lock()
	a.finishCodexThreadCallLocked(meta.ToolID, meta.SessionID)
	a.llmPromptMu.Unlock()
	match := codexThreadIDPattern.FindStringSubmatch(response)
	if match == nil || match[1] == strings.TrimSpace(meta.SessionID) {
		return
	}
	parent := a.canonicalHookSpawnParent(meta)
	if strings.TrimSpace(parent.AgentID) == "" || parent.AgentDepth < 0 || parent.AgentDepth >= 64 {
		return
	}
	child := meta
	child.SessionID = match[1]
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.storeHookChildThreadLocked(child, parent, time.Now().UTC())
}

// storeHookChildThreadLocked records that child's session is one parent
// started. Caller holds a.llmPromptMu.
func (a *APIServer) storeHookChildThreadLocked(child, parent llmEventMeta, now time.Time) {
	key := hookChildThreadKey(child)
	if a.hookChildThreads == nil {
		a.hookChildThreads = make(map[string]hookChildThread)
	}
	kept := a.hookChildThreadOrder[:0]
	for _, candidate := range a.hookChildThreadOrder {
		if link, ok := a.hookChildThreads[candidate]; ok && candidate != key && now.Sub(link.createdAt) <= hookChildThreadTTL {
			kept = append(kept, candidate)
		} else {
			delete(a.hookChildThreads, candidate)
		}
	}
	a.hookChildThreadOrder = kept
	for len(a.hookChildThreads) >= hookChildThreadMaxEntries && len(a.hookChildThreadOrder) > 0 {
		delete(a.hookChildThreads, a.hookChildThreadOrder[0])
		a.hookChildThreadOrder = a.hookChildThreadOrder[1:]
	}
	a.hookChildThreads[key] = hookChildThread{parent: parent, createdAt: now}
	a.hookChildThreadOrder = append(a.hookChildThreadOrder, key)
}

// Copilot CLI runs a task sub-agent in a session of its own. Its tool hooks
// name only that child session; subagentStart arrives in the parent's session
// before the child's first hook and names only the agent, and subagentStop,
// after the child's last hook, names the child session as agentId
// (GAP-0371). A child session's first hook (not a sessionStart, which only a
// chat sends) is therefore linked to the agent of a pending subagentStart of
// the same agent identity, when every pending start shares one parent, and
// subagentStop links the session it names in any case.
const (
	copilotSubagentTTL        = 30 * time.Minute
	copilotSubagentMaxPending = 256
)

type copilotPendingSubagent struct {
	identity  string
	parent    llmEventMeta
	child     string
	createdAt time.Time
}

// applyCopilotSubagentLineage tracks Copilot sub-agent starts and stops and
// links a child session's hooks to the agent that started it.
func (a *APIServer) applyCopilotSubagentLineage(meta llmEventMeta, payload map[string]any) llmEventMeta {
	// Secure Client keeps the lineage of main (issue #1092).
	if a == nil || meta.Source != "copilot" || a.managedAIDOnly() || meta.AgentIdentityID == "" ||
		strings.TrimSpace(meta.SessionID) == "" {
		return meta
	}
	now := time.Now().UTC()
	switch meta.LifecycleEvent {
	case "subagent_start":
		a.noteCopilotSubagentStart(meta, now)
		return meta
	case "subagent_stop":
		return a.noteCopilotSubagentStop(meta, firstString(payload, "agentId", "agent_id"), now)
	case "session_start":
		return meta
	}
	if linked := a.applyHookChildThreadLineage(meta); linked.ParentLineageResolved || meta.AgentDepth != 0 ||
		meta.ParentSessionID != "" || meta.LineageProvenance == "reported" {
		return linked
	}
	if _, seen := a.hookSessionStateSnapshot("copilot", meta.SessionID, ""); seen {
		return meta
	}
	a.llmPromptMu.Lock()
	claimed := -1
	for i, pending := range a.copilotSubagents {
		if pending.identity != meta.AgentIdentityID || pending.child != "" ||
			pending.parent.SessionID == meta.SessionID || now.Sub(pending.createdAt) > copilotSubagentTTL {
			continue
		}
		if claimed >= 0 && (pending.parent.SessionID != a.copilotSubagents[claimed].parent.SessionID ||
			pending.parent.AgentID != a.copilotSubagents[claimed].parent.AgentID) {
			claimed = -1 // open starts under two parents: the child's is not known
			break
		}
		if claimed < 0 {
			claimed = i
		}
	}
	if claimed >= 0 {
		a.copilotSubagents[claimed].child = meta.SessionID
		a.storeHookChildThreadLocked(meta, a.copilotSubagents[claimed].parent, now)
	}
	a.llmPromptMu.Unlock()
	if claimed < 0 {
		return meta
	}
	return a.applyHookChildThreadLineage(meta)
}

func (a *APIServer) noteCopilotSubagentStart(meta llmEventMeta, now time.Time) {
	parent, ok := a.hookSessionStateSnapshot("copilot", meta.SessionID,
		agentNodeID(meta.AgentIdentityID, "copilot", meta.SessionID, "root"))
	if !ok {
		if parent, ok = a.hookSessionStateSnapshot("copilot", meta.SessionID, ""); !ok {
			return
		}
	}
	if strings.TrimSpace(parent.meta.AgentID) == "" || parent.meta.AgentDepth < 0 || parent.meta.AgentDepth >= 64 {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	kept := a.copilotSubagents[:0]
	for _, pending := range a.copilotSubagents {
		if now.Sub(pending.createdAt) <= copilotSubagentTTL {
			kept = append(kept, pending)
		}
	}
	a.copilotSubagents = kept
	if len(a.copilotSubagents) >= copilotSubagentMaxPending {
		a.copilotSubagents = a.copilotSubagents[1:]
	}
	a.copilotSubagents = append(a.copilotSubagents, copilotPendingSubagent{
		identity: meta.AgentIdentityID, parent: parent.meta, createdAt: now,
	})
}

// noteCopilotSubagentStop ends the pending start the child session belongs
// to and links that session, which agent identities then does not count as a
// chat.
func (a *APIServer) noteCopilotSubagentStop(meta llmEventMeta, child string, now time.Time) llmEventMeta {
	child = strings.TrimSpace(child)
	a.llmPromptMu.Lock()
	match := -1
	for i, pending := range a.copilotSubagents {
		if pending.identity != meta.AgentIdentityID || pending.parent.SessionID != meta.SessionID {
			continue
		}
		if child != "" && pending.child == child {
			match = i
			break
		}
		if match < 0 && pending.child == "" {
			match = i
		}
	}
	var parent llmEventMeta
	if match >= 0 {
		parent = a.copilotSubagents[match].parent
		a.copilotSubagents = append(a.copilotSubagents[:match], a.copilotSubagents[match+1:]...)
	}
	linked := match >= 0 && child != "" && child != meta.SessionID
	if linked {
		childMeta := meta
		childMeta.SessionID = child
		a.storeHookChildThreadLocked(childMeta, parent, now)
	}
	a.llmPromptMu.Unlock()
	if linked {
		sharedAgentIdentities.markSubagentSession(meta.AgentIdentityID, child)
		// Copilot sends subagentStop in the parent's session with agentId
		// equal to the child's session UUID. Emit the lifecycle row with the
		// same child node and parent edge as that child's tool rows.
		meta.SessionID = child
		meta.AgentID = agentNodeID(meta.AgentIdentityID, "copilot", child, "root")
		meta.ParentAgentID = parent.AgentID
		meta.RootAgentID = firstNonEmpty(parent.RootAgentID, parent.AgentID)
		meta.ParentSessionID = parent.SessionID
		meta.RootSessionID = firstNonEmpty(parent.RootSessionID, parent.SessionID)
		meta.AgentDepth = parent.AgentDepth + 1
		meta.LineageProvenance = "inferred"
		meta.ParentLineageResolved = true
		meta.LifecycleID = stableLLMEventID("lifecycle", meta.Source, child, meta.AgentID)
		if snapshot, ok := a.hookSessionStateSnapshot(meta.Source, child, meta.AgentID); ok {
			meta.ExecutionID = snapshot.meta.ExecutionID
		}
	}
	return meta
}

// applyHookChildThreadLineage links a hook of a session that a create_thread
// call started to the agent that called it: depth one under it, the parent
// session named. It changes nothing for a hook that already has a parent, a
// reported lineage, or another user's session.
func (a *APIServer) applyHookChildThreadLineage(meta llmEventMeta) llmEventMeta {
	if a == nil || meta.LineageProvenance == "reported" || meta.ParentAgentReported || meta.ParentLineageResolved ||
		strings.TrimSpace(meta.ParentAgentID) != "" || strings.TrimSpace(meta.ParentSessionID) != "" || meta.AgentDepth != 0 {
		return meta
	}
	a.llmPromptMu.Lock()
	link, ok := a.hookChildThreads[hookChildThreadKey(meta)]
	a.llmPromptMu.Unlock()
	if !ok || time.Since(link.createdAt) > hookChildThreadTTL {
		return meta
	}
	parent := link.parent
	if !sameHookIdentity(parent, meta) {
		return meta
	}
	meta.ParentAgentID = parent.AgentID
	meta.RootAgentID = firstNonEmpty(parent.RootAgentID, parent.AgentID)
	meta.ParentSessionID = parent.SessionID
	meta.RootSessionID = firstNonEmpty(parent.RootSessionID, parent.SessionID)
	meta.AgentDepth = parent.AgentDepth + 1
	meta.LineageProvenance = "inferred"
	meta.ParentLineageResolved = true
	return meta
}

// hookAgentStateKnown reports whether the agent's lifecycle is retained: a
// start (SubagentStart, or an inferred one) or another hook of it was seen.
func (a *APIServer) hookAgentStateKnown(source, sessionID, agentID string) bool {
	if strings.TrimSpace(agentID) == "" {
		return false
	}
	_, ok := a.hookSessionStateSnapshot(source, sessionID, agentID)
	return ok
}

func (a *APIServer) hookSpawnIntentCandidatesLocked(
	scope, parentAgentID string,
	aliases map[string]struct{},
) []string {
	candidates := make([]string, 0, 2)
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || intent.ambiguous || hookSpawnIntentScope(intent.parent) != scope ||
			(parentAgentID != "" && intent.parent.AgentID != parentAgentID) {
			continue
		}
		if len(aliases) > 0 && hookSpawnAliasScore(aliases, intent.aliases) == 0 {
			continue
		}
		candidates = append(candidates, key)
	}
	return candidates
}

func (a *APIServer) discardHookSpawnIntentLocked(
	scope, toolKey, parentAgentID string,
	aliases map[string]struct{},
) {
	if toolKey != "" {
		a.removeHookSpawnIntentLocked(toolKey)
		return
	}
	candidates := a.hookSpawnIntentCandidatesLocked(scope, parentAgentID, aliases)
	if len(candidates) == 1 {
		a.removeHookSpawnIntentLocked(candidates[0])
	}
}

func (a *APIServer) insertHookSpawnIntentLocked(intent hookSpawnIntent) {
	for len(a.hookSpawnIntents) >= hookSpawnIntentMaxEntries && len(a.hookSpawnIntentOrder) > 0 {
		a.removeHookSpawnIntentLocked(a.hookSpawnIntentOrder[0])
	}
	a.hookSpawnIntents[intent.key] = intent
	a.hookSpawnIntentOrder = append(a.hookSpawnIntentOrder, intent.key)
}

func (a *APIServer) touchHookSpawnIntentLocked(key string) {
	for index, candidate := range a.hookSpawnIntentOrder {
		if candidate == key {
			copy(a.hookSpawnIntentOrder[index:], a.hookSpawnIntentOrder[index+1:])
			a.hookSpawnIntentOrder = a.hookSpawnIntentOrder[:len(a.hookSpawnIntentOrder)-1]
			break
		}
	}
	a.hookSpawnIntentOrder = append(a.hookSpawnIntentOrder, key)
}

func (a *APIServer) removeHookSpawnIntentLocked(key string) {
	delete(a.hookSpawnIntents, key)
	for index, candidate := range a.hookSpawnIntentOrder {
		if candidate == key {
			copy(a.hookSpawnIntentOrder[index:], a.hookSpawnIntentOrder[index+1:])
			a.hookSpawnIntentOrder = a.hookSpawnIntentOrder[:len(a.hookSpawnIntentOrder)-1]
			return
		}
	}
}

func (a *APIServer) evictHookSpawnIntentsLocked(now time.Time) {
	if len(a.hookSpawnIntentOrder) == 0 {
		return
	}
	kept := a.hookSpawnIntentOrder[:0]
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok {
			continue
		}
		if now.Sub(intent.updatedAt) > hookSpawnIntentTTL {
			delete(a.hookSpawnIntents, key)
			continue
		}
		kept = append(kept, key)
	}
	a.hookSpawnIntentOrder = kept
}

func (a *APIServer) takeHookSpawnIntentAt(
	meta llmEventMeta,
	aliases map[string]struct{},
	now time.Time,
) (hookSpawnIntent, bool) {
	if a == nil || strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.SessionID) == "" {
		return hookSpawnIntent{}, false
	}
	scope := hookSpawnIntentScope(meta)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.evictHookSpawnIntentsLocked(now)

	candidates := make([]scoredHookSpawnIntent, 0, 4)
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || intent.ambiguous || hookSpawnIntentScope(intent.parent) != scope ||
			intent.parent.AgentID == "" || intent.parent.AgentID == meta.AgentID || !sameHookIdentity(intent.parent, meta) {
			continue
		}
		score := hookSpawnAliasScore(aliases, intent.aliases)
		if len(aliases) > 0 && score == 0 {
			continue
		}
		candidates = append(candidates, scoredHookSpawnIntent{key: key, score: score, ready: intent.resultObserved})
	}
	if len(candidates) == 0 {
		return hookSpawnIntent{}, false
	}
	readyCount := 0
	for _, candidate := range candidates {
		if candidate.ready {
			readyCount++
		}
	}
	if readyCount > 0 {
		filtered := candidates[:0]
		for _, candidate := range candidates {
			if candidate.ready {
				filtered = append(filtered, candidate)
			}
		}
		candidates = filtered
	}
	best := candidates[0]
	tied := false
	for _, candidate := range candidates[1:] {
		switch {
		case candidate.score > best.score:
			best = candidate
			tied = false
		case candidate.score == best.score:
			tied = true
		}
	}
	if tied && !a.hookSpawnTieSharesParentLocked(meta.Source, candidates, best) {
		return hookSpawnIntent{}, false
	}
	intent := a.hookSpawnIntents[best.key]
	a.removeHookSpawnIntentLocked(best.key)
	return intent, true
}

// hookSpawnTieSharesParentLocked reports whether a tie between the best
// scored spawn intents may be broken by taking the oldest (best, the first
// in intent order): only where every tied intent names the same parent, so
// the child's lineage is the same whichever it takes, and only for a
// connector whose children name nothing to tell the calls apart by. Claude
// Code is one: its subagents cannot start subagents (a subagent's model
// request offers no Agent tool; measured on 2.1.156 for #957), so every
// Agent call of a session is the main agent's, and its SubagentStart
// carries only agent_id and agent_type. Parallel Agent calls therefore
// always tie. Which call ran which subagent follows exactly from the
// call's PostToolUse (tool_response.agentId), not from this choice.
func (a *APIServer) hookSpawnTieSharesParentLocked(source string, candidates []scoredHookSpawnIntent, best scoredHookSpawnIntent) bool {
	if !strings.EqualFold(strings.TrimSpace(source), "claudecode") {
		return false
	}
	want := a.hookSpawnIntents[best.key].parent
	for _, candidate := range candidates {
		if candidate.score != best.score {
			continue
		}
		got := a.hookSpawnIntents[candidate.key].parent
		if got.AgentID != want.AgentID || got.ExecutionID != want.ExecutionID ||
			got.RootAgentID != want.RootAgentID || got.AgentDepth != want.AgentDepth ||
			got.SessionID != want.SessionID || got.RootSessionID != want.RootSessionID {
			return false
		}
	}
	return true
}

// takeUniqueCompletedHookSpawnIntentForUnseenAgentAt owns the conservative
// fallback used by Codex releases that report a completed spawn tool call but
// never emit SubagentStart. Unlike the explicit-start matcher above, this path
// deliberately ignores aliases: the child's first tool payload describes the
// child's work, not its spawn identity. Exactly one completed intent in the
// connector/session scope is therefore the only admissible correlation.
func (a *APIServer) takeUniqueCompletedHookSpawnIntentForUnseenAgentAt(
	meta llmEventMeta,
	now time.Time,
) (hookSpawnIntent, bool) {
	if a == nil || strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.SessionID) == "" ||
		strings.TrimSpace(meta.AgentID) == "" {
		return hookSpawnIntent{}, false
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scope := hookSpawnIntentScope(meta)
	childKey := hookSessionStateKey(meta)

	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.evictHookSpawnIntentsLocked(now)
	if childKey == "" {
		return hookSpawnIntent{}, false
	}
	if _, seen := a.hookSessionStates[childKey]; seen {
		return hookSpawnIntent{}, false
	}

	selectedKey := ""
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || intent.ambiguous || !intent.resultObserved ||
			hookSpawnIntentScope(intent.parent) != scope {
			continue
		}
		if selectedKey != "" {
			return hookSpawnIntent{}, false
		}
		selectedKey = key
	}
	if selectedKey == "" {
		return hookSpawnIntent{}, false
	}

	intent := a.hookSpawnIntents[selectedKey]
	parent := intent.parent
	if parentKey := hookSessionStateKey(parent); parentKey != "" {
		if snapshot, ok := a.hookSessionStates[parentKey]; ok {
			parent = snapshot.meta
		}
	}
	if strings.TrimSpace(parent.AgentID) == "" || parent.AgentID == meta.AgentID ||
		parent.AgentDepth < 0 || parent.AgentDepth >= 64 {
		return hookSpawnIntent{}, false
	}
	intent.parent = parent
	a.removeHookSpawnIntentLocked(selectedKey)
	return intent, true
}

func (a *APIServer) inferHookSpawnFromFirstEvent(
	meta llmEventMeta,
) (llmEventMeta, llmEventMeta, bool) {
	return a.inferHookSpawnFromFirstEventAt(meta, time.Now().UTC())
}

// inferHookSpawnFromFirstEvent returns the corrected original event plus one
// synthetic canonical SubagentStart. Reported topology and explicit starts are
// never changed here; explicit SubagentStart continues to use the alias-aware
// matcher in applyHookSpawnIntentLineage.
func (a *APIServer) inferHookSpawnFromFirstEventAt(
	meta llmEventMeta,
	now time.Time,
) (llmEventMeta, llmEventMeta, bool) {
	if a == nil || meta.LifecycleEvent == "session_start" || meta.LifecycleEvent == "subagent_start" ||
		meta.LineageProvenance == "reported" || meta.ParentAgentReported || meta.ParentLineageResolved {
		return meta, llmEventMeta{}, false
	}
	intent, ok := a.takeUniqueCompletedHookSpawnIntentForUnseenAgentAt(meta, now)
	if !ok {
		return meta, llmEventMeta{}, false
	}
	parent := intent.parent
	meta.ParentAgentID = parent.AgentID
	meta.RootAgentID = firstNonEmpty(parent.RootAgentID, parent.AgentID)
	meta.ParentSessionID = firstNonEmpty(parent.SessionID, parent.RootSessionID)
	meta.RootSessionID = firstNonEmpty(parent.RootSessionID, parent.SessionID, meta.SessionID)
	meta.AgentDepth = parent.AgentDepth + 1
	meta.AgentType = "subagent"
	meta.LineageProvenance = "inferred"
	meta.ParentLineageResolved = true

	start := meta
	start.LifecycleEvent = "subagent_start"
	start.LifecycleState = "active"
	start.LifecycleOutcome = "attempted"
	start.LifecycleDedupe = ""
	start.Phase = "session"
	start.PreviousPhase = ""
	start.OperationID = ""
	start.Sequence = 0
	start.PromptID = ""
	start.ResponseID = ""
	start.ToolName = ""
	start.ToolID = ""
	start.TraceEventID = ""
	start.ReportedCostUSD = 0
	start.ReportedCost = false
	start.ReportedCostSum = false
	return meta, start, true
}

// clearUnresolvedHookSpawnFallback removes the legacy depth-one session-root
// edge only when a same-scope spawn intent proves that a child exists but the
// owning parent cannot be correlated uniquely. Without an active intent, the
// historical one-level inference used by generic connectors is preserved.
func (a *APIServer) clearUnresolvedHookSpawnFallbackAt(meta llmEventMeta, now time.Time) llmEventMeta {
	if a == nil || meta.LineageProvenance == "reported" || meta.ParentAgentReported || meta.ParentLineageResolved ||
		strings.TrimSpace(meta.AgentID) == "" {
		return meta
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scope := hookSpawnIntentScope(meta)
	childKey := hookSessionStateKey(meta)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.evictHookSpawnIntentsLocked(now)
	if childKey == "" {
		return meta
	}
	if _, seen := a.hookSessionStates[childKey]; seen {
		return meta
	}
	hasUnresolvedIntent := false
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || hookSpawnIntentScope(intent.parent) != scope ||
			intent.parent.AgentID == "" || intent.parent.AgentID == meta.AgentID || !sameHookIdentity(intent.parent, meta) {
			continue
		}
		hasUnresolvedIntent = true
		break
	}
	if !hasUnresolvedIntent {
		return meta
	}
	meta.RootAgentID = meta.AgentID
	meta.ParentAgentID = ""
	meta.RootSessionID = meta.SessionID
	meta.ParentSessionID = ""
	meta.AgentDepth = 0
	meta.LineageProvenance = ""
	return meta
}

func (a *APIServer) applyHookSpawnIntentLineage(
	meta llmEventMeta,
	payload map[string]any,
) llmEventMeta {
	return a.applyHookSpawnIntentLineageAt(meta, payload, time.Now().UTC())
}

func (a *APIServer) applyHookSpawnIntentLineageAt(
	meta llmEventMeta,
	payload map[string]any,
	now time.Time,
) llmEventMeta {
	if a == nil || meta.LifecycleEvent != "subagent_start" || meta.LineageProvenance == "reported" ||
		meta.ParentAgentReported {
		return meta
	}
	aliases := hookSpawnAliasesFromChild(meta, payload)
	intent, ok := a.takeHookSpawnIntentAt(meta, aliases, now)
	if !ok {
		return a.clearUnresolvedHookSpawnFallbackAt(meta, now)
	}
	parent := a.canonicalHookSpawnParent(intent.parent)
	if parent.AgentID == "" || parent.AgentID == meta.AgentID || parent.AgentDepth < 0 || parent.AgentDepth >= 64 {
		return meta
	}
	meta.ParentAgentID = parent.AgentID
	meta.RootAgentID = firstNonEmpty(parent.RootAgentID, parent.AgentID)
	meta.ParentSessionID = firstNonEmpty(parent.SessionID, parent.RootSessionID)
	meta.RootSessionID = firstNonEmpty(parent.RootSessionID, parent.SessionID, meta.SessionID)
	meta.AgentDepth = parent.AgentDepth + 1
	meta.LineageProvenance = "inferred"
	meta.ParentLineageResolved = true
	return meta
}
