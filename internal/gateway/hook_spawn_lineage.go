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
	source         string
	sessionID      string
	parent         llmEventMeta
	aliases        map[string]struct{}
	createdAt      time.Time
	updatedAt      time.Time
	resultObserved bool
	ambiguous      bool
}

var hookSpawnTaskPattern = regexp.MustCompile(`(?i)(?:task[_-]?name|agent[_-]?name|child[_-]?(?:name|role))\s*[:=]\s*["']?([A-Za-z0-9_./:-]{1,512})`)

func hookSpawnIntentToolKey(meta llmEventMeta) string {
	source := strings.ToLower(strings.TrimSpace(meta.Source))
	sessionID := strings.TrimSpace(meta.SessionID)
	toolID := strings.TrimSpace(meta.ToolID)
	if source == "" || sessionID == "" || toolID == "" {
		return ""
	}
	return strings.Join([]string{source, sessionID, toolID}, "\x00")
}

func hookSpawnIntentScope(source, sessionID string) string {
	return strings.ToLower(strings.TrimSpace(source)) + "\x00" + strings.TrimSpace(sessionID)
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
	scope := hookSpawnIntentScope(meta.Source, meta.SessionID)

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
			key: toolKey, toolKey: toolKey, source: strings.ToLower(strings.TrimSpace(meta.Source)),
			sessionID: strings.TrimSpace(meta.SessionID), parent: parent, aliases: aliases,
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
		key: key, source: strings.ToLower(strings.TrimSpace(meta.Source)),
		sessionID: strings.TrimSpace(meta.SessionID), parent: parent, aliases: aliases,
		createdAt: now, updatedAt: now, resultObserved: phase == hookSpawnIntentCompleted,
	})
}

func (a *APIServer) hookSpawnIntentCandidatesLocked(
	scope, parentAgentID string,
	aliases map[string]struct{},
) []string {
	candidates := make([]string, 0, 2)
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || intent.ambiguous || hookSpawnIntentScope(intent.source, intent.sessionID) != scope ||
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
	scope := hookSpawnIntentScope(meta.Source, meta.SessionID)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	a.evictHookSpawnIntentsLocked(now)

	type scoredIntent struct {
		key   string
		score int
		ready bool
	}
	candidates := make([]scoredIntent, 0, 4)
	for _, key := range a.hookSpawnIntentOrder {
		intent, ok := a.hookSpawnIntents[key]
		if !ok || intent.ambiguous || hookSpawnIntentScope(intent.source, intent.sessionID) != scope ||
			intent.parent.AgentID == "" || intent.parent.AgentID == meta.AgentID {
			continue
		}
		score := hookSpawnAliasScore(aliases, intent.aliases)
		if len(aliases) > 0 && score == 0 {
			continue
		}
		candidates = append(candidates, scoredIntent{key: key, score: score, ready: intent.resultObserved})
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
	if tied {
		return hookSpawnIntent{}, false
	}
	intent := a.hookSpawnIntents[best.key]
	a.removeHookSpawnIntentLocked(best.key)
	return intent, true
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
	scope := hookSpawnIntentScope(meta.Source, meta.SessionID)
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
			hookSpawnIntentScope(intent.source, intent.sessionID) != scope {
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
	scope := hookSpawnIntentScope(meta.Source, meta.SessionID)
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
		if !ok || hookSpawnIntentScope(intent.source, intent.sessionID) != scope ||
			intent.parent.AgentID == "" || intent.parent.AgentID == meta.AgentID {
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
