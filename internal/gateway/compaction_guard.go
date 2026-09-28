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

package gateway

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// This virtual patch recognizes the study's forged user-turn delimiters when
// they carry a bounded, study-derived claim. Only the narrower forged approval and
// curl-to-shell combination can affect a later tool decision. A delimiter
// alone is not evidence that an instruction survived compaction.
const (
	compactionGuardRuleID         = "COMPACTION-FORGED-APPROVAL-001"
	compactionPoisonRuleID        = "COMPACTION-INSTRUCTION-POISON-001"
	compactionCodexWarningMessage = "DefenseClaw found a possible forged user-role claim in tool output before compaction. The compacted context cannot be verified. Start a new session before sensitive work."
	compactionWarningMessage      = "DefenseClaw found evidence of a forged user instruction in Claude Code's exposed compaction summary. Start a new session before sensitive work."
	compactionNoEvidenceMessage   = "DefenseClaw compaction scan found no matching forged-user claim in the exposed summary. This does not verify the full session context."
	compactionNoSummaryMessage    = "DefenseClaw could not inspect Claude Code's compaction summary. The session remains unverified."
	compactionGuardMaxInput       = 256 * 1024
	compactionGuardMaxClaim       = 1024
	compactionGuardMaxMarkers     = 128
	compactionGuardMaxSessions    = 256
	compactionGuardMaxCandidates  = 8
	compactionGuardSessionTTL     = 2 * time.Hour
)

var (
	defaultCompactionOnce     sync.Once
	defaultCompactionCompiled *compiledCompactionPatterns
)

// The compaction-only signatures come from the effective runtime rule pack,
// not the generic content scanner. Its exact-action proof remains code-owned.
type compiledCompactionPatterns struct {
	configDigest       [sha256.Size]byte
	enabled            bool
	nextRole           *regexp.Regexp
	roleHeader         *regexp.Regexp
	avoidance          *regexp.Regexp
	exfiltration       *regexp.Regexp
	memory             *regexp.Regexp
	memoryVerb         *regexp.Regexp
	falseFact          *regexp.Regexp
	newTask            *regexp.Regexp
	override           *regexp.Regexp
	summaryApproval    *regexp.Regexp
	summaryInstruction *regexp.Regexp
	summaryDisavowal   *regexp.Regexp
	approval           *regexp.Regexp
	noAsk              *regexp.Regexp
	curlPipe           *regexp.Regexp
}

func compactionConfigFromRulePack(rp *guardrail.RulePack) *guardrail.CompactionConfig {
	if rp != nil {
		return rp.Compaction
	}
	return nil
}

func compactionConfigDigest(cfg *guardrail.CompactionConfig) [sha256.Size]byte {
	// Length prefixes preserve exact pattern bytes, including values that JSON
	// would normalize, while ignoring decoder-only bookkeeping in the struct.
	data := binary.AppendVarint(nil, int64(cfg.Version))
	if cfg.Enabled {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	for _, pattern := range []string{
		cfg.NextRole, cfg.RoleHeader, cfg.Avoidance, cfg.Exfiltration,
		cfg.Memory, cfg.MemoryVerb, cfg.FalseFact, cfg.NewTask, cfg.Override,
		cfg.SummaryApproval, cfg.SummaryInstruction, cfg.SummaryDisavowal,
		cfg.Approval, cfg.NoAsk, cfg.CurlPipe,
	} {
		data = binary.AppendUvarint(data, uint64(len(pattern)))
		data = append(data, pattern...)
	}
	return sha256.Sum256(data)
}

func defaultCompactionPatterns() *compiledCompactionPatterns {
	defaultCompactionOnce.Do(func() {
		rp, err := guardrail.LoadRulePack("")
		if err != nil {
			panic(fmt.Sprintf("load embedded compaction rule pack: %v", err))
		}
		defaultCompactionCompiled, err = compileCompactionPatterns(rp.Compaction)
		if err != nil {
			panic(fmt.Sprintf("compile embedded compaction rule pack: %v", err))
		}
	})
	return defaultCompactionCompiled
}

func compileCompactionPatterns(cfg *guardrail.CompactionConfig) (*compiledCompactionPatterns, error) {
	if cfg == nil {
		return defaultCompactionPatterns(), nil
	}
	// Only the exported rule-pack content defines the effective detector.
	// A fresh compilation of identical YAML must not discard active sessions.
	compiled := &compiledCompactionPatterns{
		configDigest: compactionConfigDigest(cfg),
		enabled:      cfg.Enabled,
	}
	if !cfg.Enabled {
		return compiled, nil
	}
	// Activation can also receive a programmatically built RulePack, bypassing
	// the YAML loader's validation. Recheck the pinned proof fields here before
	// publishing this generation to a live hook connector.
	canonical, err := guardrail.LoadRulePack("")
	if err != nil {
		return nil, fmt.Errorf("load embedded compaction proof: %w", err)
	}
	if cfg.Approval != canonical.Compaction.Approval ||
		cfg.NoAsk != canonical.Compaction.NoAsk ||
		cfg.CurlPipe != canonical.Compaction.CurlPipe {
		return nil, fmt.Errorf("compaction rule-pack exact-action proof patterns differ from embedded baseline")
	}
	fields := []struct {
		name string
		text string
		dst  **regexp.Regexp
	}{
		{"next_role", cfg.NextRole, &compiled.nextRole},
		{"role_header", cfg.RoleHeader, &compiled.roleHeader},
		{"avoidance", cfg.Avoidance, &compiled.avoidance},
		{"exfiltration", cfg.Exfiltration, &compiled.exfiltration},
		{"memory", cfg.Memory, &compiled.memory},
		{"memory_verb", cfg.MemoryVerb, &compiled.memoryVerb},
		{"false_fact", cfg.FalseFact, &compiled.falseFact},
		{"new_task", cfg.NewTask, &compiled.newTask},
		{"override", cfg.Override, &compiled.override},
		{"summary_approval", cfg.SummaryApproval, &compiled.summaryApproval},
		{"summary_instruction", cfg.SummaryInstruction, &compiled.summaryInstruction},
		{"summary_disavowal", cfg.SummaryDisavowal, &compiled.summaryDisavowal},
		{"approval", cfg.Approval, &compiled.approval},
		{"no_ask", cfg.NoAsk, &compiled.noAsk},
		{"curl_pipe", cfg.CurlPipe, &compiled.curlPipe},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.text) == "" {
			return nil, fmt.Errorf("compaction rule-pack %s is empty", field.name)
		}
		re, err := compileRegexSafe(field.text)
		if err != nil {
			return nil, fmt.Errorf("compaction rule-pack %s: %w", field.name, err)
		}
		*field.dst = re
	}
	return compiled, nil
}

func compactionPatternsForConnector(connector string) (*compiledCompactionPatterns, uint64) {
	connector = canonicalConnectorRulePackKey(connector)
	ruleCategoriesMu.RLock()
	patterns := effectiveCompactionPatternsLocked(connector)
	epoch := connectorCompactionEpoch[connector]
	ruleCategoriesMu.RUnlock()
	return patterns, epoch
}

type compactionGuardCandidate struct {
	seen           time.Time
	pending        bool
	active         bool
	warned         bool
	summaryAlerted bool
	summaryDigest  [sha256.Size]byte
}

type compactionGuardSession struct {
	lastSeen     time.Time
	patterns     *compiledCompactionPatterns
	packEpoch    uint64
	candidates   map[[sha256.Size]byte]*compactionGuardCandidate
	instructions map[[sha256.Size]byte]*compactionGuardCandidate
	approved     map[[sha256.Size]byte]time.Time
	inlineNotice string
	compactDue   bool
}

// compactionGuardStore is process-local and contains command digests only.
// No tool output, summary, prompt, URL, or command text is retained.
type compactionGuardStore struct {
	mu       sync.Mutex
	sessions map[string]*compactionGuardSession
}

func compactionGuardKey(connector, sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if (connector != "codex" && connector != "claudecode") || sessionID == "" || len(sessionID) > 256 {
		return ""
	}
	return connector + "\x00" + sessionID
}

func (s *compactionGuardStore) session(key string, create bool, now time.Time, patterns *compiledCompactionPatterns, epoch uint64) *compactionGuardSession {
	if key == "" || patterns == nil {
		return nil
	}
	if s.sessions == nil {
		if !create {
			return nil
		}
		s.sessions = make(map[string]*compactionGuardSession)
	}
	for id, state := range s.sessions {
		if now.Sub(state.lastSeen) > compactionGuardSessionTTL {
			delete(s.sessions, id)
		}
	}
	if state := s.sessions[key]; state != nil {
		if state.patterns.configDigest == patterns.configDigest && state.packEpoch == epoch && patterns.enabled {
			state.lastSeen = now
			return state
		}
		// A changed effective component must not inherit candidate or approval
		// digests, including across an off/on toggle without an intervening hook.
		delete(s.sessions, key)
	}
	if !create || !patterns.enabled {
		return nil
	}
	if len(s.sessions) >= compactionGuardMaxSessions {
		var oldestKey string
		var oldest time.Time
		for id, state := range s.sessions {
			if oldestKey == "" || state.lastSeen.Before(oldest) {
				oldestKey, oldest = id, state.lastSeen
			}
		}
		delete(s.sessions, oldestKey)
	}
	state := &compactionGuardSession{
		lastSeen:     now,
		patterns:     patterns,
		packEpoch:    epoch,
		candidates:   make(map[[sha256.Size]byte]*compactionGuardCandidate),
		instructions: make(map[[sha256.Size]byte]*compactionGuardCandidate),
		approved:     make(map[[sha256.Size]byte]time.Time),
	}
	s.sessions[key] = state
	return state
}

func (s *compactionGuardStore) reset(connector, sessionID string) {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

// observeToolResult performs a bounded exact-pattern scan on successful tool
// output. It only records a candidate; existing PostToolUse decisions remain
// entirely under their existing policy path.
func (s *compactionGuardStore) observeToolResult(connector, sessionID, output string) bool {
	key := compactionGuardKey(connector, sessionID)
	patterns, epoch := compactionPatternsForConnector(connector)
	if key == "" || patterns == nil || !patterns.enabled {
		return false
	}
	command, ok := forgedApprovalCommandWithPatterns(output, patterns)
	if !ok {
		return false
	}
	digest := sha256.Sum256([]byte(command))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now, patterns, epoch)
	if _, approved := state.approved[digest]; approved {
		return false
	}
	if prior := state.candidates[digest]; prior != nil {
		prior.seen = now
		return true
	}
	if len(state.candidates) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, candidate := range state.candidates {
			if oldest.IsZero() || candidate.seen.Before(oldest) {
				oldestDigest, oldest = id, candidate.seen
			}
		}
		delete(state.candidates, oldestDigest)
	}
	state.candidates[digest] = &compactionGuardCandidate{seen: now}
	return true
}

// observeInstructionResult records a role-spoofing shape that could promote
// tool content into user authority. It does not alter PostToolUse decisions;
// a declarative claim is only a warning candidate, not proof of intent.
func (s *compactionGuardStore) observeInstructionResult(connector, sessionID, output string) bool {
	key := compactionGuardKey(connector, sessionID)
	patterns, epoch := compactionPatternsForConnector(connector)
	if key == "" || patterns == nil || !patterns.enabled {
		return false
	}
	// The exact forged-approval path already records this tool result and
	// supports authenticated user approval; do not create a second alert
	// that would survive after that approval clears the action candidate.
	if _, strict := forgedApprovalCommandWithPatterns(output, patterns); strict {
		return false
	}
	claim, ok := instructionPoisoningClaimWithPatterns(output, patterns)
	if !ok {
		return false
	}
	digest := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(claim), " "))))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now, patterns, epoch)
	if prior := state.instructions[digest]; prior != nil {
		prior.seen = now
		return true
	}
	if len(state.instructions) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, candidate := range state.instructions {
			if oldest.IsZero() || candidate.seen.Before(oldest) {
				oldestDigest, oldest = id, candidate.seen
			}
		}
		delete(state.instructions, oldestDigest)
	}
	firstLine, _, _ := strings.Cut(claim, "\n")
	state.instructions[digest] = &compactionGuardCandidate{
		seen:          now,
		summaryDigest: sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(firstLine), " ")))),
	}
	return true
}

func (s *compactionGuardStore) observeUserPrompt(connector, sessionID, prompt string) {
	key := compactionGuardKey(connector, sessionID)
	patterns, epoch := compactionPatternsForConnector(connector)
	command, ok := explicitUserApprovalCommand(prompt)
	if key == "" || patterns == nil || !patterns.enabled || !ok {
		return
	}
	digest := sha256.Sum256([]byte(command))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now, patterns, epoch)
	if len(state.approved) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, seen := range state.approved {
			if oldest.IsZero() || seen.Before(oldest) {
				oldestDigest, oldest = id, seen
			}
		}
		delete(state.approved, oldestDigest)
	}
	state.approved[digest] = now
	delete(state.candidates, digest)
}

type compactionGuardPending struct {
	action      bool
	instruction bool
}

func (s *compactionGuardStore) preCompact(connector, sessionID string) compactionGuardPending {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return compactionGuardPending{}
	}
	patterns, epoch := compactionPatternsForConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, connector == "claudecode", time.Now(), patterns, epoch)
	if state == nil {
		return compactionGuardPending{}
	}
	state.compactDue = true
	var pending compactionGuardPending
	for _, candidate := range state.candidates {
		candidate.pending = true
		pending.action = true
	}
	for _, candidate := range state.instructions {
		candidate.pending = true
		pending.instruction = true
	}
	return pending
}

// PostCompact discards systemMessage. A summary-based notice is queued for the
// first eligible later hook because compact-source SessionStart can run first.
func (s *compactionGuardStore) takeClaudeInlineNotice(sessionID string) string {
	key := compactionGuardKey("claudecode", sessionID)
	if key == "" {
		return ""
	}
	patterns, epoch := compactionPatternsForConnector("claudecode")
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now(), patterns, epoch)
	if state == nil {
		return ""
	}
	notice := state.inlineNotice
	state.inlineNotice = ""
	return notice
}

// inspectClaudeSummary only treats an explicit user-authority assertion as
// evidence when it matches a prior forged claim from untrusted tool output.
// Quoted/code-fenced material and lines attributing the claim to a file or
// injection are excluded. This high-precision rule intentionally misses
// paraphrases; a negative result is never a safety certification. It returns
// true only for newly matched evidence so a later compaction does not repeat
// the same OS alert. The inline notice still describes each summary scan.
func (s *compactionGuardStore) inspectClaudeSummary(sessionID, summary string) bool {
	key := compactionGuardKey("claudecode", sessionID)
	if key == "" {
		return false
	}
	patterns, epoch := compactionPatternsForConnector("claudecode")
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, time.Now(), patterns, epoch)
	if state == nil {
		return false
	}
	if strings.TrimSpace(summary) == "" || len(summary) > compactionGuardMaxInput {
		state.inlineNotice = compactionNoSummaryMessage
		return false
	}
	evidence := false
	newEvidence := false
	inFence := false
	previous := ""
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			previous = trimmed
			continue
		}
		if inFence || len(line) > compactionGuardMaxClaim || patterns.summaryDisavowal.MatchString(line) || patterns.summaryDisavowal.MatchString(previous) {
			previous = trimmed
			continue
		}
		if patterns.summaryApproval.MatchString(line) && patterns.noAsk.MatchString(line) {
			if command, ok := compactionCommandInText(line); ok {
				digest := sha256.Sum256([]byte(command))
				if candidate := state.candidates[digest]; candidate != nil && candidate.active {
					if _, approved := state.approved[digest]; !approved {
						evidence = true
						if !candidate.summaryAlerted {
							candidate.summaryAlerted = true
							newEvidence = true
						}
					}
				}
			}
		}
		if location := patterns.summaryInstruction.FindStringIndex(line); location != nil {
			claim := strings.TrimSpace(line[location[1]:])
			digest := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(claim), " "))))
			for _, candidate := range state.instructions {
				if candidate.warned && candidate.summaryDigest == digest {
					evidence = true
					if !candidate.summaryAlerted {
						candidate.summaryAlerted = true
						newEvidence = true
					}
					break
				}
			}
		}
		previous = trimmed
	}
	if evidence {
		state.inlineNotice = compactionWarningMessage
	} else {
		state.inlineNotice = compactionNoEvidenceMessage
	}
	return newEvidence
}

type compactionGuardActivation struct {
	actionActive    bool
	actionWarn      bool
	instructionWarn bool
	completed       bool
}

// postCompact activates pending candidates without treating a generated
// summary as a complete or authoritative account of the resumed context.
// Only an exact forged-approval candidate can affect a later tool call.
func (s *compactionGuardStore) postCompact(connector, sessionID string) compactionGuardActivation {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return compactionGuardActivation{}
	}
	patterns, epoch := compactionPatternsForConnector(connector)
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now(), patterns, epoch)
	if state == nil {
		return compactionGuardActivation{}
	}
	result := compactionGuardActivation{completed: state.compactDue}
	state.compactDue = false
	for _, candidate := range state.candidates {
		if candidate.pending && !candidate.warned {
			result.actionWarn = true
			candidate.warned = true
		}
		candidate.active = candidate.active || candidate.pending
		candidate.pending = false
		if candidate.active {
			result.actionActive = true
		}
	}
	for _, candidate := range state.instructions {
		if candidate.pending && !candidate.warned {
			result.instructionWarn = true
			candidate.warned = true
		}
		candidate.pending = false
	}
	return result
}

func instructionPoisoningClaim(output string) (string, bool) {
	return instructionPoisoningClaimWithPatterns(output, defaultCompactionPatterns())
}

func instructionPoisoningClaimWithPatterns(output string, patterns *compiledCompactionPatterns) (string, bool) {
	if patterns == nil || !patterns.enabled || len(output) == 0 || len(output) > compactionGuardMaxInput {
		return "", false
	}
	output = strings.ReplaceAll(output, "\r\n", "\n")
	for _, marker := range patterns.roleHeader.FindAllStringIndex(output, compactionGuardMaxMarkers) {
		end := min(len(output), marker[1]+compactionGuardMaxClaim)
		claim := output[marker[1]:end]
		// Goose serializes an ordinary tool response under a user role as
		// `[user]: tool_response: ...`. That wrapper is not a forged new
		// user turn and would otherwise produce an avoidable false alert.
		if strings.Contains(output[marker[0]:marker[1]], "[user]:") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(claim)), "tool_response:") {
			continue
		}
		if next := patterns.nextRole.FindStringIndex(claim); next != nil {
			claim = claim[:next[0]]
		}
		if patterns.avoidance.MatchString(claim) || patterns.exfiltration.MatchString(claim) ||
			patterns.falseFact.MatchString(claim) || patterns.newTask.MatchString(claim) ||
			patterns.override.MatchString(claim) ||
			(patterns.memory.MatchString(claim) && patterns.memoryVerb.MatchString(claim)) ||
			(patterns.approval.MatchString(claim) && patterns.noAsk.MatchString(claim)) {
			return claim, true
		}
	}
	return "", false
}

func compactionPoisonFinding(verdict *ToolInspectVerdict, phase string) {
	if verdict == nil {
		return
	}
	severity := "INFO"
	if phase == "post_compact_warning" {
		severity = "HIGH"
	}
	verdict.Findings = append(verdict.Findings, compactionPoisonRuleID)
	verdict.DetailedFindings = append(verdict.DetailedFindings, RuleFinding{
		RuleID:     compactionPoisonRuleID,
		Title:      "Possible forged user-role claim before compaction",
		Severity:   severity,
		Confidence: 0.9,
		Evidence:   phase,
		Tags:       []string{"compaction", "untrusted_tool_result", "forged_authority"},
	})
	if verdict.Severity == "" || verdict.Severity == "NONE" || (severity == "HIGH" && verdict.Severity == "INFO") {
		verdict.Severity = severity
	}
}

func (s *compactionGuardStore) matchingAction(connector, sessionID, toolName string, toolInput map[string]interface{}) bool {
	key := compactionGuardKey(connector, sessionID)
	patterns, epoch := compactionPatternsForConnector(connector)
	command, ok := compactionCommandFromTool(toolName, toolInput)
	if key == "" || patterns == nil || !patterns.enabled || !ok {
		return false
	}
	digest := sha256.Sum256([]byte(command))
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now(), patterns, epoch)
	if state == nil {
		return false
	}
	if _, approved := state.approved[digest]; approved {
		return false
	}
	candidate := state.candidates[digest]
	return candidate != nil && candidate.active
}

func forgedApprovalCommand(output string) (string, bool) {
	return forgedApprovalCommandWithPatterns(output, defaultCompactionPatterns())
}

func forgedApprovalCommandWithPatterns(output string, patterns *compiledCompactionPatterns) (string, bool) {
	if patterns == nil || !patterns.enabled || len(output) == 0 || len(output) > compactionGuardMaxInput {
		return "", false
	}
	// The action lane uses the canonical embedded role boundaries. Operators
	// may tune warning signatures, but a broad custom regex must not expand
	// which untrusted text can arm a later tool-call guard.
	proofPatterns := defaultCompactionPatterns()
	output = strings.ReplaceAll(output, "\r\n", "\n")
	markers := proofPatterns.roleHeader.FindAllStringIndex(output, compactionGuardMaxMarkers)
	for _, marker := range markers {
		end := marker[1] + compactionGuardMaxClaim
		if end > len(output) {
			end = len(output)
		}
		claim := output[marker[1]:end]
		if strings.Contains(output[marker[0]:marker[1]], "[user]:") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(claim)), "tool_response:") {
			continue
		}
		if next := proofPatterns.nextRole.FindStringIndex(claim); next != nil {
			claim = claim[:next[0]]
		}
		if !proofPatterns.approval.MatchString(claim) || !proofPatterns.noAsk.MatchString(claim) {
			continue
		}
		if command, ok := compactionCommandInText(claim); ok {
			return command, true
		}
	}
	return "", false
}

func compactionCommandInText(text string) (string, bool) {
	match := defaultCompactionPatterns().curlPipe.FindString(text)
	if match == "" {
		return "", false
	}
	return strings.Join(strings.Fields(match), " "), true
}

func explicitUserApprovalCommand(prompt string) (string, bool) {
	if len(prompt) == 0 || len(prompt) > compactionGuardMaxClaim {
		return "", false
	}
	trimmed := strings.TrimSpace(prompt)
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"i approve running ", "i approve ", "yes, run ", "yes run ", "please run ", "run "} {
		if strings.HasPrefix(lower, prefix) {
			command := strings.TrimSpace(trimmed[len(prefix):])
			command = strings.TrimSuffix(command, ".")
			command = strings.Trim(command, "`")
			return compactionExactCommand(command)
		}
	}
	return "", false
}

func compactionCommandFromTool(toolName string, input map[string]interface{}) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "bash", "shell", "exec_command", "run_command":
	default:
		return "", false
	}
	for _, key := range []string{"command", "cmd", "CommandLine"} {
		if value, ok := input[key].(string); ok {
			return compactionExactCommand(value)
		}
	}
	return "", false
}

func compactionExactCommand(command string) (string, bool) {
	command = strings.TrimSpace(command)
	if len(command) == 0 || len(command) > compactionGuardMaxClaim {
		return "", false
	}
	match, ok := compactionCommandInText(command)
	if !ok || match != strings.Join(strings.Fields(command), " ") {
		return "", false
	}
	return match, true
}

func compactionGuardFinding(verdict *ToolInspectVerdict, phase, action string) {
	if verdict == nil {
		return
	}
	severity := "INFO"
	if action != "" {
		severity = "CRITICAL"
	}
	verdict.Findings = append(verdict.Findings, compactionGuardRuleID)
	verdict.DetailedFindings = append(verdict.DetailedFindings, RuleFinding{
		RuleID:     compactionGuardRuleID,
		Title:      "Forged approval across compaction",
		Severity:   severity,
		Confidence: 1,
		Evidence:   phase,
		Tags:       []string{"compaction", "untrusted_tool_result", "forged_authority"},
	})
	if action == "" {
		if verdict.Severity == "" || verdict.Severity == "NONE" {
			verdict.Severity = severity
		}
		return
	}
	if normalizedGuardrailActionRank(action) > normalizedGuardrailActionRank(verdict.Action) {
		verdict.Action = action
		verdict.Reason = "The approval for this exact command appeared in untrusted tool output before compaction. Ask the user to approve it explicitly."
	}
	verdict.Severity = "CRITICAL"
	verdict.Confidence = 1
}
