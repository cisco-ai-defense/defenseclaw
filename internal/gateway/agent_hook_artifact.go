// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

const (
	promotedArtifactMaxBytes   = 64 << 10
	promotedArtifactReadLimit  = 500 * time.Millisecond
	promotedArtifactHookBudget = 750 * time.Millisecond
	promotedArtifactMaxReaders = 4
)

var promotedArtifactReadSlots = make(chan struct{}, promotedArtifactMaxReaders)

// safeApplyExperimentalArtifactPromotion inspects an exact script only when a
// synchronous tool proposal is about to execute, source, or load it. It does
// not scan every file write and does not trust write-time fragments: the
// current bytes are reopened and parsed at the execution boundary. This is a
// best-effort gate; the upstream agent still executes the pathname after the
// hook returns rather than an immutable DefenseClaw-owned snapshot.
func (a *APIServer) safeApplyExperimentalArtifactPromotion(
	ctx context.Context,
	profile connector.HookProfile,
	req agentHookRequest,
	original agentHookResponse,
	latency time.Duration,
) (resp agentHookResponse) {
	resp = original
	defer func() {
		if recovered := recover(); recovered != nil {
			a.handleHookPanic(
				ctx,
				req.ConnectorName,
				req.HookEventName,
				"experimental artifact promotion",
			)
			resp = original
		}
	}()
	if a == nil || ManagedEnterpriseActive() || req.toolChain == nil ||
		original.Action == guardrailActionBlock ||
		original.RawAction == guardrailActionBlock ||
		!req.toolChain.recorded ||
		!profile.ExperimentalToolLifecycleEligible() ||
		profile.ToolCallLifecycle.RouteForEvent(req.HookEventName) !=
			connector.ToolEventRouteStructuredAction {
		return resp
	}
	caps := profile.Capabilities
	preExecutionBoundary := caps.CanBlock && eventIn(req.HookEventName, caps.BlockEvents)
	artifactCtx, cancel := context.WithTimeout(ctx, promotedArtifactHookBudget)
	defer cancel()
	findings := promotedArtifactFindings(
		artifactCtx,
		req,
		req.toolChain.facts,
		preExecutionBoundary,
		func(observation trustedActionTelemetry) {
			a.recordParserUncertaintyMetricV8(
				artifactCtx,
				req.ConnectorName,
				observation.ParserUncertaintyCount,
			)
		},
	)
	if len(findings) == 0 {
		return resp
	}
	intent := guardrailActionAllow
	if enforceable := enforceableRuleFindings(findings); len(enforceable) > 0 {
		intent = guardrailRuntimeActionForConnector(
			a.scannerCfg,
			req.ConnectorName,
			HighestSeverity(enforceable),
			true,
		)
	}
	resp = mergeAgentHookFindings(profile, req, resp, findings, intent)
	if !req.SuppressCorrelationEmit {
		eval := a.emitHookRuleFindings(
			ctx,
			req.ConnectorName,
			req.HookEventName,
			&ToolInspectVerdict{
				Action:           resp.Action,
				Severity:         HighestSeverity(findings),
				Findings:         FindingStrings(findings),
				DetailedFindings: findings,
			},
			"artifact_execution",
			latency,
		)
		if resp.EvaluationID == "" {
			resp.EvaluationID = eval.EvaluationID
		}
		resp.RuleIDs = mergeBoundedRuleIDs(8, eval.RuleIDs, resp.RuleIDs)
	}
	return resp
}

func promotedArtifactFindings(
	ctx context.Context,
	req agentHookRequest,
	facts actionfacts.Facts,
	preExecutionBoundary bool,
	recordTelemetry func(trustedActionTelemetry),
) []RuleFinding {
	candidates := promotedArtifactCandidates(facts)
	if len(candidates) == 0 {
		return nil
	}
	var findings []RuleFinding
	seenRules := make(map[string]struct{})
	for _, candidate := range candidates {
		body, dialect, ok := readPromotedArtifactBounded(
			ctx,
			candidate.path,
			candidate.dialect,
		)
		if !ok {
			continue
		}
		analysisBody := promotedArtifactAnalysisBody(body)
		input := actionfacts.Input{
			Tool:        "shell",
			Command:     string(analysisBody),
			CWD:         facts.CWD,
			ActiveHome:  trustedSameHostHome(),
			DialectHint: dialect,
		}
		artifactFacts := actionfacts.Analyze(input)
		outerCandidateEnforceable := preExecutionBoundary &&
			promotedArtifactCandidateEnforcementEligible(facts, candidate)
		enforcementCapable := outerCandidateEnforceable &&
			artifactFacts.Authoritative() &&
			artifactFacts.EnforcementEligible() &&
			promotedArtifactSequentialReachabilityEligible(artifactFacts)
		matched := dispatchTrustedAction(ctx, trustedActionRequest{
			Input:              input,
			LegacyText:         string(body),
			Connector:          req.ConnectorName,
			EnforcementCapable: enforcementCapable,
			recordTelemetry:    recordTelemetry,
		})
		if req.toolChain != nil {
			req.toolChain.recordArtifactTrustedAction(
				artifactFacts,
				matched,
				enforcementCapable,
			)
		}
		for _, finding := range matched {
			if _, duplicate := seenRules[finding.RuleID]; duplicate {
				continue
			}
			seenRules[finding.RuleID] = struct{}{}
			finding.Tags = appendUniqueStrings(finding.Tags, "artifact-promotion", "experimental")
			findings = append(findings, finding)
		}
	}
	return findings
}

// promotedArtifactSequentialReachabilityEligible masks a narrow POSIX case
// the structural parser deliberately does not model: a successful top-level
// exec replaces the shell, so later sibling commands are not unconditionally
// reachable. Detection remains available, but blocking waits for proof.
func promotedArtifactSequentialReachabilityEligible(facts actionfacts.Facts) bool {
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.PipelineID != 0 ||
			command.Dialect != actionfacts.DialectPOSIX ||
			!strings.EqualFold(command.Program, "exec") {
			continue
		}
		for _, later := range facts.Commands {
			if later.ParentCommandID == 0 && later.PipelineID == 0 &&
				later.ID > command.ID {
				return false
			}
		}
	}
	return true
}

func promotedArtifactAnalysisBody(body []byte) []byte {
	// The interpreter consumes the shebang; it is not part of the command
	// program. Removing only that first line keeps the parsed execution facts
	// authoritative for an otherwise static script while preserving the exact
	// final bytes as the regex fallback input.
	if !strings.HasPrefix(string(body), "#!") {
		return body
	}
	if newline := strings.IndexByte(string(body), '\n'); newline >= 0 {
		return body[newline+1:]
	}
	return nil
}

type promotedArtifactCandidate struct {
	commandID int64
	path      string
	dialect   actionfacts.Dialect
}

func promotedArtifactCandidates(facts actionfacts.Facts) []promotedArtifactCandidate {
	commands := make(map[int64]actionfacts.CommandFact, len(facts.Commands))
	for _, command := range facts.Commands {
		commands[command.ID] = command
	}
	seen := make(map[string]struct{})
	result := make([]promotedArtifactCandidate, 0, 2)
	for _, path := range facts.Paths {
		command, ok := commands[path.CommandID]
		if !ok || command.Effect != actionfacts.EffectExecute {
			continue
		}
		dialect, eligible := promotedArtifactDialect(command, path)
		if !eligible {
			continue
		}
		resolved := strings.TrimSpace(path.Resolved)
		if resolved == "" && path.Absolute {
			resolved = strings.TrimSpace(path.Normalized)
		}
		if resolved == "" || !filepath.IsAbs(resolved) {
			continue
		}
		resolved = filepath.Clean(resolved)
		if !promotedArtifactPathIsLocal(resolved) {
			continue
		}
		candidate := promotedArtifactCandidate{
			commandID: command.ID,
			path:      resolved,
			dialect:   dialect,
		}
		key := promotedArtifactCandidateKey(candidate)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
		if len(result) == 4 {
			break
		}
	}
	return result
}

func promotedArtifactCandidateEnforcementEligible(
	facts actionfacts.Facts,
	candidate promotedArtifactCandidate,
) bool {
	projected := facts.EnforcementProjection()
	if projected.EnforcementEligible() {
		for _, executing := range promotedArtifactCandidates(projected) {
			if promotedArtifactCandidateKey(executing) ==
				promotedArtifactCandidateKey(candidate) {
				return true
			}
		}
	}

	// Artifact promotion may replace exactly one uncertainty: the bytes of a
	// single, statically named top-level script. Any additional uncertainty
	// (control flow, expansion, redirection, wrapper, or operand ambiguity)
	// keeps the match detection-only.
	if facts.Parse.Status != actionfacts.StatusPartial ||
		len(facts.Parse.Issues) != 1 ||
		facts.Parse.Issues[0] != actionfacts.IssueOpaqueArtifact ||
		len(facts.Commands) != 1 || len(facts.Paths) != 1 {
		return false
	}
	command := facts.Commands[0]
	path := facts.Paths[0]
	if command.ID != candidate.commandID || path.CommandID != command.ID ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.Kind != actionfacts.CommandKindProcess ||
		command.Effect != actionfacts.EffectExecute || !command.ArgvComplete ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Expands {
			return false
		}
	}
	return path.Access == actionfacts.PathAccessExecute ||
		path.Access == actionfacts.PathAccessRead
}

func promotedArtifactCandidateKey(candidate promotedArtifactCandidate) string {
	key := strings.ToLower(string(candidate.dialect)) + "\x00" + candidate.path
	if runtime.GOOS == "windows" {
		key = strings.ToLower(key)
	}
	return key
}

func promotedArtifactPathIsLocal(path string) bool {
	if runtime.GOOS != "windows" {
		return true
	}
	volume := filepath.VolumeName(path)
	return !strings.HasPrefix(volume, `\\`) && !strings.HasPrefix(path, `\\`)
}

func promotedArtifactDialect(
	command actionfacts.CommandFact,
	path actionfacts.PathFact,
) (actionfacts.Dialect, bool) {
	program := strings.ToLower(strings.TrimSpace(command.Program))
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh":
		return actionfacts.DialectPOSIX, path.Access == actionfacts.PathAccessExecute
	case "source":
		return actionfacts.DialectPOSIX, path.Access == actionfacts.PathAccessRead
	case ".":
		if command.Dialect == actionfacts.DialectPowerShell {
			return actionfacts.DialectPowerShell, path.Access == actionfacts.PathAccessRead
		}
		return actionfacts.DialectPOSIX, path.Access == actionfacts.PathAccessRead
	case "pwsh", "pwsh.exe", "powershell", "powershell.exe":
		return actionfacts.DialectPowerShell,
			path.Access == actionfacts.PathAccessExecute || path.Access == actionfacts.PathAccessRead
	case "cmd", "cmd.exe":
		return actionfacts.DialectCMD, path.Access == actionfacts.PathAccessExecute
	}
	if path.Access != actionfacts.PathAccessExecute {
		return actionfacts.DialectNone, false
	}
	ext := strings.ToLower(filepath.Ext(path.Normalized))
	if command.Dialect == actionfacts.DialectPowerShell {
		switch ext {
		case ".ps1", ".psm1":
			return actionfacts.DialectPowerShell, true
		}
	}
	if command.Dialect == actionfacts.DialectCMD {
		switch ext {
		case ".cmd", ".bat":
			return actionfacts.DialectCMD, true
		}
	}
	// A direct path needs an executable shebang. A suffix alone does not prove
	// which interpreter (if any) the host will use; explicit interpreter
	// invocations were handled above.
	return actionfacts.DialectNone, true
}

type promotedArtifactReadResult struct {
	body    []byte
	dialect actionfacts.Dialect
	ok      bool
}

func readPromotedArtifactBounded(
	ctx context.Context,
	path string,
	dialect actionfacts.Dialect,
) ([]byte, actionfacts.Dialect, bool) {
	select {
	case promotedArtifactReadSlots <- struct{}{}:
	case <-ctx.Done():
		return nil, actionfacts.DialectNone, false
	default:
		return nil, actionfacts.DialectNone, false
	}
	result := make(chan promotedArtifactReadResult, 1)
	go func() {
		defer func() { <-promotedArtifactReadSlots }()
		body, resolvedDialect, ok := readPromotedArtifact(path, dialect)
		result <- promotedArtifactReadResult{
			body: body, dialect: resolvedDialect, ok: ok,
		}
	}()
	timer := time.NewTimer(promotedArtifactReadLimit)
	defer timer.Stop()
	select {
	case read := <-result:
		return read.body, read.dialect, read.ok
	case <-ctx.Done():
		return nil, actionfacts.DialectNone, false
	case <-timer.C:
		return nil, actionfacts.DialectNone, false
	}
}

func readPromotedArtifact(
	path string,
	dialectHint actionfacts.Dialect,
) ([]byte, actionfacts.Dialect, bool) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 ||
		before.Size() <= 0 || before.Size() > promotedArtifactMaxBytes {
		return nil, actionfacts.DialectNone, false
	}
	if dialectHint == actionfacts.DialectNone && runtime.GOOS != "windows" &&
		before.Mode().Perm()&0o111 == 0 {
		// A direct POSIX path without any execute bit cannot reach its shebang.
		// Explicit interpreter/source calls carry a dialect hint and remain
		// readable even when the script itself is not executable.
		return nil, actionfacts.DialectNone, false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, actionfacts.DialectNone, false
	}
	resolvedInfo, err := os.Stat(resolved)
	if err != nil || !os.SameFile(before, resolvedInfo) {
		return nil, actionfacts.DialectNone, false
	}
	file, err := os.Open(path) // #nosec G304 -- exact hook-derived path, checked above and below.
	if err != nil {
		return nil, actionfacts.DialectNone, false
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !samePromotedArtifactVersion(before, opened) {
		return nil, actionfacts.DialectNone, false
	}
	body, err := io.ReadAll(io.LimitReader(file, promotedArtifactMaxBytes+1))
	if err != nil || len(body) == 0 || len(body) > promotedArtifactMaxBytes {
		return nil, actionfacts.DialectNone, false
	}
	afterRead, err := file.Stat()
	if err != nil || !samePromotedArtifactVersion(opened, afterRead) {
		return nil, actionfacts.DialectNone, false
	}
	dialect := dialectHint
	if dialect == actionfacts.DialectNone {
		dialect = promotedArtifactShebangDialect(body)
	}
	if dialect == actionfacts.DialectNone {
		return nil, actionfacts.DialectNone, false
	}
	return body, dialect, true
}

func samePromotedArtifactVersion(left, right os.FileInfo) bool {
	return left != nil && right != nil && right.Mode().IsRegular() &&
		os.SameFile(left, right) && left.Size() == right.Size() &&
		left.ModTime().Equal(right.ModTime())
}

func promotedArtifactShebangDialect(body []byte) actionfacts.Dialect {
	line := string(body)
	if newline := strings.IndexByte(line, '\n'); newline >= 0 {
		line = line[:newline]
	}
	if !strings.HasPrefix(line, "#!") || len(line) > 256 ||
		strings.ContainsRune(line, '\r') {
		return actionfacts.DialectNone
	}
	fields := strings.Fields(strings.TrimSpace(line[2:]))
	if len(fields) == 2 && fields[0] == "/usr/bin/env" {
		return promotedArtifactInterpreterDialect(fields[1])
	}
	if len(fields) != 1 || !strings.HasPrefix(fields[0], "/") {
		return actionfacts.DialectNone
	}
	interpreter := fields[0]
	if slash := strings.LastIndexByte(interpreter, '/'); slash >= 0 {
		interpreter = interpreter[slash+1:]
	}
	return promotedArtifactInterpreterDialect(interpreter)
}

func promotedArtifactInterpreterDialect(interpreter string) actionfacts.Dialect {
	switch strings.ToLower(interpreter) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return actionfacts.DialectPowerShell
	case "sh", "bash", "zsh", "dash", "ksh", "mksh":
		return actionfacts.DialectPOSIX
	default:
		return actionfacts.DialectNone
	}
}
