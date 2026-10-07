// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/sensor"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// A kernel denial is invisible to the agent: the tool sees only EPERM
// ("Operation not permitted"), whether a DefenseClaw kernel control or the
// organization's own Tetragon policy refused the open. So, on a managed
// host, the post-tool hook answer of the agent's session says what was
// blocked, under whose policy, not to retry it, and whom to ask: the same
// pattern as the sandbox egress refusals (sandbox_egress_refusals.go). Only
// denials (never a would-block) of the session's own tool calls, or of its
// agent, are told, each once, at most kernelNoticeMax per answer; a block
// or ask answer keeps its own text and the denials wait for the next one.

// postToolContextEvents lists, per connector, the post-tool hook events
// whose answer carries context the model reads: Claude Code's and Codex's
// hookSpecificOutput.additionalContext, Copilot's additionalContext,
// Cursor's additional_context, Devin's hookSpecificOutput.additionalContext.
// The other harnesses' post-tool hooks have no such field (Hermes, Kiro,
// OpenCode, OpenHands, Amp, Antigravity, OmniGent), so their agents are not
// told. Both the sandbox egress notice and the kernel block notice use it.
var postToolContextEvents = map[string][]string{
	"claudecode": {"posttooluse", "posttoolusefailure"},
	"codex":      {"posttooluse"},
	"copilot":    {"posttooluse", "posttoolusefailure"},
	"cursor":     {"posttooluse"},
	"devin":      {"posttooluse"},
}

const (
	// kernelNoticeWindow is how far back a denial is told.
	kernelNoticeWindow = 120 * time.Second
	// kernelNoticeMax is how many denials one answer names; it counts the
	// rest.
	kernelNoticeMax = 3
	// kernelBlocksToldExtra is the audit extra key naming the denials an
	// answer told the agent of (their content-free ids).
	kernelBlocksToldExtra = "kernel_blocks_told"
	// kernelNoticeRemember is how long a told denial is remembered.
	kernelNoticeRemember = 10 * time.Minute
)

// kernelNoticeLedger remembers which denials were told.
type kernelNoticeLedger struct {
	mu   sync.Mutex
	told map[string]time.Time
}

func newKernelNoticeLedger() *kernelNoticeLedger {
	return &kernelNoticeLedger{told: map[string]time.Time{}}
}

// defaultKernelNotices is the gateway process's ledger.
var defaultKernelNotices = newKernelNoticeLedger()

// take returns the blocks not told yet and marks them told.
func (ledger *kernelNoticeLedger) take(blocks []sensor.KernelBlock, now time.Time) []sensor.KernelBlock {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	for id, at := range ledger.told {
		if now.Sub(at) > kernelNoticeRemember {
			delete(ledger.told, id)
		}
	}
	var out []sensor.KernelBlock
	for _, block := range blocks {
		if _, told := ledger.told[block.ID]; told || block.ID == "" {
			continue
		}
		ledger.told[block.ID] = now
		out = append(out, block)
	}
	return out
}

// kernelBlocksSource is the part of the runtime planes the notice reads.
type kernelBlocksSource interface {
	KernelBlocks(since time.Time) []sensor.KernelBlock
	SessionRootOf(pid int) (int, bool)
}

// safeAddKernelBlockNotice is addKernelBlockNotice with a recover: a panic
// keeps the answer as it was.
func (a *APIServer) safeAddKernelBlockNotice(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
) (out agentHookResponse) {
	defer func() {
		if r := recover(); r != nil {
			out = resp
			a.handleHookPanic(ctx, connectorName, req.HookEventName, fmt.Sprintf("kernel block notice panic: %v", r))
		}
	}()
	peer, ok := managedHookRequestPeer(ctx)
	if !ok || peer.PID <= 0 || sandboxHookForConnector(ctx, connectorName) {
		// OSS and unmanaged hosts, and sandbox hooks: nothing to tell.
		return resp
	}
	service, release := a.leaseAIRuntime()
	defer release()
	if service == nil {
		return resp
	}
	return addKernelBlockNotice(ctx, profile, connName(connectorName), req, rawBody, payload, resp, service, peer.PID,
		defaultKernelNotices, time.Now())
}

// addKernelBlockNotice adds the session's untold kernel denials to a
// post-tool hook answer and re-renders the harness output around it.
func addKernelBlockNotice(
	ctx context.Context,
	profile connector.HookProfile,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	resp agentHookResponse,
	source kernelBlocksSource,
	peerPID int,
	ledger *kernelNoticeLedger,
	now time.Time,
) agentHookResponse {
	if !slices.Contains(postToolContextEvents[connectorName], canonicalEvent(req.HookEventName)) {
		return resp
	}
	switch strings.ToLower(strings.TrimSpace(resp.Action)) {
	case "block", "confirm":
		// Their own text stands; the denials wait for the next answer.
		return resp
	}
	root, rootKnown := source.SessionRootOf(peerPID)
	var mine []sensor.KernelBlock
	for _, block := range source.KernelBlocks(now.Add(-kernelNoticeWindow)) {
		sameSession := block.SessionID != "" && block.SessionID == req.SessionID
		sameAgent := rootKnown && (block.SessionRootPID == root || block.RootPID == root)
		if sameSession || sameAgent {
			mine = append(mine, block)
		}
	}
	told := ledger.take(mine, now)
	if len(told) == 0 {
		return resp
	}
	notice := kernelBlockNoticeText(told, req.ToolInvocationID)
	if resp.AdditionalContext != "" {
		notice = resp.AdditionalContext + "\n\n" + notice
	}
	resp.AdditionalContext = notice
	resp.HookOutput = sandboxHookOutput(ctx, profile, req, rawBody, payload, nil, resp)
	for _, block := range told {
		resp.KernelBlocksTold = append(resp.KernelBlocksTold, block.ID)
	}
	return resp
}

// kernelBlockNoticeText is the agent's note: one sentence per denial, at
// most kernelNoticeMax, and a count of the rest.
func kernelBlockNoticeText(blocks []sensor.KernelBlock, toolInvocationID string) string {
	shown := blocks[:min(len(blocks), kernelNoticeMax)]
	lines := make([]string, 0, len(shown)+1)
	for _, block := range shown {
		earlier := block.ToolInvocationID != "" && toolInvocationID != "" && block.ToolInvocationID != toolInvocationID
		lines = append(lines, kernelBlockSentence(block, earlier))
	}
	if more := len(blocks) - len(shown); more > 0 {
		lines = append(lines, fmt.Sprintf("And %d more calls of this agent were blocked the same way.", more))
	}
	return strings.Join(lines, "\n")
}

// kernelBlockSentence says what one denial was, in the shape of the block
// sentences of the hook answers (agentBlockSentence).
func kernelBlockSentence(block sensor.KernelBlock, earlier bool) string {
	process := "a process"
	if name := strings.TrimSpace(block.Process); name != "" {
		process = "`" + name + "`"
	}
	target := homeRelativeTarget(block.Target, block.UID, "")
	var sentence string
	switch {
	case block.Owner == plane.PolicyOwnerCustomer:
		function := firstNonEmpty(block.Function, "a kernel hook")
		sentence = fmt.Sprintf("Your organization's Tetragon policy `%s` blocked %s (%s).", block.Policy, process, function)
	case block.Control == "kernel.ssh_private_key_read":
		sentence = fmt.Sprintf("DefenseClaw blocked %s from reading your SSH private key (%s) under your organization's policy (%s, a kernel control).",
			process, target, firstNonEmpty(block.RuleID, "PATH-SSH-KEY"))
	case block.Control == "kernel.persistence_write":
		sentence = fmt.Sprintf("DefenseClaw blocked %s from changing your shell startup or autostart file (%s) under your organization's policy (%s, a kernel control).",
			process, target, firstNonEmpty(block.RuleID, "persistence.shell_profile_write"))
	default:
		sentence = fmt.Sprintf("DefenseClaw blocked %s from opening %s under your organization's policy (a kernel control).", process, target)
	}
	sentence += ` The tool saw "Operation not permitted". Do not retry it. Contact your administrator if you need it allowed.`
	if earlier {
		// Told at a later post-tool hook than the call it happened in.
		if rest, ok := strings.CutPrefix(sentence, "Your "); ok {
			sentence = "your " + rest
		}
		sentence = "In an earlier tool call, " + sentence
	}
	return sentence
}
