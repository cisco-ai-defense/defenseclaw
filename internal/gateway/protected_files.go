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
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/protectedfiles"
)

// protectedFileRuleID names the protected-file watch's finding in the audit
// row's details, beside the kernel control's persistence rule ids.
const protectedFileRuleID = "persistence.protected_file_changed"

// protectedFileWatch is the gateway's protected-file watch (#1172): the
// hook handler records which agent tool calls run for which home, and the
// watch reports a change to a protected file made while one ran.
type protectedFileWatch struct {
	activity *protectedfiles.Activity
	watcher  *protectedfiles.Watcher
}

// newProtectedFileWatch builds the watch for cfg, or nil when
// guardrail.protected_files.on_change is off. A per-user gateway watches
// its own user's home; a managed gateway, which runs as a service account,
// adds each user's home at that user's first hook call.
func newProtectedFileWatch(cfg *config.Config, managed bool, emit func(protectedfiles.Change)) *protectedFileWatch {
	if cfg == nil {
		return nil
	}
	mode := cfg.Guardrail.ProtectedFiles.EffectiveOnChange()
	if mode == config.ProtectedFilesOff {
		return nil
	}
	stateDir := ""
	if cfg.DataDir != "" {
		stateDir = filepath.Join(cfg.DataDir, "protected-files")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			stateDir = ""
		}
	}
	var system []string
	if managed && runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			system = append(system, filepath.Join(programData, "ssh", "administrators_authorized_keys"))
		}
	}
	activity := protectedfiles.NewActivity(nil)
	watch := &protectedFileWatch{
		activity: activity,
		watcher: protectedfiles.New(protectedfiles.Options{
			Restore:  mode == config.ProtectedFilesRestore,
			Paths:    cfg.Guardrail.ProtectedFiles.Paths,
			System:   system,
			StateDir: stateDir,
			Activity: activity,
			Emit:     emit,
		}),
	}
	if !managed {
		if home := trustedSameHostHome(); home != "" {
			watch.watcher.AddHome(home)
		}
	}
	return watch
}

// startProtectedFileWatch starts the watch for the sidecar's config. It
// runs until ctx ends.
func (s *Sidecar) startProtectedFileWatch(ctx context.Context) {
	watch := newProtectedFileWatch(s.currentConfig(), ManagedEnterpriseActive(), s.emitProtectedFileChange)
	if watch == nil {
		return
	}
	// Set before the API worker starts; setAPIServer hands it to each API
	// server it publishes.
	s.apiMu.Lock()
	s.protectedFiles = watch
	s.apiMu.Unlock()
	go watch.watcher.Run(ctx)
}

// emitProtectedFileChange writes the audit row of an agent's change to a
// protected file: HIGH, naming the file, the digests (never the content)
// and the agent session. A change no agent tool call explains is the
// user's own and is accepted without a row.
func (s *Sidecar) emitProtectedFileChange(change protectedfiles.Change) {
	if !change.Attributed {
		return
	}
	logger := s.logger
	if logger == nil {
		return
	}
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		Connector: change.Session.Connector, SessionID: change.Session.SessionID, ToolID: change.Session.ToolInvocationID,
	})
	_ = logger.LogActionCtxSeverity(ctx, string(audit.ActionProtectedFileChanged), change.Path,
		protectedFileChangeDetails(change), "HIGH")
}

func protectedFileChangeDetails(change protectedfiles.Change) string {
	parts := []string{
		"rule=" + protectedFileRuleID,
		"class=" + change.Class,
		"before=" + change.Before,
		"after=" + change.After,
	}
	if change.Session.Connector != "" {
		parts = append(parts, "connector="+change.Session.Connector)
	}
	if change.Session.SessionID != "" {
		parts = append(parts, "session="+change.Session.SessionID)
	}
	if change.Session.ToolInvocationID != "" {
		parts = append(parts, "tool_invocation="+change.Session.ToolInvocationID)
	}
	if change.Session.AgentIdentityID != "" {
		parts = append(parts, "agent_identity="+change.Session.AgentIdentityID)
	}
	switch {
	case change.Restored:
		parts = append(parts, "restored=true")
	case change.RestoreError != "":
		parts = append(parts, "restored=false", fmt.Sprintf("restore_error=%q", change.RestoreError))
	}
	return strings.Join(parts, " ")
}

// noteProtectedFileActivity records a hook event for the watch: a tool
// call starts at its tool_call event and ends at its result (or the
// session's stop). Sandbox traffic is left out: a sandbox does not write
// the host user's home.
func (a *APIServer) noteProtectedFileActivity(ctx context.Context, connectorName string, req agentHookRequest, agentIdentityID string) {
	watch := a.protectedFiles
	if watch == nil || isSandboxHookRequest(ctx) {
		return
	}
	home := trustedActiveHome(ctx)
	if home == "" || home == unresolvedCallerHome {
		return
	}
	watch.watcher.AddHome(home)
	session := protectedfiles.Session{
		Connector: connectorName, SessionID: req.SessionID, ToolInvocationID: req.ToolInvocationID,
		AgentIdentityID: agentIdentityID,
	}
	switch normalizeHookEventLabel(req.HookEventName) {
	case "tool_call":
		watch.activity.Begin(home, session)
	case "tool_result":
		watch.activity.End(home, session)
	case "stop":
		session.ToolInvocationID = ""
		watch.activity.End(home, session)
	}
}
