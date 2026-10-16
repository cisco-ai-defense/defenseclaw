// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// guardianRestoresFile is the standalone guardian's record of when it last
// put back each target's hooks after they no longer verified
// (hookGuardianRestoresFile in internal/cli).
const guardianRestoresFile = "hook_guardian_restores.json"

// agentConnectors names the connector of each agent CLI agentCLIOf reports.
var agentConnectors = map[string]string{
	"claude": "claudecode", "codex": "codex", "cursor-agent": "cursor", "copilot": "copilot", "opencode": "opencode",
	"amp": "amp", "devin": "devin", "hermes": "hermes", "openhands": "openhands", "omnigent": "omnigent",
	"agy": "antigravity", "kiro-cli": "kiro",
}

type guardianRestoreKey struct {
	uid       int
	connector string
}

// guardianRestores returns when the guardian last put back each account's
// hooks of a connector, or nil.
func (e *Env) guardianRestores() map[guardianRestoreKey]time.Time {
	data, err := readBounded(e.P(filepath.Join(e.Layout.DataDir, guardianRestoresFile)), 1<<20)
	if err != nil {
		return nil
	}
	var record struct {
		Version int `json:"version"`
		Targets []struct {
			UID        *int   `json:"uid"`
			Connector  string `json:"connector"`
			RestoredAt string `json:"restored_at"`
		} `json:"targets"`
	}
	if json.Unmarshal(data, &record) != nil || record.Version != 1 {
		return nil
	}
	restores := map[guardianRestoreKey]time.Time{}
	for _, target := range record.Targets {
		at, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(target.RestoredAt))
		if err != nil || target.UID == nil || *target.UID <= 0 {
			continue
		}
		restores[guardianRestoreKey{*target.UID, strings.ToLower(strings.TrimSpace(target.Connector))}] = at
	}
	return restores
}

// describeAgentSessionsBeforeGuardianRestore names, per account, the agent
// sessions that started before the guardian put back that account's hooks
// of their connector after a user changed or removed them (the hooks block
// of a Hermes config emptied, for example): an agent keeps the hooks it
// loaded, so a session started while they were missing runs without
// DefenseClaw, and security_complete is false until it restarts
// (GAP-0499). Sessions older than the activation are named by the
// activation warning already. The connectors whose hooks are vendor machine
// policy, and Codex (it reads the managed requirements per turn), need no
// restart after a per-user restore.
func (l *lifecycle) describeAgentSessionsBeforeGuardianRestore(ctx context.Context, record *Deployment, activated time.Time) {
	restores := l.env.guardianRestores()
	if len(restores) == 0 {
		return
	}
	latest := time.Time{}
	for _, at := range restores {
		if at.After(latest) {
			latest = at
		}
	}
	machine := map[string]bool{}
	for _, name := range record.MachinePolicyConnectors {
		machine[strings.ToLower(name)] = true
	}
	type group struct {
		connector string
		at        time.Time
	}
	held := map[group][]agentSession{}
	for _, session := range l.env.agentSessionsStartedBefore(ctx, latest, record.ServiceUID) {
		connector := agentConnectors[session.Agent]
		if connector == "" || agentsReadingHooksLive[session.Agent] || machine[connector] || session.Started.Before(activated) {
			continue
		}
		at, ok := restores[guardianRestoreKey{session.UID, connector}]
		if !ok || !session.Started.Before(at) {
			continue
		}
		held[group{connector, at}] = append(held[group{connector, at}], session)
	}
	if len(held) == 0 {
		return
	}
	groups := make([]group, 0, len(held))
	for g := range held {
		groups = append(groups, g)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].connector != groups[j].connector {
			return groups[i].connector < groups[j].connector
		}
		return groups[i].at.Before(groups[j].at)
	})
	for _, g := range groups {
		l.warnAgentSessions(held[g], func(sessions string) string {
			return fmt.Sprintf("runs %s, started before the hook guardian put back the account's changed or removed %s hooks at %s; an agent keeps the hooks it loaded when it started, so a session started while they were missing runs without DefenseClaw until it is restarted: ask that user to restart these sessions", sessions, g.connector, g.at.UTC().Format(time.RFC3339))
		})
	}
	l.result.SecurityComplete = false
}
