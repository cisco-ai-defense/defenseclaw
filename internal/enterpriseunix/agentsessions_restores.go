// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// guardianRestoresFile is the standalone guardian's record of when it last
// put back each target's hooks after they no longer verified.
const guardianRestoresFile = enterprisehooks.GuardianRestoresFile

// guardianRestoreReader reads the record once; tests replace it.
var guardianRestoreReader = enterprisehooks.ReadGuardianRestoreRecord

// agentConnectors names the connector of each agent CLI agentCLIOf reports.
var agentConnectors = map[string]string{
	"claude": "claudecode", "codex": "codex", "cursor-agent": "cursor", "copilot": "copilot", "opencode": "opencode",
	"amp": "amp", "devin": "devin", "hermes": "hermes",
	"agy": "antigravity", "kiro-cli": "kiro",
}

type guardianRestoreKey struct {
	uid       int
	connector string
}

// guardianRestores returns when the guardian last put back each account's
// hooks of a connector; nil without a record. A record that stays
// unreadable after the retries, or whose content is invalid, is an error:
// it may hide a restore, so the caller reports the restart status unknown.
// It returned nil for both, and the restart-required warning vanished while
// status read complete (GAP-0624).
func (e *Env) guardianRestores() (map[guardianRestoreKey]time.Time, error) {
	record, err := enterprisehooks.ReadGuardianRestoreRecordRetrying(
		e.P(filepath.Join(e.Layout.DataDir, guardianRestoresFile)),
		guardianRestoreReader,
		enterprisehooks.GuardianRestoreReadBackoff,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	restores := map[guardianRestoreKey]time.Time{}
	for _, target := range record.Targets {
		at := target.RestoredAtTime()
		if at.IsZero() || target.UID == nil || *target.UID <= 0 {
			continue
		}
		restores[guardianRestoreKey{*target.UID, strings.ToLower(strings.TrimSpace(target.Connector))}] = at
	}
	return restores, nil
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
	machine := map[string]bool{}
	for _, name := range record.MachinePolicyConnectors {
		machine[strings.ToLower(name)] = true
	}
	restores, restoresErr := l.env.guardianRestores()
	if restoresErr != nil {
		l.warnGuardianRestoresUnknown(ctx, record, activated, machine, restoresErr)
		return
	}
	if len(restores) == 0 {
		return
	}
	latest := time.Time{}
	for _, at := range restores {
		if at.After(latest) {
			latest = at
		}
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

// warnGuardianRestoresUnknown names, per account, the agent sessions whose
// restart status is unknown because the guardian's restore record could not
// be read: each of them may have started while that account's hooks were
// missing. Security is not complete until the record reads again or the
// sessions restart, as on Windows.
func (l *lifecycle) warnGuardianRestoresUnknown(ctx context.Context, record *Deployment, activated time.Time, machine map[string]bool, cause error) {
	var unknown []agentSession
	for _, session := range l.env.agentSessionsStartedBefore(ctx, l.env.Now(), record.ServiceUID) {
		connector := agentConnectors[session.Agent]
		if connector == "" || agentsReadingHooksLive[session.Agent] || machine[connector] || session.Started.Before(activated) {
			continue
		}
		unknown = append(unknown, session)
	}
	if len(unknown) == 0 {
		l.result.AddWarning(codeAgentSessionsRestart, fmt.Sprintf("restart status unknown: the hook guardian's restore record could not be read (%v)", cause))
	} else {
		l.warnAgentSessions(unknown, func(sessions string) string {
			return fmt.Sprintf("runs %s; restart status unknown: the hook guardian's restore record could not be read (%v), so DefenseClaw cannot tell whether these sessions started before the guardian put back the account's hooks and run without DefenseClaw: ask that user to restart them", sessions, cause)
		})
	}
	l.result.SecurityComplete = false
}
