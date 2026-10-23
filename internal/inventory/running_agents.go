// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"time"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
)

// AgentProcess is one running agent run of a connector DefenseClaw supports.
type AgentProcess struct {
	PID       int
	Connector string
	// User is DOMAIN\account of the process token, or "" when the process
	// cannot be opened or its token's account name cannot be resolved.
	User string
	// OwnerSID is the SID of the account this process runs as, from the
	// snapshot's SessionOwnerID: the token SID where Remote Desktop Services
	// shows it, else the account signed in to its session. It is empty in
	// session 0 or when the owner is unknown.
	OwnerSID string
	// StartedAt is zero when this account cannot open the process.
	StartedAt time.Time
	// Args are used only by the managed launch coverage scan. They must
	// never be put in a status or audit record.
	Args      []string
	ArgsKnown bool
}

// RunningWindowsAgentProcesses lists the running agent runs of the supported
// connectors on a Windows host, classified as discovery classifies them (a
// helper an agent starts is folded into its run). The managed lifecycle
// names the runs that started before DefenseClaw was activated: an agent
// reads its hooks when it starts, so they run uninspected until restarted
// (GAP-0967). Elsewhere it lists none.
func RunningWindowsAgentProcesses() ([]AgentProcess, error) {
	catalog, err := LoadAISignatures()
	if err != nil {
		return nil, err
	}
	procs, err := processSnapshot()
	if err != nil || len(procs) == 0 || !procs[0].Windows {
		return nil, err
	}
	// The whole catalog classifies, so a basename two products share
	// (Claude Code and Claude Desktop) stays settled by its path.
	classifyWindowsProcesses(procs, catalog)
	supported := map[string]bool{}
	for _, sig := range catalog {
		if normalizeAICategory(sig.Category) == SignalSupportedConnector {
			supported[normalizeAIID(sig.ID)] = true
		}
	}
	var out []AgentProcess
	for _, proc := range procs {
		if proc.Connector != "" && supported[normalizeAIID(proc.Connector)] {
			agent := AgentProcess{PID: proc.PID, Connector: proc.Connector, User: proc.User,
				OwnerSID: proc.SessionOwnerID, StartedAt: proc.StartedAt}
			if proc.Connector == "opencode" || proc.Connector == "amp" || proc.Connector == "kiro" ||
				proc.Connector == "devin" || proc.Connector == "hermes" || proc.Connector == "antigravity" {
				if argv, err := agentprocess.CommandLineForPID(proc.PID); err == nil {
					agent.Args, agent.ArgsKnown = argv, true
				}
			}
			out = append(out, agent)
		}
	}
	return out, nil
}
