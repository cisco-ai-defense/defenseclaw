// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import "time"

// AgentProcess is one running agent run of a connector DefenseClaw supports.
type AgentProcess struct {
	PID       int
	Connector string
	// User is DOMAIN\account of the process token, "" when this account
	// cannot open the process.
	User string
	// StartedAt is zero when this account cannot open the process.
	StartedAt time.Time
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
			out = append(out, AgentProcess{PID: proc.PID, Connector: proc.Connector, User: proc.User, StartedAt: proc.StartedAt})
		}
	}
	return out, nil
}
