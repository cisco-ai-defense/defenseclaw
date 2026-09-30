// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

// An agent the standalone enumerator knows is installed for an eligible user
// but cannot enroll (its version has no verified hook contract, is below the
// platform minimum, cannot be read, or its install is not one the guardian
// can manage) gets no DefenseClaw hooks. The enumerator records every such
// agent next to the manifest, and the lifecycle's status and verify report
// them, so an unprotected agent is never a silent gap.

// UnprotectedAgentsFileName is the record the standalone enumerator writes
// next to the guardian manifest (root-only on Linux and macOS; SYSTEM and
// Administrators only on Windows).
const UnprotectedAgentsFileName = "unprotected-agents.json"

// UnprotectedAgentsMaxBytes bounds the record a reader accepts.
const UnprotectedAgentsMaxBytes = 4 << 20

// Status codes for an unprotected agent.
const (
	// UnprotectedCodeHookContractUnverified: the agent's version has no
	// verified DefenseClaw hook contract.
	UnprotectedCodeHookContractUnverified = "hook_contract_unverified"
	// UnprotectedCodeAgentUnprotected: any other reason the agent could not
	// be enrolled.
	UnprotectedCodeAgentUnprotected = "agent_unprotected"
	// UnprotectedCodeKiroIDEBelowGlobalHooksFloor: the user's Kiro IDE is
	// older than KiroIDEGlobalHooksFloor and does not read the global hook
	// file the guardian writes.
	UnprotectedCodeKiroIDEBelowGlobalHooksFloor = "kiro_ide_below_global_hooks_floor"
)

// unprotectedReasonMaxRunes bounds the user-influenced reason text.
const unprotectedReasonMaxRunes = 400

// UnprotectedAgent is one agent install the enumerator found but could not
// enroll.
type UnprotectedAgent struct {
	User      string `json:"user"`
	SID       string `json:"sid,omitempty"`
	UID       *int   `json:"uid,omitempty"`
	Connector string `json:"connector"`
	Version   string `json:"version,omitempty"`
	// Surface, Host and HostVersion describe an app or extension install
	// (connector.AgentSurface); Version is then its engine version. Empty
	// for a CLI install.
	Surface     string `json:"surface,omitempty"`
	Host        string `json:"host,omitempty"`
	HostVersion string `json:"host_version,omitempty"`
	// Refusal is set for a surface refused under
	// enterprise.enrollment.unverified_versions: refuse (RefusalEnforced
	// or RefusalMissing).
	Refusal string `json:"refusal,omitempty"`
	Code    string `json:"code"`
	Reason  string `json:"reason"`
}

type unprotectedAgentsFile struct {
	Version int                `json:"version"`
	Agents  []UnprotectedAgent `json:"agents"`
}

// UnprotectedAgentsPath is the unprotected-agents record for manifestPath.
func UnprotectedAgentsPath(manifestPath string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(manifestPath)), UnprotectedAgentsFileName)
}

// UnprotectedCodeForReason classifies an admission reason.
func UnprotectedCodeForReason(reason string) string {
	if strings.Contains(reason, "not verified against a known hook contract") ||
		strings.Contains(reason, "not covered by a known hook contract") {
		return UnprotectedCodeHookContractUnverified
	}
	return UnprotectedCodeAgentUnprotected
}

// Message is the operator-facing status line for one agent.
func (a UnprotectedAgent) Message() string {
	name := strings.TrimSpace(a.Connector)
	if version := strings.TrimSpace(a.Version); version != "" {
		name += " " + version
	}
	who := strings.TrimSpace(a.User)
	if sid := strings.TrimSpace(a.SID); sid != "" {
		if who == "" {
			who = sid
		} else {
			who += " (" + sid + ")"
		}
	}
	if surface := strings.TrimSpace(a.Surface); surface != "" {
		name += " (" + surface
		if host := strings.TrimSpace(a.Host); host != "" {
			name += " in " + host
		}
		if hostVersion := strings.TrimSpace(a.HostVersion); hostVersion != "" {
			name += " " + hostVersion
		}
		name += ")"
	}
	return fmt.Sprintf("%s for user %s is not protected: %s", name, who, strings.TrimSpace(a.Reason))
}

// MarshalUnprotectedAgents serializes agents deterministically (sorted, one
// entry per user and connector) so an unchanged set rewrites nothing.
func MarshalUnprotectedAgents(agents []UnprotectedAgent) ([]byte, error) {
	normalized := normalizeUnprotectedAgents(agents)
	data, err := json.MarshalIndent(unprotectedAgentsFile{Version: 1, Agents: normalized}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// ParseUnprotectedAgents decodes a record written by MarshalUnprotectedAgents.
func ParseUnprotectedAgents(data []byte) ([]UnprotectedAgent, error) {
	if len(data) > UnprotectedAgentsMaxBytes {
		return nil, errors.New("enterprise hooks: unprotected agents record is too large")
	}
	var record unprotectedAgentsFile
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("enterprise hooks: parse unprotected agents record: %w", err)
	}
	if record.Version != 1 {
		return nil, fmt.Errorf("enterprise hooks: unprotected agents record version %d is not supported", record.Version)
	}
	out := make([]UnprotectedAgent, 0, len(record.Agents))
	for _, agent := range record.Agents {
		if strings.TrimSpace(agent.Connector) == "" || (strings.TrimSpace(agent.User) == "" && strings.TrimSpace(agent.SID) == "") {
			continue
		}
		if agent.Code != UnprotectedCodeHookContractUnverified && agent.Code != UnprotectedCodeSurfaceUnverified &&
			agent.Code != UnprotectedCodeKiroIDEBelowGlobalHooksFloor {
			agent.Code = UnprotectedCodeAgentUnprotected
		}
		if agent.Refusal != RefusalEnforced && agent.Refusal != RefusalMissing {
			agent.Refusal = ""
		}
		out = append(out, agent)
	}
	return normalizeUnprotectedAgents(out), nil
}

func normalizeUnprotectedAgents(agents []UnprotectedAgent) []UnprotectedAgent {
	byKey := map[string]UnprotectedAgent{}
	for _, agent := range agents {
		agent.User = boundedStatusText(agent.User, 128)
		agent.SID = boundedStatusText(agent.SID, 128)
		agent.Connector = strings.ToLower(boundedStatusText(agent.Connector, 64))
		agent.Version = boundedStatusText(agent.Version, 128)
		agent.Surface = strings.ToLower(boundedStatusText(agent.Surface, 32))
		agent.Host = boundedStatusText(agent.Host, 64)
		agent.HostVersion = boundedStatusText(agent.HostVersion, 128)
		agent.Reason = boundedStatusText(agent.Reason, unprotectedReasonMaxRunes)
		if agent.Code == "" {
			agent.Code = UnprotectedCodeForReason(agent.Reason)
		}
		key := strings.ToLower(agent.SID) + "\x00" + agent.User + "\x00" + agent.Connector + "\x00" + agent.Surface + "\x00" + agent.Host
		byKey[key] = agent
	}
	out := make([]UnprotectedAgent, 0, len(byKey))
	for _, agent := range byKey {
		out = append(out, agent)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].User != out[j].User {
			return out[i].User < out[j].User
		}
		if out[i].SID != out[j].SID {
			return out[i].SID < out[j].SID
		}
		if out[i].Connector != out[j].Connector {
			return out[i].Connector < out[j].Connector
		}
		if out[i].Surface != out[j].Surface {
			return out[i].Surface < out[j].Surface
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// boundedStatusText keeps one line of at most limit runes of printable text.
func boundedStatusText(value string, limit int) string {
	value = strings.TrimSpace(value)
	var b strings.Builder
	count := 0
	for _, r := range value {
		if count >= limit {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
