// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package agentidentity derives the stable, credential-free identifiers
// DefenseClaw gives to agents:
//
//   - the agent identity (defenseclaw.agent.identity.id, "agt-…"): one
//     harness install for one user on one machine;
//   - the session instance (agent_instance_id, "ais-…"): one chat of that
//     agent;
//   - the sub-agent instance ("ais-…"): one sub-agent a session spawned.
//
// Every function here is pure. The IDs are attribution keys, not
// credentials: they are digests of facts the gateway already holds, so the
// same inputs give the same ID on every restart and on every gateway.
package agentidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
)

// Domain separators. Changing any of them changes every ID.
const (
	agentNamespace    = "defenseclaw.agent.identity.v1"
	instanceNamespace = "defenseclaw.agent.instance.v1"
	subagentNamespace = "defenseclaw.agent.subagent.v1"
	machineNamespace  = "defenseclaw.machine.v1"
)

// Prefixes of the derived IDs.
const (
	AgentIDPrefix    = "agt-"
	InstanceIDPrefix = "ais-"
)

// Inputs are the components of an agent identity.
type Inputs struct {
	// MachineHash is MachineHash of the host's machine id.
	MachineHash string
	// UserID is the uid or SID of the user the agent runs as.
	UserID string
	// Connector is the DefenseClaw connector name (claudecode, codex, ...).
	Connector string
	// InstallFP is the connector's config root inside the user's home, as
	// the gateway resolves it. It is never a path the agent claimed.
	InstallFP string
}

// AgentID returns "agt-" plus the first 16 hex digits of the namespaced
// sha256 of the normalized inputs, or "" when the machine, user or connector
// is unknown.
func AgentID(in Inputs) string {
	machine := clean(in.MachineHash)
	user := NormalizeUserID(in.UserID)
	connector := strings.ToLower(clean(in.Connector))
	if machine == "" || user == "" || connector == "" {
		return ""
	}
	return AgentIDPrefix + digest16(agentNamespace, machine, user, connector, NormalizeInstallFP(in.InstallFP))
}

// InstanceID returns the session instance id of sessionID under agentID:
// "ais-" plus 16 hex digits. agentID may be empty for traffic that carries
// no agent identity; sessionID must not be.
func InstanceID(agentID, sessionID string) string {
	sessionID = clean(sessionID)
	if sessionID == "" {
		return ""
	}
	return InstanceIDPrefix + digest16(instanceNamespace, clean(agentID), sessionID)
}

// SubagentInstanceID returns the instance id of the sub-agent subagentID
// spawned by the instance parentInstance.
func SubagentInstanceID(parentInstance, subagentID string) string {
	parentInstance, subagentID = clean(parentInstance), clean(subagentID)
	if parentInstance == "" || subagentID == "" {
		return ""
	}
	return InstanceIDPrefix + digest16(subagentNamespace, parentInstance, subagentID)
}

// MachineHash returns the 64-hex namespaced sha256 of a raw machine id
// (/etc/machine-id, Windows MachineGuid or macOS IOPlatformUUID). The raw
// value is case-folded first: the platforms print the same id in either
// case.
func MachineHash(raw string) string {
	raw = strings.ToLower(clean(raw))
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(machineNamespace + "\x00" + raw))
	return hex.EncodeToString(sum[:])
}

// NormalizeUserID trims a uid or SID and upper-cases a SID, which Windows
// compares case-insensitively.
func NormalizeUserID(id string) string {
	id = clean(id)
	if len(id) > 2 && (id[0] == 's' || id[0] == 'S') && id[1] == '-' {
		return strings.ToUpper(id)
	}
	return id
}

// NormalizeInstallFP makes one config root compare equal however it was
// spelled: separators become "/", the path is cleaned, a trailing separator
// is dropped, and a Windows path (drive letter or UNC) is case-folded.
func NormalizeInstallFP(fp string) string {
	fp = clean(fp)
	if fp == "" {
		return ""
	}
	windows := strings.Contains(fp, `\`) || (len(fp) >= 2 && fp[1] == ':' && isASCIILetter(fp[0]))
	fp = strings.ReplaceAll(fp, `\`, "/")
	unc := strings.HasPrefix(fp, "//")
	fp = path.Clean(fp)
	if unc && !strings.HasPrefix(fp, "//") {
		fp = "/" + fp
	}
	if windows || unc {
		fp = strings.ToLower(fp)
	}
	return fp
}

func digest16(namespace string, parts ...string) string {
	h := sha256.New()
	h.Write([]byte(namespace))
	for _, part := range parts {
		h.Write([]byte{0})
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// clean trims space and removes NUL, the component separator.
func clean(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\x00", ""))
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
