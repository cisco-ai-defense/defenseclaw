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
	// Account is the name the host's account database gives UserID now.
	// Linux and macOS hand a removed account's uid to the next account, so
	// a uid's ID is also keyed on its account (AccountKey) and, for a
	// directory account the host names with its domain or realm, on that
	// domain (AccountDomain): the new account never gets the removed one's
	// agent identities, their history or the guardrail profile assigned to
	// them, a namesake from another domain included (GAP-0947, GAP-1055). A
	// SID is never reused, so a SID's account is ignored and a renamed
	// Windows account keeps its IDs.
	Account string
	// Incarnation names, when set, which account held UserID under Account:
	// the gateway's token of it (the SID SSSD holds for the uid, the NSS
	// service that answers it, the macOS record). A uid handed from one
	// account to another of the same bare name and home, in another domain
	// or deleted and created again, derives other IDs for each, so neither
	// gets the other's guardrail profile or history. It is set only for an
	// account other than the first one the gateway saw hold the uid, so the
	// IDs derived before it was known stay as they were.
	Incarnation string
}

// AgentID returns "agt-" plus the first 16 hex digits of the namespaced
// sha256 of the normalized inputs, or "" when the machine, user or connector
// is unknown.
func AgentID(in Inputs) string {
	return agentID(in, true)
}

// LegacyAgentID is the ID 1.0.0 to 1.0.3 gave in, or "" when it is
// AgentID's (a SID). Those builds keyed a uid's ID on the bare account only:
// no domain, no marker of a bare account, and no account incarnation, which
// they kept none of, so in.Incarnation does not change it. A guardrail
// profile assignment written for it selects an account only when the
// gateway proves the account incarnation that holds the uid is the one
// those builds saw (the gateway's profileAgentBridge). Remove once upgrades
// from 1.0.3 are no longer supported.
func LegacyAgentID(in Inputs) string {
	if legacy := agentID(in, false); legacy != agentID(in, true) {
		return legacy
	}
	return ""
}

func agentID(in Inputs, current bool) string {
	machine := clean(in.MachineHash)
	user := NormalizeUserID(in.UserID)
	connector := strings.ToLower(clean(in.Connector))
	if machine == "" || user == "" || connector == "" {
		return ""
	}
	parts := []string{machine, user, connector, NormalizeInstallFP(in.InstallFP)}
	if !IsSID(user) {
		parts = append(parts, AccountKey(in.Account))
		if !current {
			return AgentIDPrefix + digest16(agentNamespace, parts...)
		}
		if AccountKey(in.Account) != "" {
			if domain := AccountDomain(in.Account); domain != "" {
				parts = append(parts, domain)
			} else {
				// A bare account must never share a current ID with the
				// domain-free ID a qualified account used before 1.0.4.
				// Two parts keep this namespace distinct even if a real
				// directory's domain equals the first marker.
				parts = append(parts, "account-kind:bare", "account-namespace:1.0.4")
			}
		}
		if incarnation := clean(in.Incarnation); incarnation != "" {
			parts = append(parts, "incarnation:"+incarnation)
		}
	}
	return AgentIDPrefix + digest16(agentNamespace, parts...)
}

// AccountKey is the form of an account name a uid's agent identity is keyed
// on: the bare account, without a DOMAIN\ prefix or an @realm suffix,
// lower-cased, so the spellings one directory account is reported in
// (alice, alice@corp.example.com, CORP\alice) are one account.
func AccountKey(name string) string {
	name = clean(name)
	if i := strings.IndexByte(name, '\\'); i > 0 && i < len(name)-1 {
		name = name[i+1:]
	} else if i := strings.LastIndexByte(name, '@'); i > 0 && i < len(name)-1 {
		name = name[:i]
	}
	return strings.ToLower(name)
}

// AccountDomain is the DOMAIN of a DOMAIN\name account or the realm of a
// name@realm one, lower-cased, or "" for a bare name.
func AccountDomain(name string) string {
	name = clean(name)
	if i := strings.IndexByte(name, '\\'); i > 0 && i < len(name)-1 {
		return strings.ToLower(name[:i])
	}
	if i := strings.LastIndexByte(name, '@'); i > 0 && i < len(name)-1 {
		return strings.ToLower(name[i+1:])
	}
	return ""
}

// UIDReassigned reports whether holder, the account that holds the uid
// userID now, is another account than recorded, the one a record of that
// uid was made for: recorded was removed and its uid handed to holder, or
// renamed. Two names of one account in two domains are two accounts. A SID
// is never handed on, and an unknown side proves nothing.
func UIDReassigned(userID, recorded, holder string) bool {
	if IsSID(NormalizeUserID(userID)) || clean(recorded) == "" || clean(holder) == "" {
		return false
	}
	if AccountKey(recorded) != AccountKey(holder) {
		return true
	}
	recordedDomain, holderDomain := AccountDomain(recorded), AccountDomain(holder)
	return recordedDomain != "" && holderDomain != "" && recordedDomain != holderDomain
}

// IsSID reports whether a normalized user id is a Windows SID.
func IsSID(id string) bool {
	return len(id) > 2 && id[0] == 'S' && id[1] == '-'
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
