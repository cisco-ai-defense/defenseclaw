// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"regexp"
	"strings"
)

// Observation is one normalised kernel event handed to the classifier.
//
// A local mirror of plane.Event rather than an import, so this package stays
// free of the acquisition layer and remains a pure function over data. The
// service does the two-line translation.
type Observation struct {
	Kind    string // exec | exit | file_read | file_write | identity | privilege
	PID     int
	Name    string
	Cmdline string
	Path    string
	Detail  string
}

// Kind values, mirroring plane.Kind.
const (
	KindExec      = "exec"
	KindFileRead  = "file_read"
	KindFileWrite = "file_write"
	KindIdentity  = "identity"
	KindPrivilege = "privilege"
)

// identityCommands recognise an agent minting a principal from its argv.
//
// Cloud principals come first because they are the ones with no benign
// explanation once agent lineage is established: an agent that creates an IAM
// access key has converted a transient foothold into durable access.
var identityCommands = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)\baws\s+iam\s+create-(access-key|user|login-profile)\b`), "AWS IAM principal created"},
	{regexp.MustCompile(`(?i)\baz\s+ad\s+(sp|user)\s+create\b`), "Azure AD principal created"},
	{regexp.MustCompile(`(?i)\bgcloud\s+iam\s+service-accounts\s+create\b`), "GCP service account created"},
	{regexp.MustCompile(`(?i)\bgcloud\s+iam\s+service-accounts\s+keys\s+create\b`), "GCP service account key created"},
	{regexp.MustCompile(`(?i)\bkubectl\s+create\s+(serviceaccount|clusterrolebinding)\b`), "Kubernetes principal created"},
	{regexp.MustCompile(`(?i)\b(useradd|adduser)\b`), "local account creation"},
	{regexp.MustCompile(`(?i)\bnet\s+user\s+\S+\s+.*\s+/add\b`), "Windows local account created"},
	{regexp.MustCompile(`(?i)\bNew-LocalUser\b`), "Windows local account created via PowerShell"},
	{regexp.MustCompile(`(?i)\bdscl\s+\.\s+-create\s+/Users/`), "macOS local account created"},
	{regexp.MustCompile(`(?i)\busermod\s+.*-a?G\s`), "group membership granted"},
	{regexp.MustCompile(`(?i)\b(net\s+localgroup|Add-LocalGroupMember)\b.*\/add`), "Windows group membership granted"},
	{regexp.MustCompile(`(?i)\bgroupadd\b`), "local group creation"},
}

// privilegeCommands recognise an agent acquiring rights it did not start with.
var privilegeCommands = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)^\s*sudo\s+\S`), "elevated via sudo"},
	{regexp.MustCompile(`(?i)\bdoas\s+\S`), "elevated via doas"},
	{regexp.MustCompile(`(?i)\bpkexec\b`), "elevated via pkexec"},
	{regexp.MustCompile(`(?i)\bosascript\b.*with\s+administrator\s+privileges`), "elevated via AppleScript"},
	{regexp.MustCompile(`(?i)\bStart-Process\b.*-Verb\s+RunAs`), "elevated via RunAs"},
	{regexp.MustCompile(`(?i)\bchmod\s+[ug]?\+s\b|\bchmod\s+[0-7]?[24]7[0-7]{2}\b`), "setuid bit set"},
	{regexp.MustCompile(`(?i)\bsetcap\b`), "file capability granted"},
	{regexp.MustCompile(`(?i)\btee\s+/etc/sudoers`), "sudo rule written"},
	{regexp.MustCompile(`(?i)\bvisudo\b`), "sudoers edited"},
}

// encodedPayloadCommands recognise an agent packaging data for transport. On
// its own this is ordinary tooling; as a chain stage before an upload it is
// the staging step.
var encodedPayloadCommands = []struct {
	pattern *regexp.Regexp
	reason  string
}{
	{regexp.MustCompile(`(?i)\bbase64\b`), "base64 encoding"},
	{regexp.MustCompile(`(?i)\btar\b.*\|\s*(gzip|bzip2|xz|base64)`), "archive piped to an encoder"},
	{regexp.MustCompile(`(?i)\bzip\s+-r?\s*-?P?\b`), "archive created"},
	{regexp.MustCompile(`(?i)\bopenssl\s+enc\b`), "openssl encryption"},
	{regexp.MustCompile(`(?i)\bCompress-Archive\b`), "PowerShell archive created"},
	{regexp.MustCompile(`(?i)\[Convert\]::ToBase64String`), "PowerShell base64 encoding"},
}

// exfilHosts are public drop points: paste services, anonymous file drops,
// webhook relays, and tunnels.
//
// Reaching one is a Plane C signal rather than a Plane B one because it is
// about what an agent did with the machine, not about which model it used.
var exfilHosts = []string{
	"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "dpaste.org",
	"termbin.com", "0x0.st", "ix.io", "sprunge.us",
	"transfer.sh", "file.io", "anonfiles.com", "gofile.io", "bashupload.com",
	"temp.sh", "oshi.at", "catbox.moe", "litterbox.catbox.moe",
	"webhook.site", "requestbin.com", "pipedream.net", "beeceptor.com",
	"ngrok.io", "ngrok-free.app", "trycloudflare.com", "loca.lt", "localtunnel.me",
	"telegram.org", "api.telegram.org", "discord.com/api/webhooks",
}

// exfilCommand recognises a transfer to a public drop point in one argv.
var exfilCommand = regexp.MustCompile(`(?i)\b(curl|wget|nc|ncat|scp|rsync|Invoke-WebRequest|iwr|Invoke-RestMethod)\b`)

// credentialReader recognises the commands that read a file, so a path in an
// argv is only treated as credential access when something is actually reading
// it. Without this an editor opening a config, or a grep across a tree, would
// classify as a credential read.
var credentialReader = regexp.MustCompile(
	`(?i)\b(cat|head|tail|less|more|strings|xxd|od|base64|cp|scp|rsync|dd|` +
		`type|Get-Content|gc|Copy-Item|awk|sed|python3?|node|jq)\b`)

// localMCPCommand recognises an agent starting a local MCP tool server, which
// is how it reaches the filesystem, a database, or a cloud API.
var localMCPCommand = regexp.MustCompile(`(?i)(mcp[-_]server|server[-_]mcp|@modelcontextprotocol/)`)

// Classify turns one observation into a tactic match, or reports false when
// the observation is not one.
//
// Pure: no I/O, no clock, no configuration beyond the indicator set. Every
// case is reachable from a fixture, which is what makes the detection matrix
// meaningful.
func Classify(observation Observation, indicators IndicatorSet) (Match, bool) {
	switch observation.Kind {
	case KindFileRead:
		return classifyFileRead(observation, indicators)
	case KindFileWrite:
		return classifyFileWrite(observation, indicators)
	case KindIdentity:
		return Match{
			Tactic: IdentityCreation, SignalID: "agent_identity_creation",
			Title:      "agent minted a local account or cloud principal",
			Detail:     firstNonEmpty(observation.Detail, observation.Name),
			Confidence: 1.0,
		}, true
	case KindPrivilege:
		return Match{
			Tactic: PrivilegeEscalation, SignalID: "agent_privilege_escalation",
			Title:      "agent acquired rights it did not start with",
			Detail:     firstNonEmpty(observation.Detail, observation.Name),
			Confidence: 1.0,
		}, true
	case KindExec:
		return classifyExec(observation, indicators)
	}
	return Match{}, false
}

func classifyFileRead(observation Observation, indicators IndicatorSet) (Match, bool) {
	path := observation.Path
	if path == "" {
		return Match{}, false
	}
	if match, ok := containsAny(path, indicators.HighConfidenceCredentials); ok {
		return Match{
			Tactic: CredentialAccess, SignalID: "agent_credential_access",
			Title: "agent read a secret at rest", Detail: match, Confidence: 1.0,
		}, true
	}
	if match, ok := containsAny(path, indicators.CredentialPaths); ok {
		// A path that merely looks credential-adjacent is graded down rather
		// than discarded: it can corroborate a chain, and on its own it should
		// not raise a finding.
		return Match{
			Tactic: CredentialAccess, SignalID: "agent_credential_access",
			Title: "agent read a credential-adjacent file", Detail: match, Confidence: 0.6,
		}, true
	}
	return Match{}, false
}

func classifyFileWrite(observation Observation, indicators IndicatorSet) (Match, bool) {
	path := observation.Path
	if path == "" {
		return Match{}, false
	}
	if match, ok := containsAny(path, indicators.PersistencePaths); ok {
		return Match{
			Tactic: Persistence, SignalID: "agent_persistence",
			Title:  "agent installed a launch item, unit, or rc-file hook",
			Detail: match, Confidence: 1.0,
		}, true
	}
	if match, ok := containsAny(path, indicators.AgentConfigPaths); ok {
		// The category with no equivalent in a traditional endpoint product.
		// An agent that appends to its own CLAUDE.md or registers an MCP
		// server is arranging to influence every future session on the
		// machine. There is no launch item and no login item, so nothing an
		// EDR calls persistence has happened -- and the effect on the next
		// session is identical.
		return Match{
			Tactic: Persistence, SignalID: "agent_config_persistence",
			Title:  "agent rewrote its own standing configuration",
			Detail: match, Confidence: 1.0,
		}, true
	}
	if match, ok := containsAny(path, indicators.CredentialPaths); ok {
		return Match{
			Tactic: CredentialAccess, SignalID: "agent_credential_access",
			Title: "agent wrote to a credential store", Detail: match, Confidence: 1.0,
		}, true
	}
	return Match{}, false
}

func classifyExec(observation Observation, indicators IndicatorSet) (Match, bool) {
	cmdline := strings.TrimSpace(observation.Cmdline)
	if cmdline == "" {
		return Match{}, false
	}
	for _, candidate := range identityCommands {
		if candidate.pattern.MatchString(cmdline) {
			return Match{
				Tactic: IdentityCreation, SignalID: "agent_identity_creation",
				Title:  "agent minted a local account or cloud principal",
				Detail: candidate.reason, Confidence: 1.0,
			}, true
		}
	}
	for _, candidate := range privilegeCommands {
		if candidate.pattern.MatchString(cmdline) {
			return Match{
				Tactic: PrivilegeEscalation, SignalID: "agent_privilege_escalation",
				Title:  "agent acquired rights it did not start with",
				Detail: candidate.reason, Confidence: 1.0,
			}, true
		}
	}
	if host, ok := containsAny(strings.ToLower(cmdline), exfilHosts); ok {
		if exfilCommand.MatchString(cmdline) {
			return Match{
				Tactic: Exfiltration, SignalID: "agent_public_exfil_surface",
				Title:  "agent reached a paste site, file drop, webhook relay, or tunnel",
				Detail: host, Confidence: 1.0,
			}, true
		}
		// The host appears without a transfer tool. Real, weaker, and graded
		// down so it corroborates rather than fires.
		return Match{
			Tactic: Exfiltration, SignalID: "agent_public_exfil_surface",
			Title: "agent referenced a public drop point", Detail: host, Confidence: 0.5,
		}, true
	}
	// A command line that names a secret at rest is credential access even
	// when no file event was observed. This is what keeps the tactic reachable
	// on an unprivileged Linux host, which has cn_proc but not fanotify, and on
	// Windows, where object access needs a SACL that is almost never
	// configured. Graded slightly down against a kernel file event: argv says
	// what a process was asked to do, a file event says what it did.
	if credentialReader.MatchString(cmdline) {
		if match, ok := containsAny(cmdline, indicators.HighConfidenceCredentials); ok {
			return Match{
				Tactic: CredentialAccess, SignalID: "agent_credential_access",
				Title: "agent read a secret at rest", Detail: match, Confidence: 0.9,
			}, true
		}
		if match, ok := containsAny(cmdline, indicators.CredentialPaths); ok {
			return Match{
				Tactic: CredentialAccess, SignalID: "agent_credential_access",
				Title: "agent read a credential-adjacent file", Detail: match, Confidence: 0.6,
			}, true
		}
	}
	if localMCPCommand.MatchString(cmdline) {
		return Match{
			Tactic: LocalInference, SignalID: "agent_local_mcp_server",
			Title:  "agent started a local MCP tool server",
			Detail: observation.Name, Confidence: 1.0,
		}, true
	}
	for _, candidate := range encodedPayloadCommands {
		if candidate.pattern.MatchString(cmdline) {
			return Match{
				Tactic: Exfiltration, SignalID: "agent_encoded_payload",
				Title:  "agent encoded or packaged data",
				Detail: candidate.reason, Confidence: 1.0,
			}, true
		}
	}
	return Match{}, false
}

// containsAny returns the first fragment present in value.
func containsAny(value string, fragments []string) (string, bool) {
	normalised := strings.ReplaceAll(value, `\`, "/")
	for _, fragment := range fragments {
		if fragment == "" {
			continue
		}
		if strings.Contains(value, fragment) {
			return fragment, true
		}
		// Windows paths reach a classifier that may be running with POSIX
		// indicators when an event is forwarded, so compare both separators.
		if normalisedFragment := strings.ReplaceAll(fragment, `\`, "/"); strings.Contains(normalised, normalisedFragment) {
			return fragment, true
		}
	}
	return "", false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
