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

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
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
	{regexp.MustCompile(`(?i)\bnet\s+localgroup\b.*\/add`), "Windows group membership granted"},
	// PowerShell's cmdlet takes no /add; requiring one meant the documented
	// modern spelling of this command was never recognised.
	{regexp.MustCompile(`(?i)\bAdd-LocalGroupMember\b`), "Windows group membership granted"},
	{regexp.MustCompile(`(?i)\bNew-LocalUser\b`), "Windows local account created"},
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
var exfilCommand = lazyregexp.New(`(?i)\b(curl|wget|nc|ncat|scp|rsync|Invoke-WebRequest|iwr|Invoke-RestMethod)\b`)

// credentialReader recognises the commands that read a file, so a path in an
// argv is only treated as credential access when something is actually reading
// it. Without this an editor opening a config, or a grep across a tree, would
// classify as a credential read.
var credentialReader = lazyregexp.New(
	`(?i)\b(cat|head|tail|less|more|strings|xxd|od|base64|cp|scp|rsync|dd|` +
		`type|Get-Content|gc|Copy-Item|awk|sed|python3?|node|jq)\b`)

// localMCPCommand recognises an agent starting a local MCP tool server, which
// is how it reaches the filesystem, a database, or a cloud API.
var localMCPCommand = lazyregexp.New(`(?i)(mcp[-_]server|server[-_]mcp|@modelcontextprotocol/)`)

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
	if match, ok := containsAnyFold(path, indicators.HighConfidenceCredentials, indicators.CaseInsensitivePaths); ok {
		return Match{
			Tactic: CredentialAccess, SignalID: "agent_credential_access",
			Title: "agent read a secret at rest", Detail: match, Confidence: 1.0,
		}, true
	}
	if match, ok := containsAnyFold(path, indicators.CredentialPaths, indicators.CaseInsensitivePaths); ok {
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
	if match, ok := containsAnyFold(path, indicators.PersistencePaths, indicators.CaseInsensitivePaths); ok {
		return Match{
			Tactic: Persistence, SignalID: "agent_persistence",
			Title:  "agent installed a launch item, unit, or rc-file hook",
			Detail: match, Confidence: 1.0,
		}, true
	}
	if match, ok := containsAnyFold(path, indicators.AgentConfigPaths, indicators.CaseInsensitivePaths); ok {
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
	if match, ok := containsAnyFold(path, indicators.CredentialPaths, indicators.CaseInsensitivePaths); ok {
		return Match{
			Tactic: CredentialAccess, SignalID: "agent_credential_access",
			Title: "agent wrote to a credential store", Detail: match, Confidence: 1.0,
		}, true
	}
	return Match{}, false
}

func classifyExec(observation Observation, indicators IndicatorSet) (Match, bool) {
	cmdline := withoutAgentHarness(strings.TrimSpace(observation.Cmdline))
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
		if match, ok := containsAnyFold(cmdline, indicators.HighConfidenceCredentials, indicators.CaseInsensitivePaths); ok {
			return Match{
				Tactic: CredentialAccess, SignalID: "agent_credential_access",
				Title: "agent read a secret at rest", Detail: match, Confidence: 0.9,
			}, true
		}
		if match, ok := containsAnyFold(cmdline, indicators.CredentialPaths, indicators.CaseInsensitivePaths); ok {
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
	// Packaging is read from the programs the command runs, not from its
	// text. On its own it is ordinary tooling; as a chain stage before an
	// upload it is the staging step.
	if reason, ok := encodedPayload(cmdline); ok {
		return Match{
			Tactic: Exfiltration, SignalID: "agent_encoded_payload",
			Title:  "agent encoded or packaged data",
			Detail: reason, Confidence: 1.0,
		}, true
	}
	return Match{}, false
}

// containsAny returns the first fragment present in value.
func containsAny(value string, fragments []string) (string, bool) {
	return containsAnyFold(value, fragments, false)
}

// containsAnyFold matches a path against indicator fragments, optionally
// ignoring case.
//
// Folding is per-platform rather than global. NTFS does not distinguish case,
// so an indicator written C:\Users must match an event reporting c:\users --
// otherwise the conventional spelling is the only one detected, and lowercase
// is not an exotic way to write a path. On Linux the same two strings are two
// different files, and folding them would let an indicator match something it
// does not name.
func containsAnyFold(value string, fragments []string, ignoreCase bool) (string, bool) {
	normalised := strings.ReplaceAll(value, `\`, "/")
	if ignoreCase {
		value = strings.ToLower(value)
		normalised = strings.ToLower(normalised)
	}
	for _, fragment := range fragments {
		if fragment == "" {
			continue
		}
		candidate := fragment
		if ignoreCase {
			candidate = strings.ToLower(candidate)
		}
		if strings.Contains(value, candidate) {
			return fragment, true
		}
		// Windows paths reach a classifier that may be running with POSIX
		// indicators when an event is forwarded, so compare both separators.
		if normalisedFragment := strings.ReplaceAll(candidate, `\`, "/"); strings.Contains(normalised, normalisedFragment) {
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

// encodedPayloadPrograms are the programs whose own execution packages data
// for transport, keyed by lowercased basename without ".exe".
//
// They match the program a command runs -- an exec's argv[0], or a stage of
// a pipeline, a command substitution, or the script handed to a shell, eval,
// PowerShell or cmd -- and never a word anywhere in a command line. A regex
// over the whole line fired on the agent's own shell bootstrap, whose script
// names base64 in a comment, and on an `echo base64` that encodes nothing
// (GAP-1419).
var encodedPayloadPrograms = map[string]string{
	"base64":           "base64 encoding",
	"zip":              "archive created",
	"compress-archive": "PowerShell archive created",
	"makecab":          "cabinet archive created",
}

// archiveEncoders are the stages a tar archive is piped into to compress or
// encode it for transport.
var archiveEncoders = map[string]bool{"gzip": true, "bzip2": true, "xz": true, "base64": true}

// encodedPayload reports the packaging step a command line runs, if any.
func encodedPayload(cmdline string) (string, bool) {
	commands := shellCommands(cmdline)
	archived := make(map[int]bool)
	for _, command := range commands {
		program, _ := commandProgram(command.words)
		if archived[command.pipeline] && archiveEncoders[program] {
			return "archive piped to an encoder", true
		}
		if program == "tar" {
			archived[command.pipeline] = true
		}
	}
	for _, command := range commands {
		if reason, ok := encodingCommand(command.words); ok {
			return reason, true
		}
	}
	return "", false
}

// encodingCommand reports whether one simple command encodes or packages
// data.
func encodingCommand(words []shellWord) (string, bool) {
	program, args := commandProgram(words)
	switch program {
	case "openssl":
		switch firstOperand(args) {
		case "enc":
			return "openssl encryption", true
		case "base64":
			return "base64 encoding", true
		}
	case "certutil":
		// certutil -encode is the standard Windows base64 tool and a
		// long-known living-off-the-land staging step. -decode is included
		// because an agent unpacking a payload it fetched is the same chain
		// stage in reverse.
		for _, arg := range args {
			flag := strings.ToLower(arg.text)
			if !strings.HasPrefix(flag, "-") && !strings.HasPrefix(flag, "/") {
				continue
			}
			switch strings.TrimLeft(flag, "-/") {
			case "encode", "decode", "encodehex", "decodehex":
				return "certutil encoding", true
			}
		}
	}
	if reason, ok := encodedPayloadPrograms[program]; ok {
		return reason, true
	}
	// [Convert]::ToBase64String is a .NET call in PowerShell code, not a
	// program, so it matches where it is code: in an unquoted word.
	for _, word := range words {
		if !word.quoted && strings.Contains(strings.ToLower(word.text), "[convert]::tobase64string") {
			return "PowerShell base64 encoding", true
		}
	}
	return "", false
}

// The agent harness's own shell bootstrap, as Claude Code runs it for every
// Bash tool call (argv captured on RHEL with bash and on macOS with zsh,
// Claude Code 2.1.29x). Once per session a shell writes the snapshot:
//
//	bash -c -l SNAPSHOT_FILE=~/.claude/shell-snapshots/snapshot-bash-<id>.sh <script>
//
// and each tool call then runs the command it was asked to run as:
//
//	bash -c source ~/.claude/shell-snapshots/snapshot-bash-<id>.sh ... && eval '<command>' < /dev/null && pwd -P >| /tmp/claude-<hex>-cwd
var (
	harnessShell          = `^(?:"[^"]*"|\S*)\s+(?:-\S*\s+)*["']?`
	harnessSnapshotFile   = `["']?[^\s"']*[/\\]shell-snapshots[/\\]snapshot-[\w.-]+\.sh`
	harnessSnapshotWriter = lazyregexp.New(harnessShell + `SNAPSHOT_FILE=` + harnessSnapshotFile)
	harnessToolCall       = lazyregexp.New(harnessShell + `source\s+` + harnessSnapshotFile)
	harnessEval           = lazyregexp.New(
		`(?s)&&\s*eval\s+(.+?)\s*<\s*/dev/null\s*&&\s*pwd\s+-P\s*>\|\s*\S*claude-[0-9a-f]+-cwd["']?\s*$`)
)

// withoutAgentHarness strips the agent harness's own shell bootstrap from a
// command line and returns what the agent was asked to run: the eval payload
// of a tool-call wrapper, or nothing for the snapshot writer, whose script is
// the harness's own. Any other command line is returned unchanged.
//
// Dropping the bootstrap text hides no program: every program the payload or
// the snapshot writer runs is its own exec, classified on its own argv.
func withoutAgentHarness(cmdline string) string {
	if harnessSnapshotWriter.MatchString(cmdline) {
		return ""
	}
	if !harnessToolCall.MatchString(cmdline) {
		return cmdline
	}
	match := harnessEval.FindStringSubmatch(cmdline)
	if match == nil {
		return cmdline
	}
	return shellUnquote(match[1])
}

// shellUnquote removes the quoting from one shell word, such as the
// '...'"'"'...' form the harness quotes its eval payload in.
func shellUnquote(word string) string {
	var text strings.Builder
	for index := 0; index < len(word); index++ {
		switch c := word[index]; c {
		case '\'':
			closing := strings.IndexByte(word[index+1:], '\'')
			if closing < 0 {
				text.WriteString(word[index+1:])
				return text.String()
			}
			text.WriteString(word[index+1 : index+1+closing])
			index += closing + 1
		case '"':
			for index++; index < len(word) && word[index] != '"'; index++ {
				if word[index] == '\\' && index+1 < len(word) && strings.IndexByte("\"\\$`\n", word[index+1]) >= 0 {
					index++
				}
				text.WriteByte(word[index])
			}
		case '\\':
			if index+1 < len(word) {
				index++
			}
			text.WriteByte(word[index])
		default:
			text.WriteByte(c)
		}
	}
	return text.String()
}
