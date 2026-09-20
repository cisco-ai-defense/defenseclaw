// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package actionfacts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
)

const maxSSHAuthorizedKeysApprovedFingerprints = 1024

// SSHAuthorizedKeysWriteOutcome is trusted result context supplied by a
// connector. The parser never infers success from command text.
type SSHAuthorizedKeysWriteOutcome string

const (
	SSHAuthorizedKeysWriteOutcomeUnknown   SSHAuthorizedKeysWriteOutcome = "unknown"
	SSHAuthorizedKeysWriteOutcomeSucceeded SSHAuthorizedKeysWriteOutcome = "succeeded"
	SSHAuthorizedKeysWriteOutcomeFailed    SSHAuthorizedKeysWriteOutcome = "failed"
)

// SSHAuthorizedKeysProtectionDecision is intentionally three-valued. An
// incomplete proof abstains; it never turns a generic authorized_keys access
// into a deny decision.
type SSHAuthorizedKeysProtectionDecision string

const (
	SSHAuthorizedKeysProtectionAbstain SSHAuthorizedKeysProtectionDecision = "abstain"
	SSHAuthorizedKeysProtectionAllow   SSHAuthorizedKeysProtectionDecision = "allow"
	SSHAuthorizedKeysProtectionBlock   SSHAuthorizedKeysProtectionDecision = "block"
)

// SSHAuthorizedKeysProtectionReason is a value-free conformance result. It is
// safe to test or count, but callers must not attach the source key or file
// content to telemetry.
type SSHAuthorizedKeysProtectionReason string

const (
	SSHAuthorizedKeysReasonUnapprovedKey    SSHAuthorizedKeysProtectionReason = "unapproved_key"
	SSHAuthorizedKeysReasonApprovedKey      SSHAuthorizedKeysProtectionReason = "approved_key"
	SSHAuthorizedKeysReasonMissingPolicy    SSHAuthorizedKeysProtectionReason = "missing_policy"
	SSHAuthorizedKeysReasonInvalidPolicy    SSHAuthorizedKeysProtectionReason = "invalid_policy"
	SSHAuthorizedKeysReasonOutcomeUnproven  SSHAuthorizedKeysProtectionReason = "outcome_unproven"
	SSHAuthorizedKeysReasonUnresolvedHome   SSHAuthorizedKeysProtectionReason = "unresolved_home"
	SSHAuthorizedKeysReasonUnprovenWrite    SSHAuthorizedKeysProtectionReason = "unproven_write"
	SSHAuthorizedKeysReasonUnprovenContent  SSHAuthorizedKeysProtectionReason = "unproven_content"
	SSHAuthorizedKeysReasonMalformedKey     SSHAuthorizedKeysProtectionReason = "malformed_key"
	SSHAuthorizedKeysReasonNonAuthoritative SSHAuthorizedKeysProtectionReason = "non_authoritative"
)

// SSHAuthorizedKeyWriteFact is the bounded, content-free result of a complete
// proof. Fingerprint is OpenSSH's SHA256 fingerprint of the decoded public-key
// blob, so comments and harmless whitespace do not change its identity.
type SSHAuthorizedKeyWriteFact struct {
	CommandID   int64
	Access      PathAccess
	Path        string
	KeyType     string
	Fingerprint string
}

// SSHAuthorizedKeysProtectionPolicy is opt-in trusted policy context. A nil
// ApprovedKeyFingerprints slice means that the allowlist was not supplied. A
// present empty slice intentionally approves no keys.
type SSHAuthorizedKeysProtectionPolicy struct {
	ApprovedKeyFingerprints []string
}

// SSHAuthorizedKeysProtectionResult contains no source key material.
type SSHAuthorizedKeysProtectionResult struct {
	Decision SSHAuthorizedKeysProtectionDecision
	Reason   SSHAuthorizedKeysProtectionReason
	Fact     SSHAuthorizedKeyWriteFact
}

// EvaluateSSHAuthorizedKeysProtection blocks only a succeeded, unconditional,
// exact write of one literal, parseable SSH public key to the active user's
// authorized_keys file when a complete opt-in allowlist is present and does
// not contain that key's stable fingerprint.
func EvaluateSSHAuthorizedKeysProtection(
	input Input,
	facts Facts,
	outcome SSHAuthorizedKeysWriteOutcome,
	policy *SSHAuthorizedKeysProtectionPolicy,
) SSHAuthorizedKeysProtectionResult {
	if policy == nil || policy.ApprovedKeyFingerprints == nil {
		return sshAuthorizedKeysResult(
			SSHAuthorizedKeysProtectionAbstain,
			SSHAuthorizedKeysReasonMissingPolicy,
			SSHAuthorizedKeyWriteFact{},
		)
	}
	approved, valid := validatedSSHAuthorizedKeysAllowlist(
		policy.ApprovedKeyFingerprints,
	)
	if !valid {
		return sshAuthorizedKeysResult(
			SSHAuthorizedKeysProtectionAbstain,
			SSHAuthorizedKeysReasonInvalidPolicy,
			SSHAuthorizedKeyWriteFact{},
		)
	}
	if outcome != SSHAuthorizedKeysWriteOutcomeSucceeded {
		return sshAuthorizedKeysResult(
			SSHAuthorizedKeysProtectionAbstain,
			SSHAuthorizedKeysReasonOutcomeUnproven,
			SSHAuthorizedKeyWriteFact{},
		)
	}
	fact, reason := deriveSSHAuthorizedKeyWriteFact(input, facts)
	if reason != "" {
		return sshAuthorizedKeysResult(
			SSHAuthorizedKeysProtectionAbstain,
			reason,
			SSHAuthorizedKeyWriteFact{},
		)
	}
	if _, ok := approved[fact.Fingerprint]; ok {
		return sshAuthorizedKeysResult(
			SSHAuthorizedKeysProtectionAllow,
			SSHAuthorizedKeysReasonApprovedKey,
			fact,
		)
	}
	return sshAuthorizedKeysResult(
		SSHAuthorizedKeysProtectionBlock,
		SSHAuthorizedKeysReasonUnapprovedKey,
		fact,
	)
}

func deriveSSHAuthorizedKeyWriteFact(
	input Input,
	facts Facts,
) (SSHAuthorizedKeyWriteFact, SSHAuthorizedKeysProtectionReason) {
	if !facts.Authoritative() || !facts.EnforcementEligible() {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonNonAuthoritative
	}
	activeHome := path.Clean(facts.ActiveHome)
	if facts.ActiveHome == "" || facts.ActiveHome != activeHome ||
		!path.IsAbs(activeHome) || activeHome == "/" {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonUnresolvedHome
	}
	wantPath := path.Join(activeHome, ".ssh", "authorized_keys")

	var target PathFact
	mutationCount := 0
	for _, candidate := range facts.Paths {
		if candidate.Access != PathAccessWrite &&
			candidate.Access != PathAccessAppend {
			continue
		}
		mutationCount++
		target = candidate
	}
	if mutationCount != 1 || target.Flavor != PathFlavorPOSIX ||
		!target.Absolute || target.Resolved == "" ||
		target.Value != wantPath || target.Resolved != wantPath {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonUnprovenWrite
	}
	if len(facts.Commands) != 1 {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonUnprovenWrite
	}
	command := facts.Commands[0]
	if command.ID != target.CommandID || command.ParentCommandID != 0 ||
		command.PipelineID != 0 || command.ControlFlowUncertain ||
		command.Effect != EffectExecute || !command.ArgvComplete {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonUnprovenWrite
	}

	content, ok := literalSSHAuthorizedKeyWriteContent(input, command, target)
	if !ok {
		return SSHAuthorizedKeyWriteFact{}, SSHAuthorizedKeysReasonUnprovenContent
	}
	key, reason := parseLiteralSSHAuthorizedKey(content)
	if reason != "" {
		return SSHAuthorizedKeyWriteFact{}, reason
	}
	return SSHAuthorizedKeyWriteFact{
		CommandID:   command.ID,
		Access:      target.Access,
		Path:        wantPath,
		KeyType:     key.Type(),
		Fingerprint: ssh.FingerprintSHA256(key),
	}, ""
}

func literalSSHAuthorizedKeyWriteContent(
	input Input,
	command CommandFact,
	target PathFact,
) (string, bool) {
	if content, ok := literalStructuredSSHAuthorizedKeyContent(
		input,
		command,
		target,
	); ok {
		return content, true
	}
	if command.Dialect != DialectPOSIX ||
		len(command.Argv) != len(command.Arguments) {
		return "", false
	}
	for _, argument := range command.Arguments {
		if argument.Expands {
			return "", false
		}
	}
	switch command.Program {
	case "echo":
		if len(command.Argv) != 2 || strings.HasPrefix(command.Argv[1], "-") {
			return "", false
		}
		return command.Argv[1], true
	case "printf":
		if len(command.Argv) != 3 ||
			(command.Argv[1] != `%s\n` && command.Argv[1] != "%s") {
			return "", false
		}
		return command.Argv[2], true
	default:
		return "", false
	}
}

func literalStructuredSSHAuthorizedKeyContent(
	input Input,
	command CommandFact,
	target PathFact,
) (string, bool) {
	tool := strings.ToLower(input.Tool)
	access := PathAccessWrite
	switch tool {
	case "write_file", "write-file", "writefile":
	case "append_file", "append-file", "appendfile":
		access = PathAccessAppend
	default:
		return "", false
	}
	if target.Access != access || !strings.EqualFold(command.Program, input.Tool) ||
		validateJSONWithStringLimit(input.Args, maxCommandBytes) != "" {
		return "", false
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(input.Args, &raw); err != nil || len(raw) != 2 {
		return "", false
	}
	var inputPath string
	var content string
	if err := json.Unmarshal(raw["path"], &inputPath); err != nil ||
		json.Unmarshal(raw["content"], &content) != nil ||
		len(raw["path"]) == 0 || len(raw["content"]) == 0 ||
		inputPath != target.Value {
		return "", false
	}
	return content, true
}

func parseLiteralSSHAuthorizedKey(
	content string,
) (ssh.PublicKey, SSHAuthorizedKeysProtectionReason) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" || strings.ContainsRune(trimmed, '\x00') {
		return nil, SSHAuthorizedKeysReasonMalformedKey
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil || key == nil || len(options) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, SSHAuthorizedKeysReasonMalformedKey
	}
	fields := strings.Fields(trimmed)
	if len(fields) < 2 || fields[0] != key.Type() ||
		strings.Contains(key.Type(), "-cert-") {
		return nil, SSHAuthorizedKeysReasonMalformedKey
	}
	return key, ""
}

func validatedSSHAuthorizedKeysAllowlist(
	values []string,
) (map[string]struct{}, bool) {
	if len(values) > maxSSHAuthorizedKeysApprovedFingerprints {
		return nil, false
	}
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validSSHAuthorizedKeyFingerprint(value) {
			return nil, false
		}
		out[value] = struct{}{}
	}
	return out, true
}

func validSSHAuthorizedKeyFingerprint(value string) bool {
	encoded, ok := strings.CutPrefix(value, "SHA256:")
	if !ok || encoded == "" || strings.ContainsRune(encoded, '=') {
		return false
	}
	digest, err := base64.RawStdEncoding.DecodeString(encoded)
	return err == nil && len(digest) == 32 &&
		base64.RawStdEncoding.EncodeToString(digest) == encoded
}

func sshAuthorizedKeysResult(
	decision SSHAuthorizedKeysProtectionDecision,
	reason SSHAuthorizedKeysProtectionReason,
	fact SSHAuthorizedKeyWriteFact,
) SSHAuthorizedKeysProtectionResult {
	return SSHAuthorizedKeysProtectionResult{
		Decision: decision,
		Reason:   reason,
		Fact:     fact,
	}
}
