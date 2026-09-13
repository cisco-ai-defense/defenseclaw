// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"regexp"
)

const (
	// MaxReturnedCredentialResultBytes bounds post-tool-use inspection. Result
	// bytes are classified in request scope and must never be persisted.
	MaxReturnedCredentialResultBytes = 256 * 1024
	maxReturnedCredentialLineBytes   = 16 * 1024
)

// ReturnedCredentialMaterial is a value-free classification of credential
// records observed in one successful, invocation-bound tool result.
type ReturnedCredentialMaterial uint8

const (
	ReturnedCredentialMaterialNone ReturnedCredentialMaterial = 0
	ReturnedCredentialKerberosTGS  ReturnedCredentialMaterial = 1 << iota
	ReturnedCredentialKerberosASREP
	ReturnedCredentialNTDSRecord
	ReturnedCredentialLabeledNTLM
)

const returnedCredentialMaterialKnown = ReturnedCredentialKerberosTGS |
	ReturnedCredentialKerberosASREP |
	ReturnedCredentialNTDSRecord |
	ReturnedCredentialLabeledNTLM

// ReturnedCredentialSource is a value-free description of the exact
// credential-acquisition operation whose result may be classified. It is
// deliberately narrower than the atomic directory-acquisition signal: only a
// single, direct, unconditional and completely parsed invocation qualifies.
type ReturnedCredentialSource uint8

const (
	ReturnedCredentialSourceNone ReturnedCredentialSource = iota
	ReturnedCredentialSourceSecretsDump
	ReturnedCredentialSourceKerberoast
	ReturnedCredentialSourceASREPRoast
	ReturnedCredentialSourceFileRead
)

var (
	returnedKerberosTGSLine = regexp.MustCompile(
		`(?i)^\$krb5tgs\$(?:17|18|23)\$\*?[^\s$:*]{1,128}\$[^\s$]{1,255}\$[^\s$]{1,1000}\*?\$[0-9a-f]{32,96}\$[0-9a-f]{64,}$`,
	)
	returnedKerberosASREPLine = regexp.MustCompile(
		`(?i)^\$krb5asrep\$(?:17|18|23)\$[^\s:$]{1,128}(?:@[^\s:$]{1,255})?:[0-9a-f]{32,96}\$[0-9a-f]{64,}$`,
	)
	returnedNTDSLine = regexp.MustCompile(
		`(?i)^(?:[^:\s]{1,128}\\)?[^:\s]{1,128}:[0-9]{1,10}:(?:[0-9a-f]{32}|\*):(?:[0-9a-f]{32}|\*):::$`,
	)
	returnedLabeledNTLMLine = regexp.MustCompile(
		`(?i)^(?:[^:\r\n]{1,128}\s+)?(?:ntlm|nt[ _-]?hash)\s*[:=]\s*[0-9a-f]{32}$`,
	)
	returnedCredentialTelemetryMarker = regexp.MustCompile(
		`(?i)(?:ntlm|nt[ _-]?hash)\s*[:=]|:[0-9]{1,10}:(?:[0-9a-f]{32}|\*):(?:[0-9a-f]{32}|\*):::`,
	)
)

// ClassifyReturnedCredentialMaterial recognizes complete credential record
// shapes without returning, hashing, logging, or retaining any matched value.
// The caller must separately prove a successful result and exact invocation
// lineage to a reviewed credential-acquisition action.
func ClassifyReturnedCredentialMaterial(result []byte) ReturnedCredentialMaterial {
	if len(result) == 0 || len(result) > MaxReturnedCredentialResultBytes ||
		bytes.IndexByte(result, 0) >= 0 {
		return ReturnedCredentialMaterialNone
	}
	var material ReturnedCredentialMaterial
	for _, rawLine := range bytes.Split(result, []byte{'\n'}) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		if len(line) > maxReturnedCredentialLineBytes {
			return ReturnedCredentialMaterialNone
		}
		switch {
		case returnedKerberosTGSLine.Match(line):
			material |= ReturnedCredentialKerberosTGS
		case returnedKerberosASREPLine.Match(line):
			material |= ReturnedCredentialKerberosASREP
		case returnedNTDSLine.Match(line):
			material |= ReturnedCredentialNTDSRecord
		case returnedLabeledNTLMLine.Match(line):
			material |= ReturnedCredentialLabeledNTLM
		}
	}
	return material & returnedCredentialMaterialKnown
}

// ReturnedCredentialTelemetrySensitive is a deliberately broader privacy
// boundary than ClassifyReturnedCredentialMaterial. Detection abstains when
// input limits or exact record grammar are not satisfied; telemetry must not
// expose a likely credential merely because that stricter classifier abstains.
// The loose marker scan remains linear and examines the complete value so a
// credential beyond the strict classifier's size boundary is still redacted.
func ReturnedCredentialTelemetrySensitive(result []byte) bool {
	if len(result) == 0 {
		return false
	}
	return ClassifyReturnedCredentialMaterial(result).Valid() ||
		containsASCIIFold(result, []byte("$krb5tgs$")) ||
		containsASCIIFold(result, []byte("$krb5asrep$")) ||
		returnedCredentialTelemetryMarker.Match(result)
}

func containsASCIIFold(value, marker []byte) bool {
	if len(marker) == 0 || len(value) < len(marker) {
		return false
	}
	for offset := 0; offset <= len(value)-len(marker); offset++ {
		if bytes.EqualFold(value[offset:offset+len(marker)], marker) {
			return true
		}
	}
	return false
}

// Valid reports whether the classification contains at least one known,
// value-free credential material class.
func (material ReturnedCredentialMaterial) Valid() bool {
	return material != ReturnedCredentialMaterialNone &&
		material&^returnedCredentialMaterialKnown == 0
}

// ExactReturnedCredentialSource returns a closed source class only when one
// direct invocation completely proves the acquisition operation. Pipelines,
// wrappers, redirects, compound actions, dynamic argv and structured actions
// with any competing command facts abstain.
func ExactReturnedCredentialSource(facts Facts) ReturnedCredentialSource {
	if facts.Parse.Status != StatusComplete || !facts.Authoritative() {
		return ReturnedCredentialSourceNone
	}
	if len(facts.DirectoryCredentialAcquisitions) == 0 {
		if exactReturnedCredentialFileRead(facts) {
			return ReturnedCredentialSourceFileRead
		}
		return ReturnedCredentialSourceNone
	}
	if len(facts.DirectoryCredentialAcquisitions) != 1 {
		return ReturnedCredentialSourceNone
	}
	acquisition := facts.DirectoryCredentialAcquisitions[0]
	if acquisition.CommandID == 0 {
		if len(facts.Commands) != 0 {
			return ReturnedCredentialSourceNone
		}
	} else {
		if len(facts.Commands) != 1 {
			return ReturnedCredentialSourceNone
		}
		command := facts.Commands[0]
		if command.ID != acquisition.CommandID || command.ParentCommandID != 0 ||
			command.PipelineID != 0 || command.ControlFlowUncertain ||
			command.Effect != EffectExecute || !command.ArgvComplete ||
			len(command.Redirects) != 0 || len(command.Wrappers) != 0 {
			return ReturnedCredentialSourceNone
		}
	}
	switch acquisition.Operation {
	case DirectoryCredentialSecretsDump:
		return ReturnedCredentialSourceSecretsDump
	case DirectoryCredentialKerberoast:
		return ReturnedCredentialSourceKerberoast
	case DirectoryCredentialASREPRoast:
		return ReturnedCredentialSourceASREPRoast
	default:
		// Offline cracking is intentionally excluded: returned hashes do not
		// prove that a password was recovered.
		return ReturnedCredentialSourceNone
	}
}

func exactReturnedCredentialFileRead(facts Facts) bool {
	if len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.ID == 0 || command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || command.Effect != EffectExecute ||
		!command.ArgvComplete || len(command.Argv) != 2 ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		!hasFactOperation(command, OperationRead) {
		return false
	}
	switch command.Program {
	case "cat", "type", "get-content", "gc":
	default:
		return false
	}
	reads := 0
	for _, path := range facts.Paths {
		if path.CommandID != command.ID || path.Access != PathAccessRead ||
			path.Value == "" {
			return false
		}
		reads++
	}
	return reads == 1
}

// MatchesReturnedCredentialMaterial proves the only accepted source/result
// correspondences. Extra material classes are allowed because a successful
// credential-dump result may contain more than one recognized record type.
func MatchesReturnedCredentialMaterial(
	source ReturnedCredentialSource,
	material ReturnedCredentialMaterial,
) bool {
	if !material.Valid() {
		return false
	}
	switch source {
	case ReturnedCredentialSourceSecretsDump:
		return material&(ReturnedCredentialNTDSRecord|ReturnedCredentialLabeledNTLM) != 0
	case ReturnedCredentialSourceKerberoast:
		return material&ReturnedCredentialKerberosTGS != 0
	case ReturnedCredentialSourceASREPRoast:
		return material&ReturnedCredentialKerberosASREP != 0
	case ReturnedCredentialSourceFileRead:
		return material.Valid()
	default:
		return false
	}
}
