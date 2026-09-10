// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
	"unicode/utf8"
)

const credentialRemoteExecutionDigestDomain = "defenseclaw/actionfacts/credential-remote-execution/v1"

var (
	credentialRemoteHostnamePattern = regexp.MustCompile(
		`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$`,
	)
	credentialRemotePrincipalPattern = regexp.MustCompile(
		`(?i)^(?:[a-z0-9][a-z0-9._-]{0,63}\\)?[a-z0-9][a-z0-9._@$-]{0,127}$|^[a-z0-9][a-z0-9._$-]{0,63}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`,
	)
)

// ExactCredentialRemoteExecutionOperation returns one exact value-free role
// and one opaque target/principal join. It never returns a target, principal,
// method, domain, command, or credential value.
func ExactCredentialRemoteExecutionOperation(
	facts Facts,
) (CredentialRemoteExecutionOperation, string, bool) {
	if len(facts.CredentialRemoteExecutionOperations) != 1 {
		return "", "", false
	}
	fact := facts.CredentialRemoteExecutionOperations[0]
	switch fact.Operation {
	case CredentialExtractionSecretsdump, CredentialRemoteExecutionPsExec:
	default:
		return "", "", false
	}
	if !validPrivateDigest(fact.TargetPrincipalIdentityDigest) {
		return "", "", false
	}
	return fact.Operation, fact.TargetPrincipalIdentityDigest, true
}

func projectCredentialRemoteExecutionOperations(
	input Input,
) []CredentialRemoteExecutionOperationFact {
	var operation CredentialRemoteExecutionOperation
	var target, principal string
	var ok bool
	switch input.Tool {
	case "secretsdump":
		target, principal, ok = exactSecretsdumpStructuredInput(input)
		operation = CredentialExtractionSecretsdump
	case "psexec":
		target, principal, ok = exactPsExecStructuredInput(input)
		operation = CredentialRemoteExecutionPsExec
	default:
		return nil
	}
	if !ok {
		return nil
	}
	digest := credentialRemoteTargetPrincipalDigest(target, principal)
	if digest == "" {
		return nil
	}
	return []CredentialRemoteExecutionOperationFact{{
		Operation: operation, TargetPrincipalIdentityDigest: digest,
	}}
}

func exactSecretsdumpStructuredInput(input Input) (string, string, bool) {
	object, ok := exactCredentialRemoteJSONObject(input)
	if !ok || (len(object) != 3 && len(object) != 5) {
		return "", "", false
	}
	method, methodOK := exactCredentialRemoteString(object, "method", maxScalarBytes)
	target, targetOK := exactCredentialRemoteString(object, "target", maxScalarBytes)
	principal, principalOK := exactCredentialRemoteString(object, "username", maxScalarBytes)
	if !methodOK || !targetOK || !principalOK ||
		(method != "dcsync" && method != "lsa" && method != "sam") {
		return "", "", false
	}
	domain := ""
	for key := range object {
		switch key {
		case "method", "target", "username":
		case "domain", "password":
			if len(object) != 5 {
				return "", "", false
			}
			value, valueOK := exactCredentialRemoteString(object, key, maxCommandBytes)
			if !valueOK || unresolvedCredentialRemoteScalar(value) {
				return "", "", false
			}
			if key == "domain" {
				domain = value
			}
		default:
			return "", "", false
		}
	}
	if len(object) == 5 {
		if _, domainOK := object["domain"]; !domainOK {
			return "", "", false
		}
		if _, passwordOK := object["password"]; !passwordOK {
			return "", "", false
		}
	}
	return canonicalCredentialRemoteIdentityWithDomain(target, principal, domain)
}

func exactPsExecStructuredInput(input Input) (string, string, bool) {
	object, ok := exactCredentialRemoteJSONObject(input)
	if !ok || (len(object) != 3 && len(object) != 4) {
		return "", "", false
	}
	command, commandOK := exactCredentialRemoteString(object, "command", maxCommandBytes)
	target, targetOK := exactCredentialRemoteString(object, "target", maxScalarBytes)
	principal, principalOK := exactCredentialRemoteString(object, "username", maxScalarBytes)
	if !commandOK || !targetOK || !principalOK ||
		unresolvedCredentialRemoteScalar(command) {
		return "", "", false
	}
	for key := range object {
		switch key {
		case "command", "target", "username":
		case "password":
			value, valueOK := exactCredentialRemoteString(object, key, maxCommandBytes)
			if !valueOK || unresolvedCredentialRemoteScalar(value) {
				return "", "", false
			}
		default:
			return "", "", false
		}
	}
	if len(object) == 4 {
		if _, passwordOK := object["password"]; !passwordOK {
			return "", "", false
		}
	}
	return canonicalCredentialRemoteIdentity(target, principal)
}

func exactCredentialRemoteJSONObject(input Input) (map[string]any, bool) {
	if input.Command != "" || len(input.Argv) != 0 || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes || !utf8.Valid(input.Args) ||
		validateJSONWithStringLimit(input.Args, maxCommandBytes) != "" {
		return nil, false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

func exactCredentialRemoteString(
	object map[string]any,
	key string,
	limit int,
) (string, bool) {
	value, ok := object[key].(string)
	return value, ok && value != "" && len(value) <= limit &&
		strings.TrimSpace(value) == value && strings.IndexByte(value, 0) < 0 &&
		!strings.ContainsAny(value, "\r\n")
}

func canonicalCredentialRemoteIdentity(target, principal string) (string, string, bool) {
	return canonicalCredentialRemoteIdentityWithDomain(target, principal, "")
}

func canonicalCredentialRemoteIdentityWithDomain(
	target, principal, explicitDomain string,
) (string, string, bool) {
	if unresolvedCredentialRemoteScalar(target) || unresolvedCredentialRemoteScalar(principal) ||
		!credentialRemotePrincipalPattern.MatchString(principal) {
		return "", "", false
	}
	canonicalTarget := strings.ToLower(target)
	if address, err := netip.ParseAddr(target); err == nil {
		if address.IsUnspecified() || address.IsMulticast() {
			return "", "", false
		}
		canonicalTarget = address.Unmap().String()
	} else {
		if len(target) > 253 || !credentialRemoteHostnamePattern.MatchString(target) {
			return "", "", false
		}
		canonicalTarget = strings.TrimSuffix(canonicalTarget, ".")
		if canonicalTarget == "localhost" || strings.HasSuffix(canonicalTarget, ".localhost") {
			return "", "", false
		}
	}
	canonicalPrincipal, ok := canonicalCredentialRemotePrincipal(principal, explicitDomain)
	if !ok {
		return "", "", false
	}
	return canonicalTarget, canonicalPrincipal, true
}

func canonicalCredentialRemotePrincipal(principal, explicitDomain string) (string, bool) {
	principal = strings.ToLower(principal)
	domain, hasDomain, ok := canonicalCredentialRemoteDomain(explicitDomain)
	if !ok {
		return "", false
	}
	if strings.Contains(principal, "\\") {
		parts := strings.Split(principal, "\\")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
			(hasDomain && parts[0] != domain) {
			return "", false
		}
		return parts[0] + "\\" + parts[1], true
	}
	if strings.Contains(principal, "@") {
		parts := strings.Split(principal, "@")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" ||
			(hasDomain && parts[1] != domain) {
			return "", false
		}
		return parts[1] + "\\" + parts[0], true
	}
	if hasDomain {
		return domain + "\\" + principal, true
	}
	return principal, true
}

func canonicalCredentialRemoteDomain(value string) (string, bool, bool) {
	if value == "" {
		return "", false, true
	}
	if unresolvedCredentialRemoteScalar(value) || len(value) > 253 ||
		!credentialRemoteHostnamePattern.MatchString(value) {
		return "", true, false
	}
	return strings.TrimSuffix(strings.ToLower(value), "."), true, true
}

func unresolvedCredentialRemoteScalar(value string) bool {
	lower := strings.ToLower(value)
	return strings.ContainsAny(value, "`*?[]{}<>") ||
		strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "#{") || strings.Contains(value, "%{") ||
		strings.Contains(lower, "placeholder") || strings.Contains(lower, "your_target") ||
		strings.Contains(lower, "your_username") || strings.Contains(lower, "<target") ||
		strings.Contains(lower, "<username")
}

func credentialRemoteTargetPrincipalDigest(target, principal string) string {
	canonicalTarget, canonicalPrincipal, ok := canonicalCredentialRemoteIdentity(target, principal)
	if !ok {
		return ""
	}
	hash := sha256.New()
	var length [4]byte
	for _, value := range []string{
		credentialRemoteExecutionDigestDomain, canonicalTarget, canonicalPrincipal,
	} {
		binary.BigEndian.PutUint32(length[:], uint32(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(value))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
