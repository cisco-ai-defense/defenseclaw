// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
)

const (
	compromisedCredentialAccountHMACDomain = "defenseclaw/actionfacts/compromised-credential/account/v1"
	compromisedCredentialValueHMACDomain   = "defenseclaw/actionfacts/compromised-credential/value/v1"
)

// CompromisedCredentialAuthenticationOperation is the closed vocabulary for
// a recorded compromised credential and its later authentication use.
type CompromisedCredentialAuthenticationOperation string

const (
	CompromisedCredentialRecorded CompromisedCredentialAuthenticationOperation = "credential_recorded"
	CompromisedCredentialUsed     CompromisedCredentialAuthenticationOperation = "credential_used"
)

// CompromisedCredentialAuthenticationFact retains process-keyed references
// only. AccountIdentityHMAC and CredentialValueHMAC must both join exactly;
// neither digest is stable across gateway process restarts.
type CompromisedCredentialAuthenticationFact struct {
	Operation           CompromisedCredentialAuthenticationOperation `json:"-"`
	AccountIdentityHMAC string                                       `json:"-"`
	CredentialValueHMAC string                                       `json:"-"`
}

// ExactCompromisedCredentialAuthentication returns one unambiguous closed
// role. Multiple candidate authentications, malformed digests, or mixed roles
// are rejected rather than guessed.
func ExactCompromisedCredentialAuthentication(
	facts Facts,
) (CompromisedCredentialAuthenticationFact, bool) {
	if len(facts.CompromisedCredentialAuthentications) != 1 {
		return CompromisedCredentialAuthenticationFact{}, false
	}
	fact := facts.CompromisedCredentialAuthentications[0]
	if fact.Operation != CompromisedCredentialRecorded &&
		fact.Operation != CompromisedCredentialUsed ||
		!validPrivateDigest(fact.AccountIdentityHMAC) ||
		!validPrivateDigest(fact.CredentialValueHMAC) {
		return CompromisedCredentialAuthenticationFact{}, false
	}
	return fact, true
}

func projectCompromisedCredentialAuthentications(
	input Input,
	facts Facts,
) []CompromisedCredentialAuthenticationFact {
	if input.CredentialLineageHMACKey == ([sha256.Size]byte{}) {
		return nil
	}
	if account, credential, ok := exactCompromisedCredentialRecord(input); ok {
		return compromisedCredentialAuthenticationFacts(
			input.CredentialLineageHMACKey,
			CompromisedCredentialRecorded,
			account,
			credential,
		)
	}
	if !compromisedCredentialAuthenticationParseEligible(facts.Parse) {
		return nil
	}

	var candidate CompromisedCredentialAuthenticationFact
	found := false
	for _, command := range facts.Commands {
		account, credential, ok := exactNetExecCredentialAuthentication(command)
		if !ok {
			continue
		}
		projected := compromisedCredentialAuthenticationFacts(
			input.CredentialLineageHMACKey,
			CompromisedCredentialUsed,
			account,
			credential,
		)
		if len(projected) != 1 || found {
			// Two authentication commands in one action are an ambiguous terminal,
			// even when they happen to repeat the same literal values.
			return nil
		}
		candidate = projected[0]
		found = true
	}
	if !found {
		return nil
	}
	return []CompromisedCredentialAuthenticationFact{candidate}
}

func exactCompromisedCredentialRecord(input Input) (string, string, bool) {
	tool := strings.ToLower(input.Tool)
	if tool != "add_compromised_account" && tool != "update_compromised_account" ||
		input.Command != "" || len(input.Argv) != 0 || len(input.Args) == 0 ||
		len(input.Args) > maxArgsJSONBytes ||
		validateJSONWithStringLimit(input.Args, maxCommandBytes) != "" {
		return "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return "", "", false
	}
	wantFields := 2
	if tool == "update_compromised_account" {
		wantFields = 3
	}
	if len(object) != wantFields {
		return "", "", false
	}
	for key := range object {
		if key != "username" && key != "password" &&
			!(tool == "update_compromised_account" && key == "key") {
			return "", "", false
		}
	}
	username, usernameOK := exactCredentialRemoteString(object, "username", maxScalarBytes)
	credential, credentialOK := exactCredentialRemoteString(object, "password", maxCommandBytes)
	if !usernameOK || !credentialOK || unresolvedCredentialLineageScalar(credential) {
		return "", "", false
	}
	if tool == "update_compromised_account" {
		key, keyOK := exactCredentialRemoteString(object, "key", maxScalarBytes)
		if !keyOK || unresolvedCredentialLineageScalar(key) {
			return "", "", false
		}
	}
	account, ok := canonicalCompromisedCredentialAccount(username, "")
	return account, credential, ok
}

func exactNetExecCredentialAuthentication(command CommandFact) (string, string, bool) {
	if command.Effect != EffectExecute || command.ControlFlowUncertain ||
		len(command.Argv) < 5 {
		return "", "", false
	}
	program := strings.ToLower(command.Program)
	if program != "nxc" && program != "netexec" && program != "crackmapexec" {
		return "", "", false
	}
	argv := command.Argv
	protocol := strings.ToLower(argv[1])
	switch protocol {
	case "smb", "ldap", "winrm", "mssql", "ssh", "rdp":
	default:
		return "", "", false
	}

	username, credential, domain := "", "", ""
	targets := 0
	seenOption := false
	for index := 2; index < len(argv); index++ {
		argument := argv[index]
		if unresolvedCredentialLineageScalar(argument) {
			return "", "", false
		}
		if !strings.HasPrefix(argument, "-") {
			if seenOption {
				return "", "", false
			}
			targets++
			continue
		}
		seenOption = true
		lower := strings.ToLower(argument)
		switch argument {
		case "-H":
			if index+1 >= len(argv) || strings.HasPrefix(argv[index+1], "-") ||
				unresolvedCredentialLineageScalar(argv[index+1]) || credential != "" {
				return "", "", false
			}
			credential = argv[index+1]
			index++
			continue
		}
		switch lower {
		case "-u", "--username", "-p", "--password", "--hash",
			"-d", "--domain", "-m", "-o", "-x":
			if index+1 >= len(argv) || strings.HasPrefix(argv[index+1], "-") ||
				unresolvedCredentialLineageScalar(argv[index+1]) {
				return "", "", false
			}
			value := argv[index+1]
			index++
			switch lower {
			case "-u", "--username":
				if username != "" {
					return "", "", false
				}
				username = value
			case "-p", "--password", "--hash":
				if credential != "" {
					return "", "", false
				}
				credential = value
			case "-d", "--domain":
				if domain != "" {
					return "", "", false
				}
				domain = value
			}
		case "--shares", "--groups", "--users", "--trusted-for-delegation",
			"--dc-list", "--local-auth":
		default:
			return "", "", false
		}
	}
	if targets == 0 || username == "" || credential == "" {
		return "", "", false
	}
	account, ok := canonicalCompromisedCredentialAccount(username, domain)
	return account, credential, ok
}

func compromisedCredentialAuthenticationParseEligible(parse ParseResult) bool {
	if parse.Status != StatusComplete && parse.Status != StatusPartial {
		return false
	}
	for _, issue := range parse.Issues {
		if issue != IssueUnknownOperandGrammar {
			return false
		}
	}
	return true
}

func canonicalCompromisedCredentialAccount(value, explicitDomain string) (string, bool) {
	if unresolvedCredentialLineageScalar(value) ||
		(explicitDomain != "" && unresolvedCredentialLineageScalar(explicitDomain)) {
		return "", false
	}
	if strings.Count(value, "/") == 1 && !strings.Contains(value, "\\") &&
		!strings.Contains(value, "@") {
		value = strings.Replace(value, "/", "\\", 1)
	}
	_, principal, ok := canonicalCredentialRemoteIdentityWithDomain(
		"identity.fixture", value, explicitDomain,
	)
	return principal, ok
}

func unresolvedCredentialLineageScalar(value string) bool {
	lower := strings.ToLower(value)
	return value == "" || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\x00\r\n`*?[]{}<>") ||
		strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.Contains(value, "#{") || strings.Contains(value, "%{") ||
		strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "your_username") ||
		strings.Contains(lower, "your_password")
}

func compromisedCredentialAuthenticationFacts(
	key [sha256.Size]byte,
	operation CompromisedCredentialAuthenticationOperation,
	account, credential string,
) []CompromisedCredentialAuthenticationFact {
	accountHMAC := compromisedCredentialHMAC(
		key, compromisedCredentialAccountHMACDomain, account,
	)
	credentialHMAC := compromisedCredentialHMAC(
		key, compromisedCredentialValueHMACDomain, credential,
	)
	if accountHMAC == "" || credentialHMAC == "" {
		return nil
	}
	return []CompromisedCredentialAuthenticationFact{{
		Operation: operation, AccountIdentityHMAC: accountHMAC,
		CredentialValueHMAC: credentialHMAC,
	}}
}

func compromisedCredentialHMAC(
	key [sha256.Size]byte,
	domain, value string,
) string {
	if key == ([sha256.Size]byte{}) || domain == "" || value == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key[:])
	for _, component := range []string{domain, value} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(component)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write([]byte(component))
	}
	return hex.EncodeToString(mac.Sum(nil))
}
