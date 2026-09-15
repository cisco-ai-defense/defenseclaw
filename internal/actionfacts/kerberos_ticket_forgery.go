// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strconv"
	"strings"
)

const kerberosTicketArtifactDigestDomain = "defenseclaw/actionfacts/kerberos-ticket-forgery/artifact/v1"

// KerberosTicketForgeryFact is the value-free projection of one exact
// impacket-ticketer invocation. The key, domain, SIDs, principal, and artifact
// name are deliberately discarded. ExpectedArtifactIdentityDigest lets a
// result-bound caller prove that Impacket saved the ticket for the invocation's
// final principal without retaining any of those values.
type KerberosTicketForgeryFact struct {
	CommandID                      int64
	ExpectedArtifactIdentityDigest string
}

// ExactKerberosTicketForgerySource recognizes one direct, unconditional and
// completely parsed impacket-ticketer/ticketer.py invocation. It accepts only
// the closed option grammar observed in the pinned Cochise trajectories and
// requires exactly one cryptographic key source. Successful result evidence is
// intentionally outside ActionFacts and must be joined by the caller.
func ExactKerberosTicketForgerySource(
	facts Facts,
) (KerberosTicketForgeryFact, bool) {
	if !kerberosTicketForgeryParseEligible(facts.Parse) || len(facts.Commands) != 1 {
		return KerberosTicketForgeryFact{}, false
	}
	if facts.Commands[0].ID == 0 {
		return KerberosTicketForgeryFact{}, false
	}
	return exactKerberosTicketForgeryCommand(facts.Commands[0])
}

func exactKerberosTicketForgeryCommand(
	command CommandFact,
) (KerberosTicketForgeryFact, bool) {
	// POSIX and argv parser internals use the zero value for process commands;
	// the public Facts projection normalizes it after classification. Normalize
	// the local copy here so this closed grammar can participate in that same
	// classification pass without weakening the exported structural check.
	if command.Kind == "" {
		command.Kind = CommandKindProcess
	}
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		len(command.Argv) < 8 {
		return KerberosTicketForgeryFact{}, false
	}
	program := strings.ToLower(command.Program)
	if program != "impacket-ticketer" && program != "ticketer.py" {
		return KerberosTicketForgeryFact{}, false
	}

	seen := make(map[string]struct{}, 8)
	hasKey, hasDomainSID, hasDomain := false, false, false
	principal := ""
	for index := 1; index < len(command.Argv); {
		argument := command.Argv[index]
		if !strings.HasPrefix(argument, "-") {
			// Argparse permits closed options after the positional. Identity is
			// still exact because this grammar accepts exactly one principal and
			// every recognized option consumes exactly one bounded value.
			if principal != "" || !validKerberosTicketPrincipal(argument) {
				return KerberosTicketForgeryFact{}, false
			}
			principal = argument
			index++
			continue
		}

		option := strings.ToLower(argument)
		if _, duplicate := seen[option]; duplicate || index+1 >= len(command.Argv) {
			return KerberosTicketForgeryFact{}, false
		}
		seen[option] = struct{}{}
		value := command.Argv[index+1]
		if strings.HasPrefix(value, "-") {
			return KerberosTicketForgeryFact{}, false
		}

		switch option {
		case "-nthash":
			if hasKey || !exactASCIIHex(value, 32) {
				return KerberosTicketForgeryFact{}, false
			}
			hasKey = true
		case "-aeskey":
			if hasKey || (!exactASCIIHex(value, 32) && !exactASCIIHex(value, 64)) {
				return KerberosTicketForgeryFact{}, false
			}
			hasKey = true
		case "-domain-sid":
			if !validKerberosDomainSID(value) {
				return KerberosTicketForgeryFact{}, false
			}
			hasDomainSID = true
		case "-domain":
			if !validKerberosTicketDomain(value) {
				return KerberosTicketForgeryFact{}, false
			}
			hasDomain = true
		case "-extra-sid":
			if !validKerberosExtraSID(value) {
				return KerberosTicketForgeryFact{}, false
			}
		case "-spn":
			if !validKerberosTicketSPN(value) {
				return KerberosTicketForgeryFact{}, false
			}
		case "-user-id":
			if !validKerberosTicketRID(value) {
				return KerberosTicketForgeryFact{}, false
			}
		case "-groups":
			if !validKerberosTicketGroups(value) {
				return KerberosTicketForgeryFact{}, false
			}
		case "-user":
			if !validKerberosTicketPrincipal(value) {
				return KerberosTicketForgeryFact{}, false
			}
		default:
			return KerberosTicketForgeryFact{}, false
		}
		index += 2
	}

	artifactDigest := KerberosTicketArtifactIdentity(principal + ".ccache")
	if !hasKey || !hasDomainSID || !hasDomain || principal == "" ||
		artifactDigest == "" {
		return KerberosTicketForgeryFact{}, false
	}
	return KerberosTicketForgeryFact{
		CommandID: command.ID, ExpectedArtifactIdentityDigest: artifactDigest,
	}, true
}

func kerberosTicketForgeryParseEligible(parse ParseResult) bool {
	if parse.Status == StatusComplete {
		return len(parse.Issues) == 0
	}
	return parse.Status == StatusPartial && len(parse.Issues) == 1 &&
		parse.Issues[0] == IssueUnknownOperandGrammar
}

// KerberosTicketArtifactIdentity returns the value-free identity used to join
// an invocation to an exact Impacket "Saving ticket in <name>.ccache" result.
// Paths are rejected because ticketer names the output from the final principal
// in the process working directory; accepting a path would weaken that join.
func KerberosTicketArtifactIdentity(artifact string) string {
	if len(artifact) < len("a.ccache") || len(artifact) > 135 ||
		!strings.HasSuffix(artifact, ".ccache") ||
		strings.ContainsAny(artifact, "/\\\x00\r\n\t `'&|;*?[]{}<>") {
		return ""
	}
	principal := strings.TrimSuffix(artifact, ".ccache")
	if !validKerberosTicketPrincipal(principal) {
		return ""
	}
	return framedPrivateDigest(kerberosTicketArtifactDigestDomain, artifact)
}

func validKerberosDomainSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 7 || !strings.EqualFold(parts[0], "S") ||
		parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	for _, component := range parts[4:] {
		if !validKerberosUnsigned(component, 10, 1, 4_294_967_295) {
			return false
		}
	}
	return true
}

func validKerberosExtraSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 8 || !strings.EqualFold(parts[0], "S") ||
		parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	for _, component := range parts[4:] {
		if !validKerberosUnsigned(component, 10, 1, 4_294_967_295) {
			return false
		}
	}
	return true
}

func validKerberosTicketDomain(value string) bool {
	if len(value) == 0 || len(value) > 253 ||
		unresolvedCredentialLineageScalar(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 ||
			!asciiAlphaNumeric(label[0]) ||
			!asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validKerberosTicketPrincipal(value string) bool {
	if len(value) == 0 || len(value) > 128 ||
		unresolvedCredentialLineageScalar(value) || !asciiAlphaNumeric(value[0]) {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character == '$' && index != len(value)-1 {
			return false
		}
		if !asciiAlphaNumeric(character) && !strings.ContainsRune("._-$", rune(character)) {
			return false
		}
	}
	return true
}

func validKerberosTicketSPN(value string) bool {
	if len(value) == 0 || len(value) > 255 ||
		unresolvedCredentialLineageScalar(value) || strings.Count(value, "/") != 1 {
		return false
	}
	parts := strings.SplitN(value, "/", 2)
	return validKerberosTicketPrincipal(parts[0]) &&
		validKerberosTicketDomain(parts[1])
}

func validKerberosTicketRID(value string) bool {
	return validKerberosUnsigned(value, 10, 1, 4_294_967_295)
}

func validKerberosTicketGroups(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) == 0 || len(parts) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if !validKerberosTicketRID(part) {
			return false
		}
		if _, duplicate := seen[part]; duplicate {
			return false
		}
		seen[part] = struct{}{}
	}
	return true
}

func validKerberosUnsigned(
	value string,
	maxDigits int,
	minimum, maximum uint64,
) bool {
	if len(value) == 0 || len(value) > maxDigits {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(value, 10, 64)
	return err == nil && number >= minimum && number <= maximum
}

func exactASCIIHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') &&
			(character < 'A' || character > 'F') {
			return false
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}
