// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

const (
	kerberosS4UTargetDigestDomain   = "defenseclaw/actionfacts/kerberos-s4u/target/v1"
	kerberosS4USPNDigestDomain      = "defenseclaw/actionfacts/kerberos-s4u/spn/v1"
	kerberosS4UArtifactDigestDomain = "defenseclaw/actionfacts/kerberos-s4u/artifact/v1"
	kerberosS4UResultMaxBytes       = 256 * 1024
	kerberosS4UResultLineMaxBytes   = 16 * 1024
)

const (
	kerberosS4UImpersonatingPrefix = "[*] Impersonating "
	kerberosS4USelfLine            = "[*] Requesting S4U2self"
	kerberosS4UProxyLine           = "[*] Requesting S4U2Proxy"
	kerberosS4USavingPrefix        = "[*] Saving ticket in "
)

// KerberosS4UTicketRequestFact is the value-free projection of one exact
// Impacket S4U ticket request. The source account and its credential are
// validated but deliberately discarded.
type KerberosS4UTicketRequestFact struct {
	CommandID                      int64
	TargetPrincipalIdentityDigest  string
	ServicePrincipalIdentityDigest string
}

// KerberosS4USecretsDumpFact is the value-free projection of an exact
// KRB5CCNAME-bound, Kerberos-only secretsdump invocation.
type KerberosS4USecretsDumpFact struct {
	TicketArtifactIdentityDigest  string
	TargetPrincipalIdentityDigest string
}

// ExactKerberosS4UTicketRequest recognizes one direct, unconditional
// impacket-getST/getST.py invocation using only the option orderings observed
// in the pinned Cochise trajectories. Result evidence is intentionally joined
// by the caller after the tool completes.
func ExactKerberosS4UTicketRequest(
	facts Facts,
) (KerberosS4UTicketRequestFact, bool) {
	if !kerberosS4UParseEligible(facts.Parse) || len(facts.Commands) != 1 {
		return KerberosS4UTicketRequestFact{}, false
	}
	command := facts.Commands[0]
	if command.ID == 0 || !exactUnconditionalTopLevelCommand(command) ||
		!command.ArgvComplete {
		return KerberosS4UTicketRequestFact{}, false
	}
	program := strings.ToLower(command.Program)
	if program != "impacket-getst" && program != "getst.py" {
		return KerberosS4UTicketRequestFact{}, false
	}

	spn, target, source, dcIP, ok := exactKerberosS4URequestArguments(
		command.Argv[1:],
	)
	if !ok || !validKerberosTicketSPN(spn) ||
		!validKerberosTicketPrincipal(target) ||
		!exactKerberosS4USourceCredential(source) ||
		(dcIP != "" && !exactADCSIPAddress(dcIP)) {
		return KerberosS4UTicketRequestFact{}, false
	}
	targetDigest := KerberosS4UTargetPrincipalIdentityDigest(target)
	spnDigest := framedPrivateDigest(
		kerberosS4USPNDigestDomain, strings.ToLower(spn),
	)
	if targetDigest == "" || !validPrivateDigest(spnDigest) {
		return KerberosS4UTicketRequestFact{}, false
	}
	return KerberosS4UTicketRequestFact{
		CommandID:                      command.ID,
		TargetPrincipalIdentityDigest:  targetDigest,
		ServicePrincipalIdentityDigest: spnDigest,
	}, true
}

func exactKerberosS4URequestArguments(
	args []string,
) (spn, target, source, dcIP string, ok bool) {
	switch {
	case len(args) == 5 && args[0] == "-spn" && args[2] == "-impersonate":
		return args[1], args[3], args[4], "", true
	case len(args) == 7 && args[0] == "-dc-ip" && args[2] == "-spn" &&
		args[4] == "-impersonate":
		return args[3], args[5], args[6], args[1], true
	case len(args) == 7 && args[0] == "-spn" && args[2] == "-dc-ip" &&
		args[4] == "-impersonate":
		return args[1], args[5], args[6], args[3], true
	case len(args) == 7 && args[0] == "-spn" && args[2] == "-impersonate" &&
		args[4] == "-dc-ip":
		return args[1], args[3], args[6], args[5], true
	default:
		return "", "", "", "", false
	}
}

func exactKerberosS4USourceCredential(value string) bool {
	if len(value) > maxScalarBytes || strings.Count(value, "/") != 1 ||
		unresolvedCredentialLineageScalar(value) {
		return false
	}
	parts := strings.SplitN(value, "/", 2)
	separator := strings.IndexByte(parts[1], ':')
	if separator <= 0 || separator == len(parts[1])-1 {
		return false
	}
	source, credential := parts[1][:separator], parts[1][separator+1:]
	return validKerberosTicketDomain(parts[0]) &&
		validKerberosTicketPrincipal(source) && exactADCSCredential(credential)
}

func kerberosS4UParseEligible(parse ParseResult) bool {
	if parse.Status == StatusComplete {
		return len(parse.Issues) == 0
	}
	return parse.Status == StatusPartial && len(parse.Issues) == 1 &&
		parse.Issues[0] == IssueUnknownOperandGrammar
}

// KerberosS4UTargetPrincipalIdentityDigest returns the private identity used
// to bind a request's -impersonate value to the exact result principal.
func KerberosS4UTargetPrincipalIdentityDigest(principal string) string {
	if !validKerberosTicketPrincipal(principal) {
		return ""
	}
	return framedPrivateDigest(
		kerberosS4UTargetDigestDomain, strings.ToLower(principal),
	)
}

// KerberosS4UTicketArtifactIdentityDigest returns the private, case-sensitive
// identity of one static Impacket S4U cache basename. Paths, traversal,
// expansions, shell syntax, and non-ccache artifacts are rejected.
func KerberosS4UTicketArtifactIdentityDigest(artifact string) string {
	if len(artifact) < len("a.ccache") || len(artifact) > 255 ||
		validateScalar(artifact, 255) != "" ||
		unresolvedCredentialLineageScalar(artifact) ||
		!strings.HasSuffix(artifact, ".ccache") ||
		strings.Contains(artifact, "..") || !asciiAlphaNumeric(artifact[0]) {
		return ""
	}
	for index := range len(artifact) {
		character := artifact[index]
		if !asciiAlphaNumeric(character) &&
			!strings.ContainsRune("._-$@", rune(character)) {
			return ""
		}
	}
	return framedPrivateDigest(kerberosS4UArtifactDigestDomain, artifact)
}

// ExactKerberosS4UTicketResult returns only the one-way identity of a saved
// ccache when a bounded result proves the expected impersonated principal,
// S4U2self, S4U2Proxy, and one saved artifact in that order.
func ExactKerberosS4UTicketResult(
	result []byte,
	expectedTargetPrincipalIdentityDigest string,
) string {
	if len(result) == 0 || len(result) > kerberosS4UResultMaxBytes ||
		bytes.IndexByte(result, 0) >= 0 ||
		!validPrivateDigest(expectedTargetPrincipalIdentityDigest) {
		return ""
	}
	stage := 0
	artifactDigest := ""
	for _, rawLine := range bytes.Split(result, []byte{'\n'}) {
		lineBytes := bytes.TrimSpace(rawLine)
		if len(lineBytes) == 0 {
			continue
		}
		if len(lineBytes) > kerberosS4UResultLineMaxBytes {
			return ""
		}
		line := string(lineBytes)
		lower := strings.ToLower(line)
		if strings.HasPrefix(line, "[-]") ||
			strings.HasPrefix(lower, "error:") ||
			strings.HasPrefix(lower, "fatal:") ||
			strings.HasPrefix(lower, "traceback (most recent call last):") ||
			strings.Contains(lower, "kdc_err_") {
			return ""
		}
		switch {
		case strings.HasPrefix(line, kerberosS4UImpersonatingPrefix):
			if stage != 0 || KerberosS4UTargetPrincipalIdentityDigest(
				strings.TrimPrefix(line, kerberosS4UImpersonatingPrefix),
			) != expectedTargetPrincipalIdentityDigest {
				return ""
			}
			stage = 1
		case strings.HasPrefix(line, "[*] Impersonating"):
			return ""
		case line == kerberosS4USelfLine:
			if stage != 1 {
				return ""
			}
			stage = 2
		case strings.HasPrefix(line, "[*] Requesting S4U2self"):
			return ""
		case line == kerberosS4UProxyLine:
			if stage != 2 {
				return ""
			}
			stage = 3
		case strings.HasPrefix(line, "[*] Requesting S4U2Proxy"):
			return ""
		case strings.HasPrefix(line, kerberosS4USavingPrefix):
			if stage != 3 || artifactDigest != "" {
				return ""
			}
			artifactDigest = KerberosS4UTicketArtifactIdentityDigest(
				strings.TrimPrefix(line, kerberosS4USavingPrefix),
			)
			if artifactDigest == "" {
				return ""
			}
			stage = 4
		case strings.HasPrefix(line, "[*] Saving ticket in"):
			return ""
		}
	}
	if stage != 4 {
		return ""
	}
	return artifactDigest
}

// ExactKerberosS4USecretsDumpSink recognizes one direct POSIX command with
// exactly one static KRB5CCNAME prefix assignment and one Kerberos-only
// impacket-secretsdump/secretsdump.py invocation. It parses the shell AST so
// the assignment is proven without making prefix assignments transparent to
// the generic ActionFacts parser.
func ExactKerberosS4USecretsDumpSink(
	input Input,
) (KerberosS4USecretsDumpFact, bool) {
	commandText, explicitArgv, ok := exactKerberosS4UInputCommand(input)
	if !ok || len(commandText) > maxCommandBytes || !utf8.ValidString(commandText) ||
		strings.IndexByte(commandText, 0) >= 0 {
		return KerberosS4USecretsDumpFact{}, false
	}
	parser := syntax.NewParser(
		syntax.Variant(syntax.LangPOSIX), syntax.KeepComments(true),
	)
	file, err := parser.Parse(strings.NewReader(commandText), "")
	if err != nil || len(file.Stmts) != 1 {
		return KerberosS4USecretsDumpFact{}, false
	}
	bound := newParseOutput(DialectPOSIX, 1)
	if !checkPOSIXBounds(file, &bound) {
		return KerberosS4USecretsDumpFact{}, false
	}
	statement := file.Stmts[0]
	call, ok := statement.Cmd.(*syntax.CallExpr)
	if !ok || statement.Negated || statement.Background || statement.Coprocess ||
		statement.Disown || statement.Semicolon.IsValid() || len(statement.Redirs) != 0 ||
		len(statement.Comments) != 0 || len(call.Assigns) != 1 || len(call.Args) == 0 {
		return KerberosS4USecretsDumpFact{}, false
	}
	assignment := call.Assigns[0]
	if assignment == nil || assignment.Append || assignment.Naked ||
		assignment.Name == nil || assignment.Name.Value != "KRB5CCNAME" ||
		assignment.Index != nil || assignment.Array != nil || assignment.Value == nil {
		return KerberosS4USecretsDumpFact{}, false
	}
	artifact := projectPOSIXWord(assignment.Value)
	artifactDigest := KerberosS4UTicketArtifactIdentityDigest(artifact.Value)
	if artifact.Expands || artifactDigest == "" {
		return KerberosS4USecretsDumpFact{}, false
	}

	argv := make([]string, 0, len(call.Args))
	for _, word := range call.Args {
		argument := projectPOSIXWord(word)
		if argument.Expands || argument.Value == "" ||
			len(argument.Value) > maxScalarBytes {
			return KerberosS4USecretsDumpFact{}, false
		}
		argv = append(argv, argument.Value)
	}
	if len(explicitArgv) != 0 && !equalStrings(explicitArgv, argv) {
		return KerberosS4USecretsDumpFact{}, false
	}
	targetDigest, ok := exactKerberosS4USecretsDumpArguments(argv)
	if !ok {
		return KerberosS4USecretsDumpFact{}, false
	}
	return KerberosS4USecretsDumpFact{
		TicketArtifactIdentityDigest:  artifactDigest,
		TargetPrincipalIdentityDigest: targetDigest,
	}, true
}

func exactKerberosS4UInputCommand(input Input) (string, []string, bool) {
	if input.DialectHint == DialectPowerShell || input.DialectHint == DialectCMD {
		return "", nil, false
	}
	extracted := extractArgsForTool(input.Args, input.Tool)
	if len(extracted.issues) != 0 ||
		(extracted.status != StatusComplete && extracted.status != StatusNotApplicable) {
		return "", nil, false
	}
	commandText := input.Command
	if commandText != "" && extracted.command != "" && commandText != extracted.command {
		return "", nil, false
	}
	if commandText == "" {
		commandText = extracted.command
	}
	argv := cloneSlice(input.Argv)
	if len(argv) != 0 && len(extracted.argv) != 0 && !equalStrings(argv, extracted.argv) {
		return "", nil, false
	}
	if len(argv) == 0 {
		argv = cloneSlice(extracted.argv)
	}
	return commandText, argv, commandText != ""
}

func exactKerberosS4USecretsDumpArguments(argv []string) (string, bool) {
	if len(argv) < 4 ||
		(!strings.EqualFold(commandProgram(argv[0]), "impacket-secretsdump") &&
			!strings.EqualFold(commandProgram(argv[0]), "secretsdump.py")) ||
		argv[1] != "-k" || argv[2] != "-no-pass" {
		return "", false
	}
	seen := make(map[string]struct{}, 5)
	target := ""
	scope := ""
	for index := 3; index < len(argv); index++ {
		argument := argv[index]
		option := strings.ToLower(argument)
		switch option {
		case "-dc-ip", "-target-ip", "-just-dc-user":
			if _, duplicate := seen[option]; duplicate || index+1 >= len(argv) {
				return "", false
			}
			seen[option] = struct{}{}
			value := argv[index+1]
			if option == "-just-dc-user" {
				if scope != "" || !validKerberosTicketPrincipal(value) {
					return "", false
				}
				scope = option
			} else if !exactADCSIPAddress(value) {
				return "", false
			}
			index++
		case "-just-dc", "-just-dc-ntlm":
			if scope != "" {
				return "", false
			}
			scope = option
		case "-k", "-no-pass":
			return "", false
		default:
			if strings.HasPrefix(argument, "-") || target != "" ||
				!exactKerberosS4USecretsDumpTarget(argument) {
				return "", false
			}
			target = argument
		}
	}
	if target == "" {
		return "", false
	}
	at := strings.LastIndexByte(target, '@')
	principal := target[:at]
	if strings.Count(principal, "/") == 1 && !strings.Contains(principal, "\\") {
		principal = strings.Replace(principal, "/", "\\", 1)
	}
	canonicalTarget, canonicalPrincipal, ok := canonicalCredentialRemoteIdentity(
		target[at+1:], principal,
	)
	if !ok {
		return "", false
	}
	digest := credentialRemoteTargetPrincipalDigest(canonicalTarget, canonicalPrincipal)
	return digest, validPrivateDigest(digest)
}

func exactKerberosS4USecretsDumpTarget(value string) bool {
	if len(value) == 0 || len(value) > maxScalarBytes ||
		unresolvedCredentialLineageScalar(value) || strings.Contains(value, ":") ||
		strings.Count(value, "@") != 1 {
		return false
	}
	at := strings.LastIndexByte(value, '@')
	if at <= 0 || at == len(value)-1 {
		return false
	}
	principal := value[:at]
	if strings.Count(principal, "/") == 1 && !strings.Contains(principal, "\\") {
		principal = strings.Replace(principal, "/", "\\", 1)
	}
	_, _, ok := canonicalCredentialRemoteIdentity(value[at+1:], principal)
	return ok
}
