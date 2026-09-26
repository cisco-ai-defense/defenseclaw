// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"
)

var directoryCredentialPrograms = map[string]struct{}{
	"crackmapexec":  {},
	"getnpusers.py": {}, "getuserspns.py": {}, "hashcat": {},
	"hashcat.exe": {}, "impacket-getnpusers": {},
	"impacket-getuserspns": {}, "impacket-secretsdump": {},
	"john": {}, "john.exe": {}, "netexec": {}, "nxc": {}, "secretsdump.py": {},
}

// ExactDirectoryCredentialAcquisition reports whether one or more commands in
// the action prove a reviewed credential-acquisition grammar.
func ExactDirectoryCredentialAcquisition(facts Facts) bool {
	if len(facts.DirectoryCredentialAcquisitions) == 0 {
		return false
	}
	for _, fact := range facts.DirectoryCredentialAcquisitions {
		switch fact.Operation {
		case DirectoryCredentialSecretsDump, DirectoryCredentialKerberoast,
			DirectoryCredentialASREPRoast, DirectoryCredentialHashCrack:
		default:
			return false
		}
		if fact.CommandID > 0 {
			continue
		}
		if fact.CommandID != 0 ||
			(facts.Tool != "secretsdump" && facts.Tool != "hashcat_crack" &&
				facts.Tool != "kerberoast") {
			return false
		}
	}
	return true
}

// ExactDirectoryCredentialCompromise reports whether the action proves at least
// one operation that IS the credential compromise: a directory secrets dump or an
// offline Kerberos hash crack. Those have no recoverable benign form and no useful
// result to observe, so they are the enforceable half of the vocabulary.
//
// A mixed action -- for example an AS-REP request whose output is piped to hashcat
// -- satisfies this predicate, because the crack is present.
func ExactDirectoryCredentialCompromise(facts Facts) bool {
	if !ExactDirectoryCredentialAcquisition(facts) {
		return false
	}
	for _, fact := range facts.DirectoryCredentialAcquisitions {
		if fact.Operation == DirectoryCredentialSecretsDump ||
			fact.Operation == DirectoryCredentialHashCrack {
			return true
		}
	}
	return false
}

// ExactDirectoryCredentialTicketRequest reports whether the action proves only
// Kerberos service-ticket or AS-REP requests and no dump or crack.
//
// This half stays non-enforcing deliberately. A ticket request is the step whose
// RESULT the credential.returned_kerberos_tgs lifecycle rule exists to observe:
// blocking the request would prevent the returned TGS from ever being seen, which
// removes a shipped result-backed detection rather than adding one. The two
// predicates are total and mutually exclusive over
// ExactDirectoryCredentialAcquisition, so no proven acquisition loses coverage.
func ExactDirectoryCredentialTicketRequest(facts Facts) bool {
	return ExactDirectoryCredentialAcquisition(facts) &&
		!ExactDirectoryCredentialCompromise(facts)
}

// DirectoryCredentialAcquisitionSafeNegative proves that a complete static
// invocation used a reviewed program name but did not use an acquisition
// grammar. It exists solely to suppress broad regex candidates such as help,
// inventory, unsupported hash modes, and incomplete requests.
func DirectoryCredentialAcquisitionSafeNegative(facts Facts) bool {
	if len(facts.DirectoryCredentialAcquisitions) != 0 {
		return false
	}
	found := false
	for _, command := range facts.Commands {
		if _, candidate := directoryCredentialPrograms[strings.ToLower(command.Program)]; !candidate {
			continue
		}
		found = true
		if _, complete := directoryCredentialStaticArgv(command); !complete {
			return false
		}
	}
	return found
}

func projectDirectoryCredentialAcquisitions(
	input Input,
	facts *Facts,
) []DirectoryCredentialAcquisitionFact {
	if facts == nil {
		return nil
	}
	result := make([]DirectoryCredentialAcquisitionFact, 0, 1)
	if operation, ok := exactStructuredDirectoryCredentialAcquisition(input); ok {
		result = append(result, DirectoryCredentialAcquisitionFact{Operation: operation})
	}
	for index := range facts.Commands {
		command := &facts.Commands[index]
		operation, ok := exactDirectoryCredentialCommand(*command)
		if !ok {
			continue
		}
		addOperation(command, OperationCredentialRead)
		result = append(result, DirectoryCredentialAcquisitionFact{
			CommandID: command.ID,
			Operation: operation,
		})
	}
	// A literal `bash -lc` body is useful detection evidence even though login
	// startup files make the wrapper non-authoritative. Parse only the bounded,
	// statically quoted body and project only this closed acquisition vocabulary;
	// never publish generic nested command/path/network facts or enforcement
	// authority from this compatibility path.
	if len(result) == 0 {
		result = append(result, detectionOnlyBashLoginCredentialAcquisitions(facts)...)
	}
	return result
}

func detectionOnlyBashLoginCredentialAcquisitions(
	facts *Facts,
) []DirectoryCredentialAcquisitionFact {
	if facts == nil || len(facts.Commands) != 1 {
		return nil
	}
	owner := facts.Commands[0]
	if owner.Program != "bash" || !owner.ArgvComplete || len(owner.Argv) != 3 ||
		owner.Argv[1] != "-lc" || strings.TrimSpace(owner.Argv[2]) == "" ||
		owner.ParentCommandID != 0 || owner.PipelineID != 0 ||
		owner.ControlFlowUncertain || owner.Effect != EffectExecute ||
		len(owner.Redirects) != 0 || len(owner.Wrappers) != 0 ||
		!staticArguments(owner.Arguments) ||
		!exactPOSIXProgramIdentity(owner.Executable, owner.Program) {
		return nil
	}
	child := parsePOSIX(owner.Argv[2], 1, 1)
	if child.status == StatusInvalid || child.status == StatusLimitExceeded {
		return nil
	}
	result := make([]DirectoryCredentialAcquisitionFact, 0, 1)
	seen := make(map[DirectoryCredentialAcquisition]struct{}, 3)
	for _, command := range child.commands {
		operation, ok := exactDirectoryCredentialCommand(command)
		if !ok {
			continue
		}
		if _, duplicate := seen[operation]; duplicate {
			continue
		}
		seen[operation] = struct{}{}
		result = append(result, DirectoryCredentialAcquisitionFact{
			CommandID: owner.ID,
			Operation: operation,
		})
	}
	return result
}

func exactStructuredDirectoryCredentialAcquisition(
	input Input,
) (DirectoryCredentialAcquisition, bool) {
	switch input.Tool {
	case "secretsdump":
		operation, _, ok := ExactCredentialRemoteExecutionOperation(Facts{
			CredentialRemoteExecutionOperations: projectCredentialRemoteExecutionOperations(input),
		})
		if ok && operation == CredentialExtractionSecretsdump {
			return DirectoryCredentialSecretsDump, true
		}
		// The remote-execution lineage model intentionally rejects loopback
		// targets. A closed local SAM/LSA extraction is still an exact
		// credential-acquisition fact, but it must not create remote lineage.
		object, objectOK := exactCredentialRemoteJSONObject(input)
		if !objectOK || len(object) != 3 {
			return "", false
		}
		method, methodOK := exactCredentialRemoteString(object, "method", maxScalarBytes)
		target, targetOK := exactCredentialRemoteString(object, "target", maxScalarBytes)
		principal, principalOK := exactCredentialRemoteString(object, "username", maxScalarBytes)
		if !methodOK || (method != "sam" && method != "lsa") || !targetOK ||
			!principalOK || unresolvedCredentialRemoteScalar(principal) {
			return "", false
		}
		switch strings.ToLower(target) {
		case "localhost", "127.0.0.1", "::1":
		default:
			return "", false
		}
		if _, principalOK = canonicalCredentialRemotePrincipal(principal, ""); !principalOK {
			return "", false
		}
		return DirectoryCredentialSecretsDump, true
	case "hashcat_crack":
		object, ok := exactCredentialRemoteJSONObject(input)
		if !ok || (len(object) != 3 && len(object) != 4) {
			return "", false
		}
		attackMode, modeOK := exactCredentialRemoteString(object, "attack_mode", maxScalarBytes)
		hashFile, fileOK := exactCredentialRemoteString(object, "hash_file", maxCommandBytes)
		hashModeNumber, numberOK := object["hash_mode"].(json.Number)
		if !modeOK || (attackMode != "dictionary" && attackMode != "rules") || !fileOK ||
			unresolvedStructuredCredentialPath(hashFile) || !numberOK {
			return "", false
		}
		hashMode, err := strconv.Atoi(string(hashModeNumber))
		if err != nil || !reviewedStructuredHashMode(hashMode) {
			return "", false
		}
		for key := range object {
			switch key {
			case "attack_mode", "hash_file", "hash_mode":
			case "wordlist":
				wordlist, wordlistOK := exactCredentialRemoteString(object, key, maxCommandBytes)
				if !wordlistOK || unresolvedStructuredCredentialPath(wordlist) {
					return "", false
				}
			default:
				return "", false
			}
		}
		return DirectoryCredentialHashCrack, true
	case "kerberoast":
		object, ok := exactCredentialRemoteJSONObject(input)
		if !ok || (len(object) != 1 && len(object) != 2) {
			return "", false
		}
		domain, domainOK := exactCredentialRemoteString(object, "domain", maxScalarBytes)
		if !domainOK || unresolvedCredentialRemoteScalar(domain) ||
			!credentialRemoteHostnamePattern.MatchString(domain) {
			return "", false
		}
		for key := range object {
			switch key {
			case "domain":
			case "target_user":
				user, userOK := exactCredentialRemoteString(object, key, maxScalarBytes)
				if !userOK || unresolvedCredentialRemoteScalar(user) ||
					!credentialRemotePrincipalPattern.MatchString(user) {
					return "", false
				}
			default:
				return "", false
			}
		}
		return DirectoryCredentialKerberoast, true
	default:
		return "", false
	}
}

func unresolvedStructuredCredentialPath(value string) bool {
	return strings.Contains(value, "$") || unresolvedCredentialRemoteScalar(value)
}

func reviewedStructuredHashMode(mode int) bool {
	switch mode {
	case 1000, 5600, 11300, 13100, 18200, 19700, 22000:
		return true
	default:
		return false
	}
}

func exactDirectoryCredentialCommand(
	command CommandFact,
) (DirectoryCredentialAcquisition, bool) {
	argv, argvOK := directoryCredentialStaticArgv(command)
	if !argvOK ||
		(command.Effect != EffectExecute && command.Effect != EffectUncertain) ||
		len(argv) < 2 {
		return "", false
	}
	command.Argv = argv
	command.ArgvComplete = true
	command = unwrapDirectoryCredentialTimeout(command)
	command = unwrapDirectoryCredentialPythonScript(command)
	program := strings.ToLower(command.Program)
	if _, ok := directoryCredentialPrograms[program]; !ok {
		return "", false
	}
	switch program {
	case "crackmapexec", "netexec", "nxc":
		if exactNetExecNTDSDump(command.Argv[1:]) {
			return DirectoryCredentialSecretsDump, true
		}
	case "impacket-secretsdump", "secretsdump.py":
		args := command.Argv[1:]
		if exactCredentialToolTarget(args, secretsDumpValueOptions) ||
			exactLocalSecretsDump(args) {
			return DirectoryCredentialSecretsDump, true
		}
	case "impacket-getuserspns", "getuserspns.py":
		if (hasExactOption(command.Argv[1:], "-request") ||
			hasOptionWithStaticValue(command.Argv[1:], "-request-user")) &&
			exactCredentialToolTarget(command.Argv[1:], directoryRequestValueOptions) {
			return DirectoryCredentialKerberoast, true
		}
	case "impacket-getnpusers", "getnpusers.py":
		args := command.Argv[1:]
		requestsHashes := hasExactOption(args, "-request") ||
			hasExactOptionValue(args, "-format", "hashcat") ||
			hasExactOption(args, "-no-pass") ||
			hasOptionWithStaticValue(args, "-outputfile")
		if requestsHashes &&
			exactCredentialToolTarget(args, directoryRequestValueOptions) {
			return DirectoryCredentialASREPRoast, true
		}
	case "hashcat", "hashcat.exe":
		if exactKerberosHashcatCrack(command.Argv[1:]) {
			return DirectoryCredentialHashCrack, true
		}
	case "john", "john.exe":
		if exactKerberosJohnCrack(command.Argv[1:]) {
			return DirectoryCredentialHashCrack, true
		}
	}
	return "", false
}

func exactKerberosJohnCrack(args []string) bool {
	format := ""
	wordlist := false
	show := false
	positionals := 0
	for index := 0; index < len(args); index++ {
		arg := args[index]
		lower := strings.ToLower(arg)
		if unresolvedCredentialRemoteScalar(arg) || lower == "-h" || lower == "--help" ||
			lower == "--version" {
			return false
		}
		switch {
		case strings.HasPrefix(lower, "--format="):
			format = strings.TrimPrefix(lower, "--format=")
		case strings.HasPrefix(lower, "--wordlist="):
			value := strings.TrimPrefix(arg, "--wordlist=")
			wordlist = value != "" && !unresolvedCredentialRemoteScalar(value)
		case lower == "--show":
			show = true
		case lower == "--format" || lower == "--wordlist":
			if index+1 >= len(args) || unresolvedCredentialRemoteScalar(args[index+1]) {
				return false
			}
			if lower == "--format" {
				format = strings.ToLower(args[index+1])
			} else {
				wordlist = args[index+1] != ""
			}
			index++
		case strings.HasPrefix(arg, "-"):
			return false
		default:
			positionals++
		}
	}
	kerberos := format == "krb5tgs" || format == "krb5asrep"
	return kerberos && positionals == 1 && (wordlist || show)
}

func exactNetExecNTDSDump(args []string) bool {
	if len(args) < 3 || !strings.EqualFold(args[0], "smb") ||
		unresolvedCredentialRemoteScalar(args[1]) || strings.HasPrefix(args[1], "-") {
		return false
	}
	for index := 2; index < len(args); index++ {
		if args[index] == "-h" || strings.EqualFold(args[index], "--help") ||
			strings.EqualFold(args[index], "--version") {
			return false
		}
		switch strings.ToLower(args[index]) {
		case "--ntds":
			return true
		case "-m":
			if index+1 < len(args) && strings.EqualFold(args[index+1], "ntdsutil") {
				return true
			}
		}
	}
	return false
}

func directoryCredentialStaticArgv(command CommandFact) ([]string, bool) {
	if command.ArgvComplete {
		return cloneSlice(command.Argv), len(command.Argv) != 0
	}
	if len(command.Arguments) == 0 || len(command.Arguments) != len(command.Argv) {
		return nil, false
	}
	argv := make([]string, len(command.Arguments))
	for index, argument := range command.Arguments {
		switch {
		case argument.Value != "":
			argv[index] = argument.Value
		case argument.Expands && argument.Quote == QuoteNone &&
			credentialHomeRelativeGlob(argument.StaticGlob) &&
			!strings.ContainsAny(argument.StaticGlob, "*?["):
			// Home identity does not affect this operation class; only the
			// presence of a literal hash or wordlist operand matters.
			argv[index] = argument.StaticGlob
		default:
			return nil, false
		}
	}
	return argv, true
}

func credentialHomeRelativeGlob(value string) bool {
	return strings.HasPrefix(value, "~/") ||
		strings.HasPrefix(value, "$HOME/") ||
		strings.HasPrefix(value, "${HOME}/")
}

func unwrapDirectoryCredentialTimeout(command CommandFact) CommandFact {
	if strings.ToLower(command.Program) != "timeout" || len(command.Argv) < 3 {
		return command
	}
	index := 1
	for index < len(command.Argv) && strings.HasPrefix(command.Argv[index], "-") {
		index++
	}
	if index+1 >= len(command.Argv) || !boundedTimeoutDuration(command.Argv[index]) {
		return command
	}
	index++
	program := commandProgram(command.Argv[index])
	if _, ok := directoryCredentialPrograms[program]; !ok {
		return command
	}
	command.Program = program
	command.Argv = append([]string{program}, command.Argv[index+1:]...)
	return command
}

func boundedTimeoutDuration(value string) bool {
	value = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(value, "s"), "m"), "h")
	if value == "" || len(value) > 8 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func unwrapDirectoryCredentialPythonScript(command CommandFact) CommandFact {
	program := strings.ToLower(command.Program)
	if len(command.Argv) < 3 || !pythonInterpreterProgram(program) {
		return command
	}
	script := strings.ReplaceAll(command.Argv[1], `\`, "/")
	if strings.ContainsAny(script, "*?[]{}<>") || strings.Contains(script, "..") {
		return command
	}
	basename := strings.ToLower(path.Base(script))
	switch basename {
	case "secretsdump.py", "getuserspns.py", "getnpusers.py":
		command.Program = basename
		command.Argv = append([]string{basename}, command.Argv[2:]...)
	}
	return command
}

func pythonInterpreterProgram(program string) bool {
	if program == "python" || program == "python.exe" {
		return true
	}
	program = strings.TrimSuffix(program, ".exe")
	if !strings.HasPrefix(program, "python3") {
		return false
	}
	for _, character := range strings.TrimPrefix(program, "python3") {
		if character != '.' && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func exactLocalSecretsDump(args []string) bool {
	if len(args) == 0 || !strings.EqualFold(args[len(args)-1], "local") {
		return false
	}
	return hasOptionWithStaticValue(args, "-sam") &&
		hasOptionWithStaticValue(args, "-system")
}

var directoryRequestValueOptions = map[string]struct{}{
	"-dc-host": {}, "-dc-ip": {}, "-debug": {}, "-hashes": {},
	"-format": {}, "-k": {}, "-no-pass": {}, "-outputfile": {}, "-password": {},
	"-request": {}, "-request-user": {}, "-save": {}, "-stealth": {},
	"-target-domain": {}, "-ts": {}, "-usersfile": {},
}

var secretsDumpValueOptions = map[string]struct{}{
	"-debug": {}, "-dc-ip": {}, "-exec-method": {}, "-hashes": {},
	"-history": {}, "-just-dc": {}, "-just-dc-ntlm": {},
	"-just-dc-user": {}, "-k": {}, "-keylist": {}, "-ldapfilter": {},
	"-no-pass": {}, "-ntds": {}, "-outputfile": {}, "-pwd-last-set": {},
	"-resumefile": {}, "-sam": {}, "-security": {}, "-system": {},
	"-target-ip": {}, "-ts": {}, "-use-vss": {}, "-user-status": {},
}

func exactCredentialToolTarget(args []string, known map[string]struct{}) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "-h" || lower == "--help" || lower == "-version" ||
			lower == "--version" {
			return false
		}
	}
	for index := len(args) - 1; index >= 0; index-- {
		arg := args[index]
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if index > 0 && known != nil {
			if _, takesValue := known[strings.ToLower(args[index-1])]; takesValue &&
				!directoryBooleanOption(args[index-1]) {
				continue
			}
		}
		return !unresolvedCredentialRemoteScalar(arg) &&
			(strings.ContainsAny(arg, "@/\\") || strings.Contains(arg, "."))
	}
	return false
}

func directoryBooleanOption(value string) bool {
	switch strings.ToLower(value) {
	case "-debug", "-k", "-no-pass", "-request", "-save", "-stealth", "-ts":
		return true
	case "-history", "-just-dc", "-just-dc-ntlm", "-keylist", "-pwd-last-set",
		"-use-vss", "-user-status":
		return true
	default:
		return false
	}
}

func hasExactOption(args []string, option string) bool {
	for _, arg := range args {
		if strings.EqualFold(arg, option) {
			return true
		}
	}
	return false
}

func hasExactOptionValue(args []string, option, value string) bool {
	for index := 0; index+1 < len(args); index++ {
		if strings.EqualFold(args[index], option) &&
			strings.EqualFold(args[index+1], value) {
			return true
		}
	}
	return false
}

func hasOptionWithStaticValue(args []string, option string) bool {
	for index := 0; index+1 < len(args); index++ {
		if strings.EqualFold(args[index], option) && args[index+1] != "" &&
			!strings.HasPrefix(args[index+1], "-") &&
			!unresolvedCredentialRemoteScalar(args[index+1]) {
			return true
		}
	}
	return false
}

func exactKerberosHashcatCrack(args []string) bool {
	mode := ""
	positionals := 0
	show := false
	valueOptions := map[string]struct{}{
		"-m": {}, "--hash-type": {}, "-a": {}, "--attack-mode": {},
		"-o": {}, "--outfile": {}, "-r": {}, "--rules-file": {},
		"--potfile-path": {}, "--outfile-format": {}, "--session": {},
		"--restore-file-path": {}, "-w": {}, "--workload-profile": {},
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		lower := strings.ToLower(arg)
		optionKey := lower
		if len(arg) == 2 && arg[0] == '-' {
			// Hashcat short options are case-sensitive: -o takes an output
			// path, while -O is the value-free optimized-kernel switch.
			optionKey = arg
		}
		if unresolvedHashcatArgument(arg) || lower == "-h" ||
			lower == "--help" || lower == "--version" {
			return false
		}
		if lower == "--show" {
			show = true
			continue
		}
		if strings.HasPrefix(lower, "--hash-type=") {
			mode = strings.TrimPrefix(lower, "--hash-type=")
			continue
		}
		if _, takesValue := valueOptions[optionKey]; takesValue {
			if index+1 >= len(args) || args[index+1] == "" ||
				strings.HasPrefix(args[index+1], "-") {
				return false
			}
			if optionKey == "-m" || optionKey == "--hash-type" {
				mode = args[index+1]
			}
			index++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		positionals++
	}
	return (mode == "13100" || mode == "18200") &&
		((show && positionals >= 1) || (!show && positionals >= 2))
}

func unresolvedHashcatArgument(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.ContainsAny(value, "`[]{}<>") || strings.Contains(value, "{{") ||
		strings.Contains(value, "}}") || strings.Contains(lower, "placeholder") ||
		strings.Contains(lower, "your_")
}
