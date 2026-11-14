// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// PATH-PROC-ENVIRON claims that a read of /proc/<pid>/environ puts process
// credentials in front of the agent. A read whose output is narrowed by a
// grep to a few named variables that are not credential names
// (cat /proc/408/environ | tr '\0' '\n' | grep INGEST_ENV) shows the agent
// those lines only, so the claim does not hold for it. Every other read stays
// a finding: an unfiltered dump, a filter that selects by anything but a plain
// name, an inverted or context-printing filter, a name that reads as a
// credential, and any stage between the read and the filter that could widen
// or divert the data.

// procEnvironPrerequisite is the PATH-PROC-ENVIRON owner: a proc environ read
// whose output is not narrowed to named variables.
func procEnvironPrerequisite(facts actionfacts.Facts) bool {
	found := false
	procEnvironReads(facts, func(command actionfacts.CommandFact) bool {
		if !procEnvironReadNarrowed(facts, command) {
			found = true
			return false
		}
		return true
	})
	return found
}

// procEnvironSafeNegative keeps the regex fallback quiet for a parse whose
// every proc environ read is narrowed, next to the path owner's own safe
// negative. tr and grep operands are outside the operand grammar ActionFacts
// reads, so such a pipeline is never an authoritative parse; it is enough that
// the structure is fully read (every command has a complete argument vector,
// and the only issue is that operand grammar) and that no command names a proc
// environ path except the narrowed reads.
func procEnvironSafeNegative(base semanticOwnerPrerequisite) semanticOwnerPrerequisite {
	return func(facts actionfacts.Facts) bool {
		if base(facts) {
			return true
		}
		for _, issue := range facts.Parse.Issues {
			if issue != actionfacts.IssueUnknownOperandGrammar {
				return false
			}
		}
		if facts.Parse.Status != actionfacts.StatusComplete && facts.Parse.Status != actionfacts.StatusPartial {
			return false
		}
		narrowed := map[int64]bool{}
		reads := 0
		procEnvironReads(facts, func(command actionfacts.CommandFact) bool {
			reads++
			if procEnvironReadNarrowed(facts, command) {
				narrowed[command.ID] = true
			}
			return true
		})
		if reads == 0 || reads != len(narrowed) {
			return false
		}
		for _, command := range facts.Commands {
			if !command.ArgvComplete || command.ControlFlowUncertain {
				return false
			}
			if narrowed[command.ID] {
				continue
			}
			for _, value := range command.Argv {
				if matchesProcEnvironCandidate(semanticFoldPath(strings.ReplaceAll(value, `\`, "/"))) {
					return false
				}
			}
			for _, redirect := range command.Redirects {
				if matchesProcEnvironCandidate(semanticFoldPath(strings.ReplaceAll(redirect.Target, `\`, "/"))) {
					return false
				}
			}
		}
		return true
	}
}

// procEnvironReads calls visit for each command that reads a proc environ
// path, until visit returns false.
func procEnvironReads(facts actionfacts.Facts, visit func(actionfacts.CommandFact) bool) {
	for _, command := range facts.Commands {
		if command.Effect != actionfacts.EffectExecute ||
			!hasOperation(command, actionfacts.OperationRead) {
			continue
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID == command.ID &&
				candidate.Access == actionfacts.PathAccessRead &&
				pathValueMatcher(matchesProcEnviron)(facts, candidate) {
				if !visit(command) {
					return
				}
				break
			}
		}
	}
}

// procEnvironReadNarrowed reports a read that is piped, through stages that
// only reformat, into a grep that selects plain non-credential variable names.
func procEnvironReadNarrowed(facts actionfacts.Facts, read actionfacts.CommandFact) bool {
	if read.PipelineID == 0 || !read.ArgvComplete || read.ControlFlowUncertain ||
		!onlyDiscardedStderr(read.Redirects) || !oneOfFold(path.Base(read.Program), "cat", "strings") {
		return false
	}
	for _, next := range facts.Commands {
		if next.PipelineID != read.PipelineID || next.ID <= read.ID {
			continue
		}
		if !next.ArgvComplete || next.ControlFlowUncertain || next.Effect != actionfacts.EffectExecute {
			return false
		}
		switch strings.ToLower(path.Base(next.Program)) {
		case "tr", "sort", "uniq":
			if !onlyDiscardedStderr(next.Redirects) {
				return false
			}
		case "grep", "egrep", "fgrep":
			return onlyDiscardedStderr(next.Redirects) && grepSelectsPlainNames(next.Argv[1:])
		default:
			return false
		}
	}
	return false
}

// onlyDiscardedStderr reports redirects that send standard error to the null
// device and nothing else.
func onlyDiscardedStderr(redirects []actionfacts.RedirectFact) bool {
	for _, redirect := range redirects {
		if redirect.FD != 2 || redirect.Target != "/dev/null" || redirect.Expands {
			return false
		}
	}
	return true
}

var (
	// plainEnvName is one variable name, optionally anchored at the start and
	// closed with the equals sign: the only shape of grep alternative the
	// narrowing accepts. Four letters keep a fragment from selecting a family
	// of names.
	plainEnvName = lazyregexp.New(`^\^?[A-Za-z_][A-Za-z0-9_]{3,}=?$`)
	// credentialEnvWord marks a name that reads as a credential, a connection
	// string or an identity. Such a variable stays a finding.
	credentialEnvWord = lazyregexp.New(`(?i)key|secret|token|pass|pwd|cred|auth|dsn|private|session|cookie|cert|salt|sign|conn|url|uri|bearer|jwt|api|login|access|aws|azure|gcp|github|ssh|user|account|ident|openai|anthropic|stripe|twilio|slack|sendgrid|mailgun|okta|vault|bedrock|huggingface|hf_|npm|docker|kube|postgres|mysql|redis|mongo|database|db_|smtp|ldap|oauth|gcloud|google|firebase|supabase|datadog|sentry`)
)

// grepSelectsPlainNames reports grep arguments (after the program) that read
// standard input only and select lines holding one of a few plain
// non-credential variable names. Options other than the case, matching-mode
// and output-narrowing letters, a pattern file, an inverted match and
// context lines are refused.
func grepSelectsPlainNames(args []string) bool {
	var patterns []string
	operands := 0
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--":
			operands += len(args) - index - 1
			if operands == 1 && len(patterns) == 0 {
				patterns = append(patterns, args[index+1])
			}
			index = len(args)
		case strings.HasPrefix(argument, "--"):
			switch argument {
			case "--ignore-case", "--extended-regexp", "--fixed-strings", "--only-matching",
				"--word-regexp", "--text", "--count", "--quiet", "--no-messages", "--basic-regexp":
			default:
				return false
			}
		case strings.HasPrefix(argument, "-") && len(argument) > 1:
			for letter := 1; letter < len(argument); letter++ {
				switch argument[letter] {
				case 'i', 'E', 'F', 'G', 'o', 'w', 'a', 'c', 's', 'q':
				case 'e':
					value := argument[letter+1:]
					if value == "" {
						index++
						if index >= len(args) {
							return false
						}
						value = args[index]
					}
					patterns = append(patterns, value)
					letter = len(argument)
				default:
					return false
				}
			}
		default:
			operands++
			if len(patterns) == 0 && operands == 1 {
				patterns = append(patterns, argument)
			}
		}
	}
	// With -e the patterns come from the options and no operand is allowed;
	// otherwise the first operand is the pattern and there is no file.
	if len(patterns) == 0 || (operands > 1) || (operands == 1 && len(patterns) > 1) {
		return false
	}
	for _, pattern := range patterns {
		for _, alternative := range strings.Split(strings.ReplaceAll(pattern, `\|`, "|"), "|") {
			if !plainEnvName.MatchString(alternative) || credentialEnvWord.MatchString(alternative) {
				return false
			}
		}
	}
	return true
}
