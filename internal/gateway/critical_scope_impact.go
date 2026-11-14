// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10:GAP-0594. A rule that blocks the delete of the filesystem root,
// a system folder or the home matches the whole scope it protects, not one
// spelling of it:
//
//   - the contents of a critical folder or of the home (`rm -rf /etc/*`,
//     `rm -rf ~/*`, `rm -rf "$HOME"/.[!.]*`) and the direct children of the
//     system payload folders (/usr/lib, /boot/grub) are critical scope as
//     much as the folder is;
//   - an unrestricted `find <critical> -delete` and a recursive chmod that
//     locks the owner out of (or opens to everyone) a critical scope are the
//     same destruction by another program;
//   - the shell expands a glob after the hook reads it, so the facts keep only
//     its spelling and the parse is partial; the directory part and the
//     match-everything last component are static, so the target is proven
//     from the words (the same reading globbedStateMutation uses for the
//     state), and the call no longer depends on a complete parse;
//   - the rules that are alert-only or detection-only by design because a
//     recursive chmod or a fork bomb may be authorized administration or a
//     drill (CMD-CHMOD-WORLD, impact.fork_bomb) alert in the default and
//     permissive packs and block in strict and managed, where the target is
//     proven. CMD-MKFS and CMD-DEVICE-WIPE stay detection-only in every
//     pack (the 1.0.10 lead's ruling: a format may be provisioning).

// criticalPayloadParents are the system payload folders whose direct
// children (/usr/lib, /usr/bin, /boot/grub) are critical delete scope.
var criticalPayloadParents = []string{"/bin", "/boot", "/lib", "/lib64", "/sbin", "/usr"}

// criticalDeleteScope reports whether removing value (a canonical, lower
// case slash path) removes a host or an account: the filesystem or a drive
// root, a top-level system folder, the active home, or a direct child of a
// system payload folder. home is the canonical active home, "" when unknown.
func criticalDeleteScope(value, home string) bool {
	if value == "/" || windowsDriveRoot(value) {
		return true
	}
	trimmed := strings.TrimRight(value, "/")
	switch trimmed {
	case "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
		"/mnt", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var",
		"/applications", "/library", "/system", "/users",
		"c:/program files", "c:/program files (x86)", "c:/programdata",
		"c:/users", "c:/windows":
		return true
	}
	if home != "" && trimmed == home {
		return true
	}
	// Another account's home is not judged: removing it is the ordinary
	// offboarding of an account (userdel -r, dscl -delete) and owner traces
	// carry it as benign. Only the active home is critical.
	return strings.HasPrefix(trimmed, "/") &&
		slices.Contains(criticalPayloadParents, path.Dir(trimmed))
}

// forkBombProof is forkBombFallbackProof for a call whose command text is in
// the tool arguments (a Bash hook call) as well as in Input.Command.
func forkBombProof(input actionfacts.Input, facts actionfacts.Facts) bool {
	if command, known := trustedBashCommandInput(input); known && canonicalShellForkBomb(command) {
		return true
	}
	return forkBombFallbackProof(input, facts)
}

// matchesEveryEntry reports whether a glob's last component names every
// entry of a directory (or every dot entry): only wildcards, the dot and a
// negated dot class, with at least one `*`. `*`, `.*`, `.[!.]*`, `..?*`,
// `?*`; never a name with a literal letter (`*.log`, `build*`).
func matchesEveryEntry(name string) bool {
	if !strings.Contains(name, "*") {
		return false
	}
	for _, char := range name {
		if !strings.ContainsRune("*?[]!^.", char) {
			return false
		}
	}
	return true
}

func hasGlobMeta(word string) bool { return strings.ContainsAny(word, "*?[") }

// criticalDeleteWord reports whether a recursive delete of the word (a static
// operand: a path, a home spelling, or a glob whose last component matches
// every entry) removes a critical scope. A relative word is not judged here.
func criticalDeleteWord(word, home string) bool {
	word = strings.TrimSpace(strings.ReplaceAll(word, `\`, "/"))
	if word == "" {
		return false
	}
	lower := strings.ToLower(word)
	rest, homeSpelled := "", false
	switch {
	case lower == "~" || lower == "$home" || lower == "${home}":
		homeSpelled = true
	case strings.HasPrefix(lower, "~/"):
		rest, homeSpelled = lower[2:], true
	case strings.HasPrefix(lower, "$home/"):
		rest, homeSpelled = lower[6:], true
	case strings.HasPrefix(lower, "${home}/"):
		rest, homeSpelled = lower[8:], true
	}
	if homeSpelled {
		rest = path.Clean("/" + rest)[1:]
		switch {
		case rest == "":
			return true
		case !strings.Contains(rest, "/"):
			return matchesEveryEntry(rest)
		}
		return false
	}
	if !strings.HasPrefix(lower, "/") {
		return false
	}
	cleaned := path.Clean(lower)
	if hasGlobMeta(cleaned) {
		dir, last := path.Split(cleaned)
		if !matchesEveryEntry(last) || hasGlobMeta(dir) {
			return false
		}
		cleaned = path.Clean(dir)
	}
	return criticalDeleteScope(cleaned, home)
}

// criticalScopeHome is the canonical active home of the facts.
func criticalScopeHome(facts actionfacts.Facts) string {
	return strings.TrimRight(canonicalSemanticPath(facts.ActiveHome), "/")
}

// criticalScopeCommands calls visit with the program a top-level POSIX
// command runs (through a transparent wrapper such as sudo) and its static
// operand words, for each command whose words are readable. A parse that is
// not complete (a glob, or any other word the parser could not read) is
// judged only on a command with no unreadable word beside the glob, and only
// the glob targets count: a root or a folder named next to an unrelated
// dynamic word stays at the unknown tier of the pack, as before.
func criticalScopeCommands(facts actionfacts.Facts, visit func(program string, words []string, partial bool) bool) bool {
	partial := !facts.Authoritative()
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 ||
			command.Effect == actionfacts.EffectPreview ||
			command.Dialect != actionfacts.DialectPOSIX {
			continue
		}
		words, ok := stateOperandWords(command)
		if !ok || partial && slices.Contains(words, "") {
			continue
		}
		inner, innerWords := unwrapStateWrapper(command, words)
		if visit(strings.ToLower(path.Base(inner.Program)), innerWords, partial) {
			return true
		}
	}
	return false
}

// criticalTarget reports a word that removes or locks a critical scope; in a
// partial parse only a glob target counts (criticalScopeCommands).
func criticalTarget(word, home string, partial bool) bool {
	return (!partial || hasGlobMeta(word)) && criticalDeleteWord(word, home)
}

// criticalGlobDeleteProof proves a recursive force `rm` of the contents of a
// critical scope from the words of the call: the shell expands the glob
// after the hook reads it, so the parse is partial, but the directory part
// and the match-everything last component are static. A complete parse is
// judged by the CMD-RM-RF owner itself.
func criticalGlobDeleteProof(_ actionfacts.Input, facts actionfacts.Facts) bool {
	if facts.Authoritative() {
		return false
	}
	home := criticalScopeHome(facts)
	return criticalScopeCommands(facts, func(program string, words []string, partial bool) bool {
		if program != "rm" || !posixRecursiveForceFlags(append([]string{"rm"}, words...)) {
			return false
		}
		options := true
		for _, word := range words {
			switch {
			case options && word == "--":
				options = false
			case options && strings.HasPrefix(word, "-") && word != "-":
			case criticalTarget(word, home, partial):
				return true
			}
		}
		return false
	})
}

// unrestrictedFindDelete reports a `find ... -delete` whose expression has
// no test (name, type, time, owner, path...) that narrows what it removes:
// only traversal options and -delete.
func unrestrictedFindDelete(command actionfacts.CommandFact) bool {
	if !oneOfFold(command.Program, "find") {
		return false
	}
	argv := command.Argv
	index := 1
	for index < len(argv) && (argv[index] == "-H" || argv[index] == "-L" || argv[index] == "-P") {
		index++
	}
	for index < len(argv) && !strings.HasPrefix(argv[index], "-") &&
		argv[index] != "(" && argv[index] != "!" {
		index++
	}
	deletes := false
	for ; index < len(argv); index++ {
		switch argv[index] {
		case "-delete":
			deletes = true
		case "-depth", "-xdev", "-mount", "-ignore_readdir_race", "-noignore_readdir_race":
		case "-mindepth", "-maxdepth":
			index++
		default:
			return false
		}
	}
	return deletes
}

// chmodLocksOut reports a mode that, applied recursively, makes the tree
// unusable: it takes an owner permission away (a directory loses search, a
// file its read or write) or opens it to every user for writing.
func chmodLocksOut(mode string) bool {
	if parsed, err := strconv.ParseUint(mode, 8, 16); err == nil {
		if len(mode) < 3 || len(mode) > 4 {
			return false
		}
		return parsed&0700 != 0700 || parsed&0002 != 0
	}
	for _, clause := range strings.Split(strings.ToLower(mode), ",") {
		operator := strings.IndexAny(clause, "+-=")
		if operator < 0 {
			return false
		}
		who, permissions := clause[:operator], clause[operator+1:]
		if strings.Trim(who, "ugoa") != "" || strings.Trim(permissions, "rwxXst") != "" {
			return false
		}
		owner := who == "" || strings.ContainsAny(who, "ua")
		public := who == "" || strings.ContainsAny(who, "oa")
		op := clause[operator]
		if owner && op == '-' && strings.ContainsAny(permissions, "rwx") {
			return true
		}
		if owner && op == '=' && (!strings.Contains(permissions, "r") ||
			!strings.Contains(permissions, "w") || !strings.Contains(permissions, "x")) {
			return true
		}
		if public && op != '-' && strings.Contains(permissions, "w") {
			return true
		}
	}
	return false
}

// criticalRecursiveLockoutProof proves a recursive chmod of a critical scope
// to a mode that locks it out or opens it for writing.
func criticalRecursiveLockoutProof(_ actionfacts.Input, facts actionfacts.Facts) bool {
	home := criticalScopeHome(facts)
	return criticalScopeCommands(facts, func(program string, words []string, partial bool) bool {
		if program != "chmod" {
			return false
		}
		recursive, options, mode := false, true, ""
		var targets []string
		for _, word := range words {
			switch {
			case options && word == "--":
				options = false
			case options && (word == "--recursive"):
				recursive = true
			case options && strings.HasPrefix(word, "--"):
				if strings.HasPrefix(word, "--reference") {
					return false
				}
			case options && len(word) > 1 && word[0] == '-' && strings.Trim(word[1:], "RfvcHLPh") == "":
				recursive = recursive || strings.Contains(word, "R")
			case mode == "":
				mode = word
			default:
				targets = append(targets, word)
			}
		}
		if !recursive || mode == "" || !chmodLocksOut(mode) {
			return false
		}
		return slices.ContainsFunc(targets, func(target string) bool {
			return criticalTarget(target, home, partial)
		})
	})
}

// provenScopeRule is a rule whose scope this lane proves from the words of
// the call. tiered rules are the ones that are alert-only by design outside
// strict and managed (see withProvenScopeFindings).
type provenScopeRule struct {
	ruleID string
	proves func(actionfacts.Input, actionfacts.Facts) bool
	tiered bool
}

var provenScopeRules = []provenScopeRule{
	{ruleID: "CMD-RM-RF", proves: criticalGlobDeleteProof},
	{ruleID: "CMD-CHMOD-WORLD", proves: criticalRecursiveLockoutProof, tiered: true},
	{ruleID: "impact.fork_bomb", proves: forkBombProof, tiered: true},
}

// withProvenScopeFindings adds the findings of provenScopeRules the pack
// carries and the call proves, and grades the tiered ones: an alert outside
// strict and managed, enforceable in them (rel-1-0-10:GAP-0594).
func withProvenScopeFindings(
	generation *compiledRulePackCategories,
	request trustedActionRequest,
	facts actionfacts.Facts,
	findings []RuleFinding,
) []RuleFinding {
	enforced := request.StrictPolicy || request.ManagedInstall
	findings = slices.Clone(findings)
	grade := func(finding *RuleFinding, tiered bool) {
		if !request.EnforcementCapable {
			finding.enforcement = findingEnforcementDetectionOnly
			return
		}
		finding.proof = newActionFactsSubgraphFindingProof(finding.RuleID, true, true)
		switch {
		case !tiered || enforced:
			finding.enforcement = findingEnforcementAllowed
		default:
			finding.enforcement = findingEnforcementAlertOnly
		}
		if tiered && guardrailSeverityRank(finding.Severity) < guardrailSeverityRank("CRITICAL") {
			finding.Severity = "CRITICAL"
		}
	}
	for _, rule := range provenScopeRules {
		if !rule.proves(request.Input, facts) {
			continue
		}
		index := slices.IndexFunc(findings, func(f RuleFinding) bool {
			return canonicalTrustedRuleID(f.RuleID) == canonicalTrustedRuleID(rule.ruleID)
		})
		if index >= 0 {
			if findings[index].disposition != findingDispositionUnspecified {
				continue
			}
			grade(&findings[index], rule.tiered)
			continue
		}
		_, catalog, ok := trustedActionCatalogRule(generation, rule.ruleID)
		if !ok {
			continue
		}
		finding := RuleFinding{
			RuleID: catalog.ID, Title: catalog.Title, Severity: catalog.Severity,
			Confidence: catalog.Confidence, Tags: append([]string(nil), catalog.Tags...),
			Evidence: trustedActionInputText(request.Input, ""), LineNumber: 1,
		}
		grade(&finding, rule.tiered)
		findings = append(findings, adjustConfidence(request.Input.Tool, finding))
	}
	return findings
}
