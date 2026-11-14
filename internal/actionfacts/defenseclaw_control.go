// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
)

// DefenseClawControlKind names how a command reaches DefenseClaw's own
// guardrail. The set is closed and value-free: a finding carries a kind, never
// operand text.
type DefenseClawControlKind string

const (
	// DefenseClawControlStop stops, kills, unloads, disables or deletes a
	// DefenseClaw service, process, scheduled task or unit.
	DefenseClawControlStop DefenseClawControlKind = "stop"
	// DefenseClawControlUninstall removes or resets the installation.
	DefenseClawControlUninstall DefenseClawControlKind = "uninstall"
	// DefenseClawControlDisable turns a guardrail part off through the
	// DefenseClaw CLI, or moves it to a weaker mode (observe, fail open).
	DefenseClawControlDisable DefenseClawControlKind = "disable"
	// DefenseClawControlConfig changes the DefenseClaw configuration through
	// the CLI: the same effect as a write to config.yaml, which the state
	// rule blocks.
	DefenseClawControlConfig DefenseClawControlKind = "config"
	// DefenseClawControlUnproven is a DefenseClaw command whose effect the
	// parse could not resolve (a changing verb that is not a known stop or
	// disable, a dynamic operand, an unparsed nested shell). It is judged at
	// the unknown tier.
	DefenseClawControlUnproven DefenseClawControlKind = "unproven"
)

// DefenseClawControlFact is one command of the call that stops or changes the
// DefenseClaw guardrail. Proven is false for DefenseClawControlUnproven.
type DefenseClawControlFact struct {
	Kind   DefenseClawControlKind
	Proven bool
}

// defenseClawNamespace is the product namespace every packaged program,
// systemd unit, launchd label and Windows service shares (packaging/systemd,
// packaging/launchd*, internal/enterpriseunix, internal/winpath). A drift test
// walks the installer assets and fails when one escapes it.
const defenseClawNamespace = "defenseclaw"

// IsDefenseClawServiceName reports whether a unit, label, plist path, service
// or task name names a DefenseClaw service: the name, after its manager
// decoration (domain, path, extension, vendor prefix), starts with the
// product namespace.
func IsDefenseClawServiceName(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.Trim(name, `"'`)
	if name == "" {
		return false
	}
	// launchctl domain targets and plist or unit file paths.
	if cut := strings.LastIndexAny(name, `/\`); cut >= 0 {
		name = name[cut+1:]
	}
	for _, suffix := range []string{".service", ".socket", ".timer", ".path", ".target", ".plist", ".exe"} {
		name = strings.TrimSuffix(name, suffix)
	}
	for _, prefix := range []string{"com.cisco.secureclient.", "com.cisco."} {
		name = strings.TrimPrefix(name, prefix)
	}
	return strings.HasPrefix(name, defenseClawNamespace)
}

// defenseClawProgramName returns the packaged CLI or gateway program an
// argv invokes ("defenseclaw" or "defenseclaw-gateway"), or "". It accepts a
// path, a Windows extension and `python -m defenseclaw`.
func defenseClawProgramName(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	base := commandBaseName(argv[0])
	if base == "defenseclaw" || base == "defenseclaw-gateway" {
		return base
	}
	if strings.HasPrefix(base, "python") {
		for index := 1; index+1 < len(argv); index++ {
			if argv[index] == "-m" {
				module := strings.ToLower(argv[index+1])
				if module == "defenseclaw" || strings.HasPrefix(module, "defenseclaw.") {
					return "defenseclaw"
				}
				break
			}
		}
	}
	return ""
}

func commandBaseName(word string) string {
	word = strings.ToLower(strings.Trim(word, `"'`))
	if cut := strings.LastIndexAny(word, `/\`); cut >= 0 {
		word = word[cut+1:]
	}
	for _, suffix := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		word = strings.TrimSuffix(word, suffix)
	}
	return word
}

// launcherInner returns the argv a launcher runs, or nil when argv is not a
// launcher. It knows the option grammar of each launcher only as far as the
// inner program's position.
func launcherInner(argv []string) []string {
	if len(argv) < 2 {
		return nil
	}
	rest := argv[1:]
	skipOptions := func(valued ...string) []string {
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") && rest[0] != "-" && rest[0] != "--" {
			option := rest[0]
			rest = rest[1:]
			for _, name := range valued {
				if option == name && len(rest) > 0 {
					rest = rest[1:]
					break
				}
			}
		}
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		return rest
	}
	switch commandBaseName(argv[0]) {
	case "env":
		skipOptions("-u", "-C", "-S", "--unset", "--chdir", "--split-string")
		for len(rest) > 0 && strings.Contains(rest[0], "=") && !strings.HasPrefix(rest[0], "-") {
			rest = rest[1:]
		}
	case "nohup", "exec", "setsid", "time", "command", "builtin", "chrt", "unbuffer":
		skipOptions("-a", "-n", "-p")
	case "xargs":
		skipOptions("-n", "-I", "-P", "-d", "-L", "-E", "-s", "-a", "-i", "-l")
	case "nice":
		skipOptions("-n", "--adjustment")
	case "ionice":
		skipOptions("-c", "-n", "-p", "-P", "-u")
	case "stdbuf":
		skipOptions("-i", "-o", "-e")
	case "timeout":
		skipOptions("-s", "-k", "--signal", "--kill-after")
		if len(rest) > 0 {
			rest = rest[1:]
		}
	case "sudo", "doas":
		skipOptions("-u", "-g", "-C", "-h", "-p", "-r", "-t", "-U", "-D", "-R", "-T")
		for len(rest) > 0 && strings.Contains(rest[0], "=") && !strings.HasPrefix(rest[0], "-") {
			rest = rest[1:]
		}
	case "runuser":
		skipOptions("-u", "-g", "-G", "-s", "-c", "-l")
	case "uv", "pipx", "poetry":
		if len(rest) > 0 && rest[0] == "run" {
			rest = rest[1:]
			skipOptions("--with", "--python", "-p")
		} else {
			return nil
		}
	default:
		return nil
	}
	if len(rest) == 0 {
		return nil
	}
	return rest
}

// DefenseClawControl returns what the commands of one call do to DefenseClaw's
// own guardrail: stop or remove its service or process, uninstall or reset it,
// turn a guard off or weaken it through the CLI, change its configuration
// through the CLI, or run a DefenseClaw command whose effect the parse could
// not resolve. Read-only DefenseClaw commands (status, doctor, explain,
// version, logs, list, show, scan, validate) and restarts return nothing.
//
// Every command of the parse is judged, including one in a pipeline, a list
// or a nested shell: whether the call would run it is not a question a
// guardrail answers in the agent's favour.
func DefenseClawControl(facts Facts, text string) []DefenseClawControlFact {
	return defenseClawControl(facts, text, 0)
}

func defenseClawControl(facts Facts, text string, depth int) []DefenseClawControlFact {
	textNames := strings.Contains(strings.ToLower(text), defenseClawNamespace)
	var out []DefenseClawControlFact
	seen := map[DefenseClawControlFact]bool{}
	add := func(fact DefenseClawControlFact) {
		if !seen[fact] {
			seen[fact] = true
			out = append(out, fact)
		}
	}
	for _, command := range facts.Commands {
		if command.Kind != "" && command.Kind != CommandKindProcess {
			continue
		}
		argv := command.Argv
		if len(argv) == 0 && command.Executable != "" {
			argv = []string{command.Executable}
		}
		for unwrap := 0; unwrap < 6 && len(argv) > 0; unwrap++ {
			inner := launcherInner(argv)
			if inner == nil {
				break
			}
			argv = inner
		}
		if len(argv) == 0 {
			continue
		}
		if fact, ok := judgeDefenseClawArgv(argv, textNames, depth, facts, command); ok {
			add(fact)
		}
	}
	return out
}

func judgeDefenseClawArgv(argv []string, textNames bool, depth int, facts Facts, command CommandFact) (DefenseClawControlFact, bool) {
	proven := func(kind DefenseClawControlKind) (DefenseClawControlFact, bool) {
		return DefenseClawControlFact{Kind: kind, Proven: true}, true
	}
	unproven := DefenseClawControlFact{Kind: DefenseClawControlUnproven}
	// A word the parse could not resolve (a substitution, a variable, a
	// tilde) has no value in argv.
	dynamic := slices.Contains(argv[1:], "")
	if program := defenseClawProgramName(argv); program != "" {
		kind, decided := judgeDefenseClawCLI(argv[1:], program, dynamic)
		if decided {
			if kind == "" {
				return DefenseClawControlFact{}, false
			}
			return proven(kind)
		}
		return unproven, true
	}
	name := commandBaseName(argv[0])
	words, flags := splitOperands(argv[1:])
	switch name {
	case "systemctl", "service", "launchctl", "sc", "net", "net1", "stop-service",
		"set-service", "remove-service", "schtasks", "stop-scheduledtask",
		"disable-scheduledtask", "unregister-scheduledtask", "initctl", "rc-service":
		if kind, ok := serviceManagerStopsDefenseClaw(name, words, flags); ok {
			return proven(kind)
		}
		if serviceManagerStopVerb(name, words, flags) && dynamic && pipelineNamesDefenseClaw(facts, command) {
			return proven(DefenseClawControlStop)
		}
		if serviceManagerStopVerb(name, words, flags) && dynamic && textNames {
			return unproven, true
		}
	case "kill", "killall", "pkill", "taskkill", "stop-process":
		if slices.Contains(flags, "-0") || slices.Contains(flags, "-l") {
			// kill -0 probes whether a process exists; kill -l lists signals.
			break
		}
		if killTargetsDefenseClaw(words) {
			return proven(DefenseClawControlStop)
		}
		if (dynamic || len(words) == 0) && (childNamesDefenseClaw(facts, command) || pipelineNamesDefenseClaw(facts, command)) {
			return proven(DefenseClawControlStop)
		}
		// A dynamic target (a pid read from a file, a substitution) of a
		// call that names DefenseClaw elsewhere: the target is unproven.
		if (dynamic || len(words) == 0) && textNames &&
			(hasChildCommands(facts, command) || command.PipelineID != 0) {
			return unproven, true
		}
	case "powershell", "pwsh", "cmd":
		// An inline script the parse did not open is read again in its own
		// dialect; whatever it stops or disables is judged like a command of
		// the call.
		if script, dialect := inlineScript(name, argv[1:]); script != "" && depth < 3 {
			tool := "Bash"
			if dialect == DialectPowerShell {
				tool = "PowerShell"
			}
			inner := defenseClawControl(Analyze(Input{Tool: tool, Command: script, DialectHint: dialect}), script, depth+1)
			for _, fact := range inner {
				if fact.Proven {
					return fact, true
				}
			}
			if len(inner) > 0 {
				return inner[0], true
			}
		}
	}
	return DefenseClawControlFact{}, false
}

// splitOperands separates words from options. A word that starts with "-" or,
// for Windows tools, "/" followed by a letter is a flag (lower case, without
// its "=value").
func splitOperands(args []string) (words, flags []string) {
	for _, arg := range args {
		switch {
		case strings.HasPrefix(arg, "--") && len(arg) > 2, strings.HasPrefix(arg, "-") && len(arg) > 1:
			flag := strings.ToLower(arg)
			if cut := strings.Index(flag, "="); cut > 0 {
				flag = flag[:cut]
			}
			flags = append(flags, flag)
		case len(arg) > 1 && arg[0] == '/' && !strings.ContainsAny(arg[1:], `/\.`) &&
			arg[1] >= 'A' && (arg[1] <= 'Z' || arg[1] >= 'a' && arg[1] <= 'z'):
			flags = append(flags, strings.ToLower(arg))
		default:
			words = append(words, arg)
		}
	}
	return words, flags
}

func hasWord(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func anyDefenseClawService(words []string) bool {
	for _, word := range words {
		if IsDefenseClawServiceName(word) {
			return true
		}
	}
	return false
}

// serviceManagerStopVerb reports whether the manager call has a verb that
// stops, disables, removes or unloads, whatever it targets.
func serviceManagerStopVerb(manager string, words, flags []string) bool {
	lower := make([]string, len(words))
	for index, word := range words {
		lower[index] = strings.ToLower(word)
	}
	switch manager {
	case "systemctl":
		return len(lower) > 0 && hasWord([]string{"stop", "disable", "mask", "kill"}, lower[0])
	case "service", "rc-service":
		return len(lower) > 1 && lower[1] == "stop"
	case "initctl":
		return len(lower) > 0 && lower[0] == "stop"
	case "launchctl":
		return len(lower) > 0 && hasWord([]string{"unload", "bootout", "remove", "stop", "disable", "kill"}, lower[0])
	case "sc":
		if len(lower) == 0 {
			return false
		}
		if lower[0] == "stop" || lower[0] == "delete" {
			return true
		}
		return lower[0] == "config" && (hasWord(lower, "disabled") || hasWord(lower, "start=disabled"))
	case "net", "net1":
		return len(lower) > 0 && (lower[0] == "stop" || lower[0] == "pause")
	case "stop-service", "remove-service", "stop-scheduledtask", "disable-scheduledtask", "unregister-scheduledtask":
		return true
	case "set-service":
		return hasWord(lower, "disabled") || hasWord(lower, "stopped")
	case "schtasks":
		return hasWord(flags, "/end") || hasWord(flags, "/delete") || hasWord(flags, "/disable") ||
			hasWord(lower, "/disable")
	}
	return false
}

func serviceManagerStopsDefenseClaw(manager string, words, flags []string) (DefenseClawControlKind, bool) {
	if !serviceManagerStopVerb(manager, words, flags) {
		return "", false
	}
	if anyDefenseClawService(words) {
		return DefenseClawControlStop, true
	}
	return "", false
}

// killTargetsDefenseClaw reports a process-name or image-name operand that
// names a DefenseClaw program: pkill and killall patterns, taskkill /IM,
// Stop-Process -Name.
func killTargetsDefenseClaw(words []string) bool {
	for _, word := range words {
		if strings.Contains(strings.ToLower(word), defenseClawNamespace) {
			return true
		}
	}
	return false
}

func hasChildCommands(facts Facts, command CommandFact) bool {
	for _, other := range facts.Commands {
		if other.ParentCommandID == command.ID && command.ID != 0 {
			return true
		}
	}
	return false
}

// childNamesDefenseClaw reports a command nested in command (a substitution
// such as the pid lookup of a kill) that names the DefenseClaw namespace.
func childNamesDefenseClaw(facts Facts, command CommandFact) bool {
	for _, other := range facts.Commands {
		if other.ParentCommandID != command.ID || command.ID == 0 {
			continue
		}
		for _, word := range other.Argv {
			if strings.Contains(strings.ToLower(word), defenseClawNamespace) {
				return true
			}
		}
	}
	return false
}

// pipelineNamesDefenseClaw reports another command of the same pipeline that
// names the DefenseClaw namespace (Get-Process defenseclaw* | Stop-Process).
func pipelineNamesDefenseClaw(facts Facts, command CommandFact) bool {
	if command.PipelineID == 0 {
		return false
	}
	for _, other := range facts.Commands {
		if other.PipelineID != command.PipelineID || other.ID == command.ID {
			continue
		}
		for _, word := range other.Argv {
			if strings.Contains(strings.ToLower(word), defenseClawNamespace) {
				return true
			}
		}
	}
	return false
}

func inlineScriptTouchesDefenseClaw(args []string) bool {
	text := strings.ToLower(strings.Join(args, " "))
	if !strings.Contains(text, defenseClawNamespace) {
		return false
	}
	for _, verb := range []string{"stop", "disable", "uninstall", "kill", "remove", "delete", "unload", "bootout", "teardown", "mask", "reset", "config", "mode"} {
		if strings.Contains(text, verb) {
			return true
		}
	}
	return false
}

// Verbs of the DefenseClaw CLI and gateway. They are the subcommand names the
// CLI registers (cli/defenseclaw/commands, internal/cli); a drift test fails
// when a registered stop, disable, uninstall or teardown command is not
// recognised here.
var (
	// defenseClawStopVerbs stop, remove or tear down at any depth.
	defenseClawStopVerbs = map[string]DefenseClawControlKind{
		"stop": DefenseClawControlStop, "kill": DefenseClawControlStop, "shutdown": DefenseClawControlStop,
		"uninstall": DefenseClawControlUninstall, "teardown": DefenseClawControlUninstall,
		"remove-all": DefenseClawControlUninstall,
	}
	// defenseClawReadVerbs read, report, scan or restart; they change no
	// guard. A restart re-reads the protected configuration.
	defenseClawReadVerbs = map[string]bool{
		"status": true, "doctor": true, "explain": true, "version": true, "logs": true, "log": true,
		"list": true, "show": true, "get": true, "scan": true, "validate": true, "check": true,
		"info": true, "inspect": true, "search": true, "reference": true, "path": true, "help": true,
		"tui": true, "alerts": true, "audit": true, "aibom": true, "codeguard": true, "evaluate": true,
		"digest": true, "verify": true, "profile-explain": true, "readiness": true, "enumerate": true, "test": true, "export": true, "report": true, "diff": true,
		"enable": true, "start": true, "restart": true, "reload": true, "up": true, "completion": true,
	}
	// defenseClawRelaxVerbs relax what the guardrail enforces without a stop
	// or a disable; they are judged at the unknown tier.
	defenseClawRelaxVerbs = map[string]bool{
		"use-pack": true, "suppress": true, "severity": true, "trusted-paths": true,
		"allow-private-upstream": true, "migrate": true,
	}
	defenseClawReadFlags = map[string]bool{
		"--version": true, "-v": true, "-version": true, "--help": true, "-h": true, "-help": true,
	}
)

// judgeDefenseClawCLI classifies one defenseclaw or defenseclaw-gateway
// invocation. decided is false when the command is a changing verb the rules
// cannot name, or has an operand the parse left open before any verb.
func judgeDefenseClawCLI(args []string, program string, dynamic bool) (kind DefenseClawControlKind, decided bool) {
	words, flags := splitOperands(args)
	for _, flag := range flags {
		if flag == "--disable" || flag == "--uninstall" {
			return DefenseClawControlDisable, true
		}
	}
	lower := make([]string, len(words))
	for index, word := range words {
		lower[index] = strings.ToLower(word)
	}
	for index, word := range lower {
		if found, ok := defenseClawStopVerbs[word]; ok {
			return found, true
		}
		switch word {
		case "reset":
			if index == 0 {
				return DefenseClawControlUninstall, true
			}
		case "disable":
			return DefenseClawControlDisable, true
		case "mode":
			if index+1 < len(lower) && lower[index+1] == "observe" {
				return DefenseClawControlDisable, true
			}
		case "fail-mode":
			if index+1 < len(lower) && lower[index+1] == "open" {
				return DefenseClawControlDisable, true
			}
		case "config":
			if index+1 < len(lower) {
				switch lower[index+1] {
				case "set", "unset":
					return DefenseClawControlConfig, true
				case "migrate":
					return "", false
				}
			}
		}
	}
	for _, word := range lower {
		if defenseClawReadVerbs[word] {
			return "", true
		}
	}
	if len(words) == 0 {
		// A bare program, --version, --help.
		return "", true
	}
	for _, flag := range flags {
		if defenseClawReadFlags[flag] {
			return "", true
		}
	}
	// A verb that relaxes the policy without naming a stop (a pack switch, a
	// suppression, a severity change, a trusted path) is a reading the rules
	// cannot prove either way; so is a call whose verb the parse left open.
	for _, word := range lower {
		if defenseClawRelaxVerbs[word] {
			return "", false
		}
	}
	if dynamic {
		return "", false
	}
	// Any other command (enterprise ensure, repair, skill install, setup)
	// changes nothing the guardrail rests on by itself.
	return "", true
}

// inlineScript returns the script text a PowerShell or cmd invocation runs
// from its command line and the dialect to read it in.
func inlineScript(program string, args []string) (string, Dialect) {
	for index, arg := range args {
		flag := strings.ToLower(arg)
		switch program {
		case "powershell", "pwsh":
			if flag == "-command" || flag == "-c" || flag == "-com" || flag == "-comm" {
				return strings.Join(args[index+1:], " "), DialectPowerShell
			}
		case "cmd":
			if flag == "/c" || flag == "/k" || flag == "/r" {
				return strings.Join(args[index+1:], " "), DialectCMD
			}
		}
	}
	return "", ""
}
