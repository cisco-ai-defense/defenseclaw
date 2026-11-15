// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
	"unicode"

	"mvdan.cc/sh/v3/syntax"
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
	// DefenseClawControlSubstrate is a Substrate command that changes
	// DefenseClaw's own state, configuration, credentials or session, or
	// starts, connects to or changes an agent runtime DefenseClaw governs
	// (defenseclaw substrate run, login, secrets set, template build; the
	// gateway's substrate-controller). A Substrate command that only reports
	// adds nothing.
	DefenseClawControlSubstrate DefenseClawControlKind = "substrate"
	// DefenseClawControlUnproven is a DefenseClaw command whose effect the
	// parse could not resolve (a changing verb that is not a known stop or
	// disable, a dynamic operand, an unparsed nested shell, a reading the
	// parse bounds cut). It is judged at the unknown tier.
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

// isDefenseClawWindowsServiceName is IsDefenseClawServiceName for the Windows
// service and task managers. The services and tasks the installers register
// are one CamelCase word (DefenseClawGateway, DefenseClawHookGuardian,
// DefenseClawCertGateway_<hex>); a name that continues the namespace with a
// hyphen or a dot (a lab task such as DefenseClaw-<test>-AuditTail) is
// somebody's own task, not one of the product's.
func isDefenseClawWindowsServiceName(name string) bool {
	if !IsDefenseClawServiceName(name) {
		return false
	}
	lower := strings.ToLower(strings.Trim(strings.TrimSpace(name), `"'`))
	if cut := strings.LastIndexAny(lower, `/\`); cut >= 0 {
		lower = lower[cut+1:]
	}
	lower = strings.TrimSuffix(lower, ".exe")
	index := strings.Index(lower, defenseClawNamespace)
	if index < 0 {
		return true
	}
	rest := lower[index+len(defenseClawNamespace):]
	return rest == "" || (rest[0] != '-' && rest[0] != '.')
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

// maxControlNesting bounds the nested scripts, launchers and fan-outs one call
// is followed through. A call that goes deeper while its text names DefenseClaw
// is judged at the unknown tier (ONE BOUND rule): what was read before the
// bound still decides.
const maxControlNesting = 8

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
	case "flock":
		skipOptions("-w", "-E", "--timeout", "--conflict-exit-code")
		if len(rest) > 0 {
			// flock FILE COMMAND: the lock file comes first.
			rest = rest[1:]
		}
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
		skipOptions("-u", "-g", "-G", "-s", "-l")
	case "systemd-run":
		skipOptions("-p", "--property", "-u", "--unit", "--uid", "--gid", "-E", "--setenv", "-M", "--machine",
			"--slice", "-H", "--host", "--description", "--working-directory", "-t")
	case "watch":
		skipOptions("-n", "--interval", "-d", "-w")
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

// shellProgram reports a POSIX-family shell that takes -c SCRIPT.
func shellProgram(name string) bool {
	switch name {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "rbash":
		return true
	}
	return false
}

// inlineCodeRunner reports an interpreter run with code on its command line
// (python -c, node -e, perl -e, ...). Its code is not shell, so it is not read.
func inlineCodeRunner(name string, args []string) bool {
	flag := ""
	switch {
	case strings.HasPrefix(name, "python"), name == "pypy", name == "pypy3":
		flag = "c"
	case name == "node", name == "nodejs", name == "bun", name == "deno", name == "perl", name == "ruby",
		name == "lua", name == "osascript":
		flag = "e"
	case name == "php":
		flag = "r"
	default:
		return false
	}
	for _, arg := range args {
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg[1:], flag) {
			return true
		}
		if arg == "--eval" || arg == "-E" && flag == "e" || arg == "--exec" {
			return true
		}
		if !strings.HasPrefix(arg, "-") {
			return false
		}
	}
	return false
}

// shellScript returns the script a shell runs through -c (any option cluster
// holding c: -c, -lc, -ic, -ec), and whether the invocation has one. The
// script word may be empty when the parse could not resolve it.
func shellScript(argv []string) (string, bool) {
	wantScript := false
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		switch {
		case arg == "--":
			if wantScript && index+1 < len(argv) {
				return argv[index+1], true
			}
			return "", wantScript
		case arg == "-o" || arg == "+o" || arg == "-O" || arg == "+O" || arg == "--rcfile" || arg == "--init-file":
			index++
		case strings.HasPrefix(arg, "--"):
		case len(arg) > 1 && (arg[0] == '-' || arg[0] == '+'):
			if arg[0] == '-' && strings.Contains(arg[1:], "c") {
				wantScript = true
			}
		default:
			if wantScript {
				return arg, true
			}
			return "", false
		}
	}
	return "", wantScript
}

// userSwitchScript returns the command string of su and runuser (-c,
// --command, a cluster holding c such as -lc), of sudo -s and sudo -i, and of
// script -c.
func userSwitchScript(argv []string, name string) (string, bool) {
	switch name {
	case "su", "runuser":
		for index := 1; index < len(argv); index++ {
			arg := argv[index]
			switch {
			case arg == "--command":
				if index+1 < len(argv) {
					return argv[index+1], true
				}
				return "", true
			case strings.HasPrefix(arg, "--command="):
				return strings.TrimPrefix(arg, "--command="), true
			case arg == "-s" || arg == "--shell" || arg == "-g" || arg == "-G" || arg == "-u" || arg == "-w":
				index++
			case strings.HasPrefix(arg, "--"):
			case len(arg) > 1 && arg[0] == '-' && strings.Contains(arg[1:], "c"):
				if index+1 < len(argv) {
					return argv[index+1], true
				}
				return "", true
			}
		}
	case "sudo", "doas":
		login := false
		for index := 1; index < len(argv); index++ {
			arg := argv[index]
			switch {
			case arg == "-i" || arg == "-s" || arg == "--login" || arg == "--shell":
				login = true
			case arg == "-u" || arg == "-g" || arg == "-h" || arg == "-p" || arg == "-C" || arg == "-r" ||
				arg == "-t" || arg == "-U" || arg == "-D" || arg == "-R" || arg == "-T":
				index++
			case strings.HasPrefix(arg, "-"):
			default:
				if login {
					return strings.Join(argv[index:], " "), true
				}
				return "", false
			}
		}
	case "script":
		for index := 1; index < len(argv); index++ {
			arg := argv[index]
			if arg == "--command" && index+1 < len(argv) {
				return argv[index+1], true
			}
			if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' && strings.Contains(arg[1:], "c") && index+1 < len(argv) {
				return argv[index+1], true
			}
		}
	}
	return "", false
}

// remoteInner returns the command ssh runs on its target. It runs in
// another login session, so what it holds is never better than the unknown
// tier.
func remoteInner(argv []string, name string) ([]string, bool) {
	if name != "ssh" {
		return nil, false
	}
	valued := map[string]bool{}
	for _, option := range []string{"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-E", "-m", "-O", "-S", "-w", "-W", "-B", "-I", "-Q"} {
		valued[option] = true
	}
	return afterOptions(argv[1:], valued, 1), true
}

// sshTargetIsLocal reports an ssh call whose host operand is the loopback
// address: the command it runs is on this host.
func sshTargetIsLocal(argv []string) bool {
	valued := map[string]bool{}
	for _, option := range []string{"-p", "-i", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-b", "-c", "-e", "-E", "-m", "-O", "-S", "-w", "-W", "-B", "-I", "-Q"} {
		valued[option] = true
	}
	operands := afterOptions(argv[1:], valued, 0)
	if len(operands) == 0 {
		return false
	}
	host := operands[0]
	if cut := strings.LastIndex(host, "@"); cut >= 0 {
		host = host[cut+1:]
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// afterOptions skips leading options (with the values of valued ones) and
// then skip operands, and returns what is left.
func afterOptions(args []string, valued map[string]bool, skip int) []string {
	index := 0
	for index < len(args) {
		arg := args[index]
		switch {
		case arg == "--":
			index++
			goto operands
		case strings.HasPrefix(arg, "-") && arg != "-":
			index++
			if valued[arg] && index < len(args) {
				index++
			}
		default:
			goto operands
		}
	}
operands:
	for ; skip > 0 && index < len(args); skip-- {
		index++
		// Options may follow the host operand.
		for index < len(args) && strings.HasPrefix(args[index], "-") && args[index] != "--" && len(args[index]) > 1 {
			index++
			if valued[args[index-1]] && index < len(args) {
				index++
			}
		}
	}
	if index >= len(args) {
		return nil
	}
	return args[index:]
}

// dynamicWord marks an operand that is filled in at run time.
const dynamicWord = ""

// fanOut returns the commands a launcher that feeds its operands from another
// source runs: find -exec/-execdir/-ok/-okdir, xargs and parallel. The words
// the source supplies are unresolved ("" in the argv); a find placeholder is
// the file the find expression selects, so when that expression names
// DefenseClaw the placeholder is that name.
func fanOut(argv []string, name string) ([][]string, bool) {
	switch name {
	case "find":
		var named string
		var inners [][]string
		for index := 1; index < len(argv); index++ {
			switch argv[index] {
			case "-exec", "-execdir", "-ok", "-okdir":
				end := index + 1
				for end < len(argv) && argv[end] != ";" && argv[end] != "+" {
					end++
				}
				inners = append(inners, slices.Clone(argv[index+1:end]))
				index = end
			default:
				if named == "" && containsFold(argv[index], defenseClawNamespace) {
					named = argv[index]
				}
			}
		}
		if len(inners) == 0 {
			return nil, false
		}
		for _, inner := range inners {
			for position, word := range inner {
				if strings.Contains(word, "{}") {
					inner[position] = strings.ReplaceAll(word, "{}", named)
					if named == "" {
						inner[position] = dynamicWord
					}
				}
			}
		}
		return inners, true
	case "xargs":
		rest := argv[1:]
		valued := map[string]bool{"-n": true, "-P": true, "-d": true, "-L": true, "-E": true, "-s": true, "-a": true, "-l": true}
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") && rest[0] != "--" {
			option := rest[0]
			rest = rest[1:]
			if valued[option] && len(rest) > 0 {
				rest = rest[1:]
			}
			if option == "-I" || option == "-i" || option == "--replace" {
				// -I TOKEN: the next word names the replacement string.
				if option == "-I" && len(rest) > 0 {
					rest = rest[1:]
				}
			}
		}
		if len(rest) > 0 && rest[0] == "--" {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return nil, false
		}
		inner := slices.Clone(rest)
		for position, word := range inner {
			if word == "{}" {
				inner[position] = dynamicWord
			}
		}
		return [][]string{append(inner, dynamicWord)}, true
	case "parallel":
		cut := slices.Index(argv, ":::")
		if cut < 0 {
			cut = len(argv)
		}
		rest := argv[1:cut]
		for len(rest) > 0 && strings.HasPrefix(rest[0], "-") {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return nil, false
		}
		return [][]string{append(slices.Clone(rest), dynamicWord)}, true
	}
	return nil, false
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
// guardrail answers in the agent's favour. A call whose text names DefenseClaw
// and whose commands the parse could not resolve (a program in a variable, a
// script fed to a shell on stdin, a reading cut by the parse bounds) is the
// unknown tier, never a clean allow.
func DefenseClawControl(facts Facts, text string) []DefenseClawControlFact {
	reader := &controlReader{seen: map[DefenseClawControlFact]bool{}}
	reader.read(facts, text, 0)
	return reader.out
}

type controlReader struct {
	out  []DefenseClawControlFact
	seen map[DefenseClawControlFact]bool
	// remote counts the launchers (ssh, docker exec) the reading is inside:
	// what they run is not this host's guard, so it never counts as proven.
	remote int
}

func (r *controlReader) add(fact DefenseClawControlFact) {
	if fact.Proven && r.remote > 0 {
		fact = DefenseClawControlFact{Kind: DefenseClawControlUnproven}
	}
	if !r.seen[fact] {
		r.seen[fact] = true
		r.out = append(r.out, fact)
	}
}

func (r *controlReader) hasProven() bool {
	for _, fact := range r.out {
		if fact.Proven {
			return true
		}
	}
	return false
}

// commandArgv is the argv of one command with its program resolved as far as
// the parse allows: a program spelled with $HOME carries its home spelling.
func commandArgv(command CommandFact, facts Facts) []string {
	argv := command.Argv
	if len(argv) == 0 && command.Executable != "" {
		argv = []string{command.Executable}
	}
	if len(argv) > 0 && argv[0] == "" && len(command.Arguments) > 0 {
		if spelling := command.Arguments[0].homeSpelling; strings.HasPrefix(spelling, "~") && facts.ActiveHome != "" {
			argv = slices.Clone(argv)
			argv[0] = strings.TrimRight(facts.ActiveHome, `/\`) + spelling[1:]
		}
	}
	return argv
}

func (r *controlReader) read(facts Facts, text string, depth int) {
	if !containsFold(text, defenseClawNamespace) {
		return
	}
	unresolved := false
	switch facts.Parse.Status {
	case StatusInvalid, StatusLimitExceeded:
		// The POSIX grammar rejected the text (a here-string, for one) or a
		// bound cut the parse, so the facts hold none or part of its
		// commands. The commands of a bash parse of the text are judged
		// instead, with no bound but the number of commands, and its
		// here-documents and here-strings are read as the scripts they are.
		if commands := bashCommands(text); len(commands) > 0 {
			facts.Commands = commands
			// More commands than the bound reads: the rest is unresolved.
			unresolved = len(commands) >= maxBashCommands
		}
		for _, body := range heredocBodies(text) {
			if containsFold(body, defenseClawNamespace) {
				r.script(facts, body, depth)
			}
		}
	case StatusAmbiguous, StatusUnsupported:
		// A construct the parse does not model: unresolved when it left no
		// command to judge.
		unresolved = len(facts.Commands) == 0
	}
	// What a bound cut and the bash parse could not place is the shared cap
	// floor's reading (internal/gateway cap floor, ONE BOUND rule), not a
	// second one here.
	commands := facts.Commands
	needTwin := false
	for _, command := range commands {
		if command.Kind != "" && command.Kind != CommandKindProcess {
			continue
		}
		if argv := commandArgv(command, facts); len(argv) > 0 && argv[0] == "" {
			needTwin = true
		}
	}
	if needTwin && facts.ActiveHome != "" && facts.Parse.Dialect == DialectPOSIX {
		// A program named with ~ or $HOME is read on the home-resolved twin
		// of the call, as the other readers do.
		if twin, ok := HomeResolvedTwin(Input{Tool: facts.Tool, Command: text, CWD: facts.CWD, ActiveHome: facts.ActiveHome}); ok {
			facts, commands = twin, twin.Commands
			needTwin = false
		}
	}
	skipUnresolved := 0
	if needTwin && facts.ActiveHome != "" && facts.Parse.Dialect == DialectPOSIX {
		// HomeResolvedTwin declined (another word of the call is dynamic): a
		// program that starts with an unquoted ~ is still the home path.
		if tilde, count, ok := tildeProgramText(text, facts.ActiveHome); ok {
			r.read(Analyze(Input{Tool: facts.Tool, Command: tilde, CWD: facts.CWD, ActiveHome: facts.ActiveHome}), tilde, depth+1)
			skipUnresolved = count
		}
	}
	aliases := map[string][]string{}
	for _, command := range commands {
		if command.Kind != "" && command.Kind != CommandKindProcess {
			continue
		}
		argv := commandArgv(command, facts)
		if len(argv) == 0 {
			continue
		}
		if commandBaseName(argv[0]) == "alias" {
			for _, word := range argv[1:] {
				if name, value, ok := strings.Cut(word, "="); ok && name != "" {
					aliases[name] = strings.Fields(value)
				}
			}
			continue
		}
		if value, ok := aliases[argv[0]]; ok && len(value) > 0 {
			argv = append(slices.Clone(value), argv[1:]...)
		}
		if argv[0] == "" && skipUnresolved > 0 {
			skipUnresolved--
			continue
		}
		if r.command(facts, text, command, argv, depth, 0) {
			unresolved = true
		}
	}
	if unresolved && !r.hasProven() && namesProduct(text) {
		r.add(DefenseClawControlFact{Kind: DefenseClawControlUnproven})
	}
}

// script reads the text a nested shell runs. It reports a script that could
// not be read (empty, unresolved, past the nesting bound).
func (r *controlReader) script(facts Facts, script string, depth int) bool {
	if strings.TrimSpace(script) == "" || depth+1 > maxControlNesting {
		return true
	}
	inner := Analyze(Input{Tool: "Bash", Command: script, CWD: facts.CWD, ActiveHome: facts.ActiveHome})
	r.read(inner, script, depth+1)
	return false
}

// command judges one command, following wrappers, nested shells and fan-out
// launchers. It reports a command whose effect could not be resolved.
func (r *controlReader) command(facts Facts, text string, command CommandFact, argv []string, depth, hops int) bool {
	for ; hops < maxControlNesting && len(argv) > 0; hops++ {
		if argv[0] == "" {
			// The program is a word the parse could not resolve (a variable, a
			// substitution): the call is unresolved when what follows reads as
			// a DefenseClaw stop, disable or uninstall (or is itself open).
			kind, _ := judgeDefenseClawCLI(argv[1:], defenseClawNamespace, slices.Contains(argv[1:], ""))
			return kind != ""
		}
		name := commandBaseName(argv[0])
		if shellProgram(name) {
			if script, ok := shellScript(argv); ok {
				return r.script(facts, script, depth)
			}
		}
		if script, ok := userSwitchScript(argv, name); ok {
			return r.script(facts, script, depth)
		}
		if inner, ok := remoteInner(argv, name); ok {
			// ssh to another machine, a container or a cluster runs somewhere
			// else: the guard of this host is not the one it stops. Only a
			// loopback target is this host.
			if len(inner) == 0 || !sshTargetIsLocal(argv) {
				return false
			}
			r.remote++
			defer func() { r.remote-- }()
			if len(inner) == 1 && strings.ContainsAny(inner[0], " \t") {
				return r.script(facts, inner[0], depth)
			}
			argv = inner
			continue
		}
		if inners, ok := fanOut(argv, name); ok {
			unresolved := false
			for _, inner := range inners {
				if r.command(facts, text, command, inner, depth, hops+1) {
					unresolved = true
				}
			}
			return unresolved
		}
		if name == "watch" || name == "systemd-run" {
			// A single quoted word is a command line.
			if inner := launcherInner(argv); len(inner) == 1 && strings.ContainsAny(inner[0], " \t") {
				return r.script(facts, inner[0], depth)
			}
		}
		inner := launcherInner(argv)
		if inner == nil {
			break
		}
		argv = inner
	}
	if len(argv) == 0 || argv[0] == "" {
		return len(argv) > 0
	}
	if hops >= maxControlNesting {
		return true
	}
	return r.judge(facts, text, command, argv, depth)
}

func (r *controlReader) judge(facts Facts, text string, command CommandFact, argv []string, depth int) bool {
	proven := func(kind DefenseClawControlKind) bool {
		r.add(DefenseClawControlFact{Kind: kind, Proven: true})
		return false
	}
	unproven := func() bool {
		r.add(DefenseClawControlFact{Kind: DefenseClawControlUnproven})
		return false
	}
	// A word the parse could not resolve (a substitution, a variable, a
	// tilde) has no value in argv.
	dynamic := slices.ContainsFunc(argv[1:], func(word string) bool { return word == "" || strings.HasPrefix(word, "$") })
	if program := defenseClawProgramName(argv); program != "" {
		kind, decided := judgeDefenseClawCLI(argv[1:], program, dynamic)
		if decided {
			if kind == "" {
				return false
			}
			return proven(kind)
		}
		return unproven()
	}
	name := commandBaseName(argv[0])
	words, flags := splitOperands(argv[1:])
	switch name {
	case "systemctl", "service", "launchctl", "sc", "net", "net1", "stop-service",
		"set-service", "remove-service", "schtasks", "stop-scheduledtask",
		"disable-scheduledtask", "unregister-scheduledtask", "initctl", "rc-service":
		if name == "systemctl" {
			words = systemctlOperands(argv[1:])
		}
		if kind, ok := serviceManagerStopsDefenseClaw(name, words, flags); ok {
			return proven(kind)
		}
		if serviceManagerStopVerb(name, words, flags) && dynamic &&
			r.pipelineNamesProcess(facts, command) {
			return proven(DefenseClawControlStop)
		}
		if serviceManagerStopVerb(name, words, flags) && dynamic && namesProduct(text) {
			// Its target is a word the parse could not resolve, in a call that
			// names DefenseClaw.
			return unproven()
		}
	case "kill", "killall", "pkill", "taskkill", "stop-process":
		if slices.Contains(flags, "-0") || slices.Contains(flags, "-l") {
			// kill -0 probes whether a process exists; kill -l lists signals.
			break
		}
		if killTargetsDefenseClaw(words) {
			return proven(DefenseClawControlStop)
		}
		if (dynamic || len(words) == 0) && (childNamesProcess(facts, command) || r.pipelineNamesProcess(facts, command)) {
			return proven(DefenseClawControlStop)
		}
		if (dynamic || name == "pkill") && pidFileInState(text, facts.ActiveHome) &&
			(dynamic && name != "pkill" || slices.ContainsFunc(words, func(word string) bool { return pidFileInState(word, facts.ActiveHome) })) {
			// kill of a pid read from the product's own state folder.
			return proven(DefenseClawControlStop)
		}
		// A kill whose target is a pid read from some other file or a
		// substitution names no process the parse can tie to DefenseClaw.
	case "powershell", "pwsh", "cmd":
		// An inline script the parse did not open is read again in its own
		// dialect; whatever it stops or disables is judged like a command of
		// the call.
		if script, dialect := inlineScript(name, argv[1:]); script != "" {
			tool := "Bash"
			if dialect == DialectPowerShell {
				tool = "PowerShell"
			}
			if depth+1 > maxControlNesting {
				return true
			}
			r.read(Analyze(Input{Tool: tool, Command: script, DialectHint: dialect, CWD: facts.CWD, ActiveHome: facts.ActiveHome}), script, depth+1)
		}
	case "eval":
		// eval runs its operands as a script.
		if dynamic {
			return true
		}
		return r.script(facts, strings.Join(argv[1:], " "), depth)
	case "pip", "pip3", "pipx", "uv", "brew", "rpm", "dnf", "yum", "apt", "apt-get", "dpkg", "zypper",
		"apk", "pacman", "winget", "choco", "scoop", "snap", "flatpak", "npm", "conda", "mamba", "port", "pkg":
		if packageManagerRemovesDefenseClaw(name, words, flags) {
			return proven(DefenseClawControlUninstall)
		}
	default:
		if inlineCodeRunner(name, argv[1:]) {
			// Inline interpreter code is not shell. Each string literal of the
			// code, and the literals joined (an argument list), is read as a
			// command line; what a literal does to DefenseClaw is the unknown
			// tier at best, and code that only names the product (an import,
			// a version print) is not a finding.
			r.remote++
			defer func() { r.remote-- }()
			literals := codeStringLiterals(strings.Join(argv[1:], " "))
			candidates := append([]string{strings.Join(literals, " ")}, literals...)
			for _, candidate := range candidates {
				if containsFold(candidate, defenseClawNamespace) {
					r.script(facts, candidate, depth)
				}
			}
			return false
		}
		if (shellProgram(name) || name == "at" || name == "batch") && stdinRunner(argv[1:]) {
			// A shell fed a script on stdin. A here-document or here-string
			// body is read as the script it is; so is the text of a producer
			// in the pipeline that names DefenseClaw (echo, printf). A
			// producer whose output is not in the parse (a file, a download)
			// leaves the script unresolved only when its own words name the
			// product.
			unresolved := false
			for _, body := range heredocBodies(text) {
				if containsFold(body, defenseClawNamespace) {
					r.script(facts, body, depth)
				}
			}
			if command.PipelineID != 0 {
				for _, producer := range facts.Commands {
					if producer.PipelineID != command.PipelineID || producer.ID >= command.ID || len(producer.Argv) == 0 {
						continue
					}
					if !namesProduct(strings.Join(producer.Argv, " ")) {
						continue
					}
					switch commandBaseName(producer.Argv[0]) {
					case "echo", "printf":
						r.script(facts, strings.Join(producer.Argv[1:], " "), depth)
					default:
						if len(facts.Network) == 0 {
							unresolved = true
						}
					}
				}
			}
			return unresolved
		}
	}
	return false
}

// stdinRunner reports a shell invocation with no script operand: it reads
// the commands from stdin.
func stdinRunner(args []string) bool {
	for _, arg := range args {
		if arg == "-" || arg == "-s" || arg == "-l" || arg == "-i" || arg == "--login" {
			continue
		}
		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, "c") {
			continue
		}
		return false
	}
	return true
}

// systemctlOperands returns the operands of a systemctl call with the values
// of its valued options (-M HOST, -t TYPE, --signal S, ...) removed.
func systemctlOperands(args []string) []string {
	var words []string
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch {
		case arg == "-M" || arg == "--machine" || arg == "-H" || arg == "--host" || arg == "-t" || arg == "--type" ||
			arg == "-s" || arg == "--signal" || arg == "-n" || arg == "--lines" || arg == "-o" || arg == "--output" ||
			arg == "--root" || arg == "-p" || arg == "--property" || arg == "--kill-whom" || arg == "--kill-who":
			index++
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
		default:
			words = append(words, arg)
		}
	}
	return words
}

// packageManagerRemovesDefenseClaw reports a package-manager call that
// removes the DefenseClaw package or its service (pip uninstall, uv tool
// uninstall, brew uninstall / services stop, rpm -e, dnf/yum/apt remove,
// dpkg -r / -P, pacman -R).
func packageManagerRemovesDefenseClaw(manager string, words, flags []string) bool {
	named := false
	for _, word := range words {
		if IsDefenseClawServiceName(word) || strings.HasPrefix(strings.ToLower(word), defenseClawNamespace) {
			named = true
		}
	}
	if !named {
		return false
	}
	for _, word := range words {
		switch strings.ToLower(word) {
		case "uninstall", "remove", "erase", "purge", "autoremove", "del", "delete", "rm", "unlink":
			return true
		case "stop", "kill":
			if manager == "brew" && slices.Contains(words, "services") {
				return true
			}
		}
	}
	switch manager {
	case "rpm":
		return slices.Contains(flags, "-e") || slices.Contains(flags, "--erase")
	case "dpkg":
		return slices.Contains(flags, "-r") || slices.Contains(flags, "-p") || slices.Contains(flags, "--remove") || slices.Contains(flags, "--purge")
	case "pacman":
		return slices.ContainsFunc(flags, func(flag string) bool { return strings.HasPrefix(flag, "-r") })
	}
	return false
}

// pidFileInState reports a pid file in one of the product's own state folders
// named by the text: a path with a component ".defenseclaw" or "defenseclaw"
// that is under the caller's home (~, $HOME, the home path, %USERPROFILE%) or
// a system state root (/var/lib, /run, /etc, /opt, /Library,
// %ProgramData%). A pid file in a test home (a variable that is not HOME, a
// scratch folder) is that test's own gateway, not this host's guard.
func pidFileInState(text, home string) bool {
	for start := 0; ; {
		index := strings.Index(strings.ToLower(text[start:]), ".pid")
		if index < 0 {
			return false
		}
		index += start
		begin := index
		for begin > 0 && !strings.ContainsRune(" \t\r\n'\"`();|&<>=", rune(text[begin-1])) {
			begin--
		}
		token := text[begin : index+len(".pid")]
		start = index + len(".pid")
		slash := func(char rune) bool { return char == '/' || char == '\\' }
		prefix, found := "", false
		for rest, consumed := token, 0; ; {
			cut := strings.IndexFunc(rest, slash)
			segment := rest
			if cut >= 0 {
				segment = rest[:cut]
			}
			if lower := strings.ToLower(segment); lower == defenseClawNamespace || lower == "."+defenseClawNamespace {
				prefix, found = token[:consumed], true
				break
			}
			if cut < 0 {
				break
			}
			consumed += cut + 1
			rest = rest[cut+1:]
		}
		if !found {
			continue
		}
		lowerPrefix := strings.ToLower(prefix)
		switch {
		case strings.HasPrefix(prefix, "~/"), strings.HasPrefix(prefix, "$HOME/"), strings.HasPrefix(prefix, "${HOME}/"),
			strings.HasPrefix(lowerPrefix, "%userprofile%"), strings.HasPrefix(lowerPrefix, "$env:userprofile"),
			strings.HasPrefix(lowerPrefix, "%programdata%"), strings.HasPrefix(lowerPrefix, "$env:programdata"):
			return true
		case home != "" && strings.HasPrefix(prefix, strings.TrimRight(home, `/\`)+"/"):
			return true
		}
		for _, root := range []string{"/var/lib/", "/var/run/", "/run/", "/etc/", "/opt/", "/library/", "/private/var/", "c:\\programdata\\"} {
			if strings.HasPrefix(lowerPrefix, root) {
				return true
			}
		}
	}
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
	windows := false
	switch manager {
	case "sc", "net", "net1", "stop-service", "set-service", "remove-service", "schtasks",
		"stop-scheduledtask", "disable-scheduledtask", "unregister-scheduledtask":
		windows = true
	}
	for _, word := range words {
		if windows && isDefenseClawWindowsServiceName(word) || !windows && IsDefenseClawServiceName(word) {
			return DefenseClawControlStop, true
		}
	}
	return "", false
}

// processPatternNamesDefenseClaw reports a process-name or image-name operand
// (a pkill or killall pattern, a taskkill /IM image, Stop-Process -Name) that
// selects a DefenseClaw program: the program word of the pattern, without its
// path, anchors and extension, starts with the product namespace. A pattern
// that names DefenseClaw only inside another program's command line (a pytest
// run on a DefenseClaw checkout) selects that other program.
func processPatternNamesDefenseClaw(word string) bool {
	word = strings.ToLower(strings.TrimSpace(strings.Trim(word, `"'`)))
	word = strings.TrimLeft(word, `^(\`)
	for strings.HasPrefix(word, ".*") {
		word = word[2:]
	}
	if cut := strings.IndexAny(word, " \t"); cut > 0 {
		word = word[:cut]
	}
	word = strings.Trim(word, `"'()`)
	if cut := strings.LastIndexAny(word, `/\`); cut >= 0 {
		word = word[cut+1:]
	}
	word = strings.TrimSuffix(word, ".exe")
	return strings.HasPrefix(word, defenseClawNamespace)
}

// killTargetsDefenseClaw reports a process-name or image-name operand that
// names a DefenseClaw program.
func killTargetsDefenseClaw(words []string) bool {
	return slices.ContainsFunc(words, processPatternNamesDefenseClaw)
}

// childNamesProcess reports a command nested in command (a substitution such
// as the pid lookup of a kill) that selects a DefenseClaw process.
func childNamesProcess(facts Facts, command CommandFact) bool {
	for _, other := range facts.Commands {
		if other.ParentCommandID != command.ID || command.ID == 0 {
			continue
		}
		if slices.ContainsFunc(other.Argv, func(word string) bool { return word != "" && processPatternNamesDefenseClaw(word) }) {
			return true
		}
	}
	return false
}

// pipelineNamesProcess reports another command of the same pipeline that
// selects a DefenseClaw process (Get-Process defenseclaw* | Stop-Process).
func (r *controlReader) pipelineNamesProcess(facts Facts, command CommandFact) bool {
	if command.PipelineID == 0 {
		return false
	}
	for _, other := range facts.Commands {
		if other.PipelineID != command.PipelineID || other.ID == command.ID {
			continue
		}
		if slices.ContainsFunc(other.Argv, func(word string) bool { return word != "" && processPatternNamesDefenseClaw(word) }) {
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
	// defenseClawReadFlags make the call run nothing: help, version, and the
	// check and dry-run switches of the commands that have them.
	defenseClawReadFlags = map[string]bool{
		"--version": true, "-v": true, "-version": true, "--help": true, "-h": true, "-help": true,
		"--check": true, "--dry-run": true, "--dryrun": true,
	}
	// defenseClawGuardGroups are the command groups whose disable subcommand
	// turns a guardrail part off. Every `disable` the CLI registers that does
	// so lives under the guardrail group (guardrail disable, guardrail
	// protection disable, guardrail rule disable, guardrail secret-flow
	// disable); the disable of a skill, plugin, webhook, observability sink,
	// discovery or routing does not touch the guardrail. A drift test walks the
	// registrations.
	defenseClawGuardGroups = map[string]bool{"guardrail": true}
	// defenseClawWeakValues are the values of a mode option that move a guard to
	// a weaker state.
	defenseClawWeakValues = map[string]bool{"observe": true, "open": true}
	// defenseClawSubstrateCommands are the Substrate commands: the
	// `substrate` group of both CLIs and the gateway's substrate-* components
	// (the controller, the egress callout, the bundle tool and the chart and
	// volume steps). Their verbs are classified by the tables below, not by
	// the verbs above, so a Substrate `set`, `run` or `apply` is not read as
	// some other group's verb.
	defenseClawSubstrateCommands = map[string]bool{
		"substrate": true, "substrate-bundle": true, "substrate-chart": true, "substrate-controller": true,
		"substrate-datadir": true, "substrate-extproc": true,
	}
	// defenseClawSubstrateGroups are the Substrate subcommand groups; the verb
	// is the word after them.
	defenseClawSubstrateGroups = map[string]bool{"policy": true, "bundle": true, "secrets": true, "template": true}
	// defenseClawSubstrateReadVerbs only report: status, lists, logs, usage,
	// the signed-in name, pending approvals, a policy explanation or offline
	// test, the setup checks, and the template verify and scan. Under
	// `secrets` only `list` is read (it prints names, scope, hosts and status,
	// never a value; api.Secret has no value field).
	defenseClawSubstrateReadVerbs = map[string]bool{
		"status": true, "list": true, "show": true, "logs": true, "usage": true, "whoami": true,
		"approvals": true, "explain": true, "verify": true, "doctor": true, "test": true, "scan": true,
		"info": true, "describe": true,
	}
	// defenseClawSubstrateStopVerbs change DefenseClaw's state, configuration,
	// credentials or session, or start, connect to or change an agent runtime.
	// A Substrate verb in neither table is judged the same way (an ambiguous
	// verb is a control); this table names the registered ones so the CLI
	// drift test can tell a new verb from a reviewed one.
	defenseClawSubstrateStopVerbs = map[string]bool{
		"run": true, "connect": true, "pull": true, "checkpoint": true, "undo": true, "delete": true,
		"migrate": true, "approve": true, "reject": true, "login": true, "logout": true, "set": true,
		"rm": true, "reset": true, "setup": true, "apply": true, "rollback": true, "build": true,
		"publish": true, "keygen": true, "serve": true,
	}
)

// guardGroupBefore reports a guardrail command group among the words before
// index (or, with index < 0, among all of them).
func guardGroupBefore(lower []string, index int) bool {
	if index < 0 || index > len(lower) {
		index = len(lower)
	}
	for _, word := range lower[:index] {
		if defenseClawGuardGroups[word] {
			return true
		}
	}
	return false
}

// judgeDefenseClawSubstrate classifies a Substrate command (ok is false for
// any other command). The verb is the first word after the command and an
// optional group: a read verb adds nothing, every other verb, and a verb the
// tables do not name, is a Substrate control. A bare `substrate` or
// `substrate GROUP`, and the bare bundle and chart tools, only print their
// help; the bare controller, callout and volume step run.
func judgeDefenseClawSubstrate(lower []string) (kind DefenseClawControlKind, ok bool) {
	if len(lower) == 0 || !defenseClawSubstrateCommands[lower[0]] {
		return "", false
	}
	group, verb := "", ""
	for _, word := range lower[1:] {
		if group == "" && verb == "" && lower[0] == "substrate" && defenseClawSubstrateGroups[word] {
			group = word
			continue
		}
		verb = word
		break
	}
	switch {
	case verb == "":
		switch lower[0] {
		case "substrate", "substrate-bundle", "substrate-chart":
			return "", true
		}
		return DefenseClawControlSubstrate, true
	case group == "secrets":
		if verb == "list" {
			return "", true
		}
		return DefenseClawControlSubstrate, true
	case defenseClawSubstrateReadVerbs[verb]:
		return "", true
	}
	return DefenseClawControlSubstrate, true
}

// weakensMode reports a mode set to a weaker value through a verb
// (`guardrail mode observe`, `fail-mode open`, `hook-outage-mode open`) or an
// option (`--mode observe`, `--fail-mode=open`): any word or option whose name
// ends in "mode" followed by a weak value.
func weakensMode(args []string) bool {
	for index, arg := range args {
		lower := strings.ToLower(arg)
		value := ""
		name := strings.TrimLeft(lower, "-")
		if cut := strings.Index(name, "="); cut >= 0 {
			name, value = name[:cut], name[cut+1:]
		} else if index+1 < len(args) {
			value = strings.ToLower(args[index+1])
			if strings.HasPrefix(value, "-") && index+2 < len(args) {
				// A value flag between the name and the value (--set, --to).
				value = strings.ToLower(args[index+2])
			}
		}
		if strings.HasSuffix(name, "mode") && defenseClawWeakValues[strings.Trim(value, `"'`)] {
			return true
		}
	}
	return false
}

// judgeDefenseClawCLI classifies one defenseclaw or defenseclaw-gateway
// invocation. decided is false when the command is a changing verb the rules
// cannot name, or has an operand the parse left open before any verb.
func judgeDefenseClawCLI(args []string, program string, dynamic bool) (kind DefenseClawControlKind, decided bool) {
	words, flags := splitOperands(args)
	// A help, version, check or dry-run request runs nothing, whatever verb it
	// names.
	for _, flag := range flags {
		if defenseClawReadFlags[flag] {
			return "", true
		}
	}
	lower := make([]string, len(words))
	for index, word := range words {
		lower[index] = strings.ToLower(word)
	}
	for _, flag := range flags {
		if (flag == "--disable" || flag == "--uninstall") && (flag == "--uninstall" || guardGroupBefore(lower, -1)) {
			return DefenseClawControlDisable, true
		}
	}
	if weakensMode(args) {
		return DefenseClawControlDisable, true
	}
	if kind, ok := judgeDefenseClawSubstrate(lower); ok {
		return kind, true
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
			if index == 0 || guardGroupBefore(lower, index) {
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

// tildeProgramText rewrites the program word of each simple command that
// starts with an unquoted ~ into the home path, and returns the new text and
// the number of words it rewrote.
func tildeProgramText(text, home string) (string, int, bool) {
	home = strings.TrimRight(home, `/\`)
	if home == "" || strings.ContainsAny(home, " \t\r\n'\"`$\\") {
		return "", 0, false
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return "", 0, false
	}
	var offsets []int
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || len(call.Args[0].Parts) == 0 {
			return true
		}
		lit, ok := call.Args[0].Parts[0].(*syntax.Lit)
		if ok && strings.HasPrefix(lit.Value, "~/") {
			offsets = append(offsets, int(lit.ValuePos.Offset()))
		}
		return true
	})
	if len(offsets) == 0 {
		return "", 0, false
	}
	slices.Sort(offsets)
	for index := len(offsets) - 1; index >= 0; index-- {
		offset := offsets[index]
		if offset >= len(text) || text[offset] != '~' {
			return "", 0, false
		}
		text = text[:offset] + home + text[offset+1:]
	}
	return text, len(offsets), true
}

// codeStringLiterals returns the single- and double-quoted string literals of
// an inline program, without escapes resolved.
func codeStringLiterals(code string) []string {
	var literals []string
	for index := 0; index < len(code); index++ {
		quote := code[index]
		if quote != '\'' && quote != '"' {
			continue
		}
		end := index + 1
		for end < len(code) && code[end] != quote {
			if code[end] == '\\' {
				end++
			}
			end++
		}
		if end > len(code) {
			end = len(code)
		}
		if index+1 <= end {
			literals = append(literals, code[index+1:end])
		}
		index = end
	}
	return literals
}

// heredocBodies returns the text of each here-document and here-string of
// the call, with the parts the shell expands left out.
func heredocBodies(text string) []string {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return nil
	}
	var bodies []string
	syntax.Walk(file, func(node syntax.Node) bool {
		redir, ok := node.(*syntax.Redirect)
		if !ok {
			return true
		}
		var word *syntax.Word
		switch redir.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			word = redir.Hdoc
		case syntax.WordHdoc:
			word = redir.Word
		}
		if word == nil {
			return true
		}
		var body strings.Builder
		for _, part := range word.Parts {
			switch part := part.(type) {
			case *syntax.Lit:
				body.WriteString(part.Value)
			case *syntax.SglQuoted:
				body.WriteString(part.Value)
			case *syntax.DblQuoted:
				for _, inner := range part.Parts {
					if lit, ok := inner.(*syntax.Lit); ok {
						body.WriteString(lit.Value)
					}
				}
			}
		}
		bodies = append(bodies, body.String())
		return true
	})
	return bodies
}

// defenseClawUnitSegments are the parts after the product namespace that the
// installers' units, plists and labels use (defenseclaw-gateway,
// defenseclaw.hook-guardian, com.cisco.defenseclaw.sandbox). A drift test
// walks packaging/systemd, packaging/launchd and the standalone launchd
// folders and fails when an installer defines one this list lacks.
var defenseClawUnitSegments = map[string]bool{
	"enterprise-apply": true, "enterprise-verify": true, "gateway": true, "gateway-api": true,
	"gateway-hook": true, "hook-enumerator": true, "hook-guardian": true, "hook-guardian-reconcile": true,
	"openshell-gateway": true, "sandbox": true, "sensor-helper": true, "apply": true, "verify": true,
}

// namesProduct reports a call text that names the product itself: a word of
// the text that is the DefenseClaw program, one of the units, labels or
// services the installers register, or a Windows service in the product's
// CamelCase spelling. A path that only passes through a folder or a host
// named after the project (a checkout, a test file, an ssh alias) does not.
func namesProduct(text string) bool {
	separators := "\"'`;|&()<>=,{}[]$#"
	words := strings.FieldsFunc(text, func(char rune) bool { return unicode.IsSpace(char) || strings.ContainsRune(separators, char) })
	for _, word := range words {
		if !containsFold(word, defenseClawNamespace) {
			continue
		}
		base := word
		if cut := strings.LastIndexAny(base, `/\`); cut >= 0 {
			base = base[cut+1:]
		}
		base = strings.TrimSuffix(strings.TrimSuffix(base, ".exe"), ".EXE")
		for _, suffix := range []string{".service", ".socket", ".timer", ".path", ".target", ".plist"} {
			base = strings.TrimSuffix(base, suffix)
		}
		lower := strings.ToLower(base)
		for _, prefix := range []string{"com.cisco.secureclient.", "com.cisco."} {
			lower = strings.TrimPrefix(lower, prefix)
		}
		if !strings.HasPrefix(lower, defenseClawNamespace) {
			continue
		}
		rest := lower[len(defenseClawNamespace):]
		switch {
		case rest == "":
			// The program itself (lower case, as the installers spell it), not
			// the product's name in a title or a folder.
			if base == defenseClawNamespace {
				return true
			}
		case (rest[0] == '-' || rest[0] == '.') && defenseClawUnitSegments[rest[1:]]:
			return true
		}
		// A Windows service or task: DefenseClaw, then an upper-case letter or
		// an underscore (DefenseClawGateway, DefenseClawCertGuardian_<hex>).
		if index := strings.Index(strings.ToLower(base), defenseClawNamespace); index >= 0 && index+len(defenseClawNamespace) < len(base) {
			next := base[index+len(defenseClawNamespace)]
			if next >= 'A' && next <= 'Z' || next == '_' {
				return true
			}
		}
	}
	return false
}

// maxBashCommands bounds the commands read from the bash parse of a call the
// POSIX parse rejected or cut. Past it the call is unresolved.
const maxBashCommands = 4096

// bashCommands returns the simple commands of a bash parse of text, with a
// word that holds an expansion as "".
func bashCommands(text string) []CommandFact {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(text), "")
	if err != nil {
		return nil
	}
	var commands []CommandFact
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || len(commands) >= maxBashCommands {
			return true
		}
		argv := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			argv = append(argv, literalWordText(word))
		}
		commands = append(commands, CommandFact{ID: int64(len(commands) + 1), Kind: CommandKindProcess, Argv: argv, Executable: argv[0]})
		return true
	})
	return commands
}

// literalWordText is the text of a word that holds only literals and quotes,
// and "" when it holds an expansion.
func literalWordText(word *syntax.Word) string {
	var out strings.Builder
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			out.WriteString(part.Value)
		case *syntax.SglQuoted:
			out.WriteString(part.Value)
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return ""
				}
				out.WriteString(lit.Value)
			}
		default:
			return ""
		}
	}
	return out.String()
}
