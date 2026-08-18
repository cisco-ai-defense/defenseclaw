// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// chooseRawCommandDialect infers a grammar only for exact, known generic
// execution tools. Explicit hints and Windows-owned tools always win. A
// POSIX-named tool also yields to a narrow native-Windows-plus-PowerShell
// compound signal because connector tool labels do not identify the host shell
// consistently on Windows. The boolean reports mixed grammar signals so callers
// can retain useful facts without treating the projection as authoritative.
func chooseRawCommandDialect(
	tool string,
	hint Dialect,
	source string,
) (Dialect, bool) {
	if hint != "" && hint != DialectNone {
		return hint, false
	}
	name := strings.ToLower(strings.TrimSpace(tool))
	switch name {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		return DialectPowerShell, false
	case "cmd", "cmd.exe":
		return DialectCMD, false
	case "bash", "sh", "zsh", "dash", "ksh", "mksh", "fish":
		first := commandProgramForDialect(
			strings.ToLower(rawFirstWord(source)),
			DialectPowerShell,
		)
		if (windowsNativeCommand(first) ||
			windowsExternalExecutable(first)) &&
			containsPowerShellCompoundCommand(source) {
			return DialectPowerShell, false
		}
		return DialectPOSIX, false
	}
	if !genericRawExecutionTool(name) {
		return DialectPOSIX, false
	}
	return inferRawCommandDialect(source)
}

func genericRawExecutionTool(name string) bool {
	switch name {
	case "shell", "shell_command", "terminal", "run_command",
		"run_shell", "run_shell_command", "runshellcommand",
		"run_terminal_cmd", "execute", "execute_command", "exec",
		"exec_command", "command", "subprocess", "system.run":
		return true
	default:
		return false
	}
}

func inferRawCommandDialect(source string) (Dialect, bool) {
	rawFirst := strings.ToLower(rawFirstWord(source))
	if rawFirst == "" {
		return DialectPOSIX, false
	}
	first := commandProgramForDialect(rawFirst, DialectPowerShell)

	windowsPathSignal := containsWindowsPathSignal(source)
	windowsPathOperand := containsExactWindowsPathOperand(source)
	windowsExternal := windowsPathOperand &&
		windowsExternalExecutable(rawFirst) &&
		!crossDialectShellLauncher(first)
	powerShellVariable := containsFold(source, "$env:")
	powerShellSwitch := containsPowerShellSwitch(source)
	powerShellCompound := containsPowerShellCompoundCommand(source)
	cmdSlashSwitch := containsKnownCMDSlashSwitch(first, source)
	posixSyntax := containsPOSIXSignalForProgram(first, source)
	filesystemAlias := powerShellFilesystemAlias(first)
	recognizedWindowsCommand := powerShellCmdlet(first) ||
		powerShellAlias(first) || filesystemAlias || cmdBuiltin(first) ||
		windowsNativeCommand(first) || crossPlatformCommand(first) ||
		variableShellCommand(first)

	powerShell := powerShellCmdlet(first) ||
		powerShellCompound ||
		((powerShellAlias(first) || filesystemAlias) &&
			(windowsPathOperand || powerShellSwitch)) ||
		(powerShellVariable && recognizedWindowsCommand)
	cmd := (containsCMDVariable(source) && recognizedWindowsCommand) ||
		(cmdBuiltin(first) &&
			(windowsPathOperand ||
				containsCMDQuotedOperand(source) ||
				cmdSlashSwitch)) ||
		((windowsNativeCommand(first) || crossPlatformCommand(first)) &&
			(windowsPathOperand || cmdSlashSwitch)) ||
		windowsExternal
	// An exact PowerShell cmdlet after an unquoted semicolon owns the grammar.
	// Native Windows executables such as reg.exe are valid PowerShell commands,
	// and their slash-prefixed operands are not evidence of a competing CMD
	// shell when the following statement is PowerShell-only.
	if powerShellCompound {
		cmd = false
	}

	// A path-shaped substring inside a filesystem alias operand is not enough
	// to select PowerShell. Keep quoted prose and other non-exact shapes on
	// fallback rather than parsing them as either authoritative shell.
	if filesystemAlias && windowsPathSignal && !windowsPathOperand &&
		!powerShellSwitch && !powerShellVariable {
		return DialectPOSIX, true
	}

	switch {
	case powerShell && !cmd && !posixSyntax:
		return DialectPowerShell, false
	case cmd && !powerShell && !posixSyntax:
		return DialectCMD, false
	case !powerShell && !cmd:
		return DialectPOSIX, false
	case powerShell:
		return DialectPowerShell, true
	case cmd:
		return DialectCMD, true
	default:
		return DialectPOSIX, true
	}
}

func windowsExternalExecutable(executable string) bool {
	name := strings.ToLower(strings.ReplaceAll(executable, `\`, "/"))
	if index := strings.LastIndexByte(name, '/'); index >= 0 {
		name = name[index+1:]
	}
	return strings.HasSuffix(name, ".exe") ||
		strings.HasSuffix(name, ".cmd")
}

func crossDialectShellLauncher(program string) bool {
	program = strings.TrimSuffix(program, ".exe")
	switch program {
	case "bash", "sh", "zsh", "dash", "ksh", "mksh", "fish",
		"cmd", "powershell", "pwsh":
		return true
	default:
		return false
	}
}

func rawFirstWord(source string) string {
	source = strings.TrimLeftFunc(source, unicode.IsSpace)
	if source == "" {
		return ""
	}
	var quote rune
	var value strings.Builder
	for index, char := range source {
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			value.WriteRune(char)
			continue
		}
		if char == '\'' || char == '"' {
			if index == 0 {
				quote = char
				continue
			}
			break
		}
		if unicode.IsSpace(char) || strings.ContainsRune("|&;<>", char) {
			break
		}
		value.WriteRune(char)
	}
	return value.String()
}

func powerShellCmdlet(program string) bool {
	switch program {
	case "get-content", "set-content", "add-content", "out-file",
		"remove-item", "get-childitem", "new-item", "test-path", "get-item",
		"get-itemproperty", "set-item", "set-itemproperty",
		"new-itemproperty", "remove-itemproperty", "copy-item", "move-item",
		"select-string", "invoke-webrequest", "invoke-restmethod",
		"start-process", "get-process", "stop-process", "remove-process",
		"clear-disk", "add-localgroupmember", "get-localgroupmember",
		"add-adgroupmember", "get-adgroupmember", "register-scheduledtask",
		"write-output", "write-host", "get-date":
		return true
	default:
		return false
	}
}

func powerShellAlias(program string) bool {
	switch program {
	case "gc", "gci", "gi", "gp", "sp", "rp", "ri", "ni", "iwr", "irm":
		return true
	default:
		return false
	}
}

func powerShellFilesystemAlias(program string) bool {
	switch program {
	case "rm", "cp", "mv", "cat", "ls":
		return true
	default:
		return false
	}
}

func cmdBuiltin(program string) bool {
	switch program {
	case "type", "dir", "del", "erase", "rmdir", "rd", "mkdir", "md",
		"copy", "move", "set", "ver":
		return true
	default:
		return false
	}
}

func windowsNativeCommand(program string) bool {
	switch program {
	case "xcopy", "robocopy", "schtasks", "net", "icacls", "takeown",
		"taskkill", "reg", "reg.exe":
		return true
	default:
		return false
	}
}

// containsPowerShellCompoundCommand recognizes only a literal PowerShell
// cmdlet at the start of a later parsed statement. Reusing the bounded
// PowerShell lexer keeps quoted prose, comments, stop-parsing tokens, and
// opaque dynamic constructs from becoming dialect signals.
func containsPowerShellCompoundCommand(source string) bool {
	if !strings.ContainsAny(source, ";|&\r\n") ||
		strings.Contains(source, `\;`) {
		// A backslash does not escape PowerShell separators, but it does in
		// POSIX shells. Keep that mixed form on the caller's declared grammar.
		return false
	}
	out := newParseOutput(DialectPowerShell, 1)
	lexemes, ok := windowsLex(source, windowsPowerShell, &out)
	if !ok {
		return false
	}
	commands, _, _ := windowsBuildCommands(lexemes, &out)
	for _, command := range commands[1:] {
		if command.callOperator || len(command.words) == 0 ||
			command.words[0].expands || command.words[0].quotedOnly {
			continue
		}
		candidate := commandProgramForDialect(
			strings.ToLower(command.words[0].value),
			DialectPowerShell,
		)
		if powerShellCmdlet(candidate) {
			return true
		}
	}
	return false
}

func crossPlatformCommand(program string) bool {
	switch program {
	case "more", "nmap", "naabu", "nc", "ncat", "netcat", "ssh", "git",
		"curl", "wget":
		return true
	default:
		return false
	}
}

func variableShellCommand(program string) bool {
	switch program {
	case "echo":
		return true
	default:
		return false
	}
}

func containsWindowsPathSignal(source string) bool {
	for index := 0; index+2 < len(source); index++ {
		if windowsPathStartBoundary(source, index) &&
			isASCIIAlpha(source[index]) && source[index+1] == ':' &&
			(source[index+2] == '\\' || source[index+2] == '/') &&
			!windowsPathCandidateInsideURI(source, index) {
			return true
		}
		if windowsPathStartBoundary(source, index) &&
			source[index] == '\\' && source[index+1] == '\\' &&
			source[index+2] != '\\' &&
			!byteAtIsSpaceOrDelimiter(source, index+2, "") &&
			!windowsPathCandidateInsideURI(source, index) {
			return true
		}
	}
	return false
}

// containsExactWindowsPathOperand recognizes an absolute drive or UNC path
// only when it is a complete token in the first simple command. Quotes may
// surround an operand, but path-shaped prose inside a larger quoted value does
// not select a Windows grammar.
func containsExactWindowsPathOperand(source string) bool {
	var token strings.Builder
	var quote rune
	tokenCount := 0
	tokenStarted := false
	found := false

	flush := func() {
		if !tokenStarted {
			return
		}
		tokenCount++
		if tokenCount > 1 && exactWindowsPathOperand(token.String()) {
			found = true
		}
		token.Reset()
		tokenStarted = false
	}

	for index, char := range source {
		if quote != 0 {
			if char == quote {
				quote = 0
				continue
			}
			token.WriteRune(char)
			tokenStarted = true
			continue
		}
		if char == '\'' || char == '"' {
			if index > 0 && source[index-1] == '\\' {
				return false
			}
			quote = char
			tokenStarted = true
			continue
		}
		if unicode.IsSpace(char) {
			if index > 0 && source[index-1] == '\\' {
				return false
			}
			flush()
			continue
		}
		if strings.ContainsRune("|&;<>", char) {
			flush()
			return found
		}
		token.WriteRune(char)
		tokenStarted = true
	}
	if quote != 0 {
		return false
	}
	flush()
	return found
}

func exactWindowsPathOperand(value string) bool {
	if strings.ContainsAny(value, "\r\n") {
		return false
	}
	if len(value) >= 3 &&
		isASCIIAlpha(value[0]) &&
		value[1] == ':' &&
		(value[2] == '\\' || value[2] == '/') {
		return true
	}
	return len(value) >= 3 &&
		value[0] == '\\' &&
		value[1] == '\\' &&
		value[2] != '\\' &&
		!byteAtIsSpaceOrDelimiter(value, 2, "")
}

func windowsPathStartBoundary(source string, index int) bool {
	if index == 0 {
		return true
	}
	before, _ := runeBeforeByteIndex(source, index)
	return unicode.IsSpace(before) ||
		strings.ContainsRune("\"'`=,:;([{|&<>", before)
}

func windowsPathCandidateInsideURI(source string, index int) bool {
	start := index
	for start > 0 {
		before, size := runeBeforeByteIndex(source, start)
		if unicode.IsSpace(before) ||
			strings.ContainsRune("\"'`|&;<>()[{", before) {
			break
		}
		start -= size
	}
	return strings.Contains(source[start:index], "://")
}

func containsCMDVariable(source string) bool {
	for start := strings.IndexByte(source, '%'); start >= 0; {
		rest := source[start+1:]
		end := strings.IndexByte(rest, '%')
		if end < 0 {
			return false
		}
		name := rest[:end]
		if name != "" {
			valid := true
			for index := 0; index < len(name); index++ {
				char := name[index]
				if !isASCIIAlpha(char) && (char < '0' || char > '9') &&
					char != '_' {
					valid = false
					break
				}
			}
			if valid {
				return true
			}
		}
		next := start + end + 2
		if next >= len(source) {
			return false
		}
		relative := strings.IndexByte(source[next:], '%')
		if relative < 0 {
			return false
		}
		start = next + relative
	}
	return false
}

func containsCMDQuotedOperand(source string) bool {
	for start := strings.IndexByte(source, '"'); start >= 0; {
		rest := source[start+1:]
		end := strings.IndexByte(rest, '"')
		if end < 0 {
			return false
		}
		value := rest[:end]
		if exactWindowsPathOperand(value) ||
			exactRelativeCMDPathOperand(value) {
			return true
		}
		next := start + end + 2
		if next >= len(source) {
			return false
		}
		relative := strings.IndexByte(source[next:], '"')
		if relative < 0 {
			return false
		}
		start = next + relative
	}
	return false
}

func exactRelativeCMDPathOperand(value string) bool {
	if value == "" ||
		strings.Contains(value, "://") ||
		strings.ContainsFunc(value, unicode.IsSpace) ||
		!strings.Contains(value, `\`) {
		return false
	}
	for _, component := range strings.Split(value, `\`) {
		if component == "" {
			return false
		}
	}
	return true
}

func containsPowerShellSwitch(source string) bool {
	lower := strings.ToLower(source)
	for _, option := range []string{
		"-literalpath", "-recurse", "-force", "-whatif", "-erroraction",
		"-itemtype", "-argumentlist", "-workingdirectory",
	} {
		if containsDelimitedFold(lower, option) {
			return true
		}
	}
	return false
}

func containsPOSIXSignal(source string) bool {
	first := commandProgramForDialect(
		strings.ToLower(rawFirstWord(source)),
		DialectCMD,
	)
	return containsPOSIXSignalForProgram(first, source)
}

func containsPOSIXSignalForProgram(program string, source string) bool {
	lower := strings.ToLower(source)
	if strings.Contains(lower, "$(") || strings.Contains(lower, "${") ||
		strings.Contains(lower, "`") {
		return true
	}
	for index := 0; index < len(source); index++ {
		if source[index] != '/' {
			continue
		}
		if index == 0 || byteBeforeIsSpaceOrDelimiter(source, index, "'\"=") {
			if index+1 < len(source) && source[index+1] != '/' &&
				!byteAtIsSpaceOrDelimiter(source, index+1, "") &&
				!knownCMDSlashSwitchAt(program, source, index) {
				return true
			}
		}
	}
	return strings.Contains(source, "~/") ||
		strings.Contains(source, "./") ||
		strings.Contains(source, "../")
}

func containsKnownCMDSlashSwitch(program string, source string) bool {
	for start := strings.IndexByte(source, '/'); start >= 0; {
		if knownCMDSlashSwitchAt(program, source, start) {
			return true
		}
		next := strings.IndexByte(source[start+1:], '/')
		if next < 0 {
			return false
		}
		start += next + 1
	}
	return false
}

func knownCMDSlashSwitchAt(program string, source string, start int) bool {
	if start < 0 || start >= len(source) || source[start] != '/' ||
		start > 0 && !byteBeforeIsSpaceOrDelimiter(source, start, "") {
		return false
	}
	end := start + 1
	for end < len(source) && !byteAtIsSpaceOrDelimiter(
		source,
		end,
		"'\"|&;<>()[{",
	) {
		_, size := runeAtByteIndex(source, end)
		end += size
	}
	if end == start+1 {
		return false
	}
	token := strings.ToLower(source[start:end])
	switch program {
	case "dir":
		return knownCMDDirSwitch(token)
	case "del", "erase":
		return token == "/p" || token == "/f" || token == "/s" ||
			token == "/q" || token == "/a" ||
			knownCMDSuffixedSwitch(token, "/a:", "drahsi-l")
	case "rmdir", "rd":
		return token == "/s" || token == "/q"
	case "copy":
		switch token {
		case "/d", "/v", "/n", "/y", "/-y", "/z", "/a", "/b":
			return true
		default:
			return false
		}
	case "xcopy", "xcopy.exe":
		switch token {
		case "/a", "/m", "/d", "/p", "/s", "/e", "/v", "/w", "/c",
			"/i", "/q", "/f", "/l", "/g", "/h", "/r", "/t", "/u",
			"/k", "/n", "/o", "/x", "/y", "/-y", "/z", "/b", "/j":
			return true
		default:
			return false
		}
	case "robocopy", "robocopy.exe":
		switch token {
		case "/s", "/e", "/mir":
			return true
		default:
			return false
		}
	case "cmd":
		switch token {
		case "/c", "/k", "/s", "/q", "/d", "/a", "/u":
			return true
		default:
			return false
		}
	case "reg", "reg.exe":
		switch token {
		case "/v", "/ve", "/va", "/t", "/s", "/d", "/f", "/c",
			"/e", "/se", "/z", "/reg:32", "/reg:64", "/?":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func knownCMDDirSwitch(token string) bool {
	switch token {
	case "/a", "/b", "/c", "/d", "/l", "/n", "/o", "/p", "/q",
		"/r", "/s", "/t", "/w", "/x", "/4":
		return true
	default:
		return knownCMDSuffixedSwitch(token, "/a:", "drahsi-l") ||
			knownCMDSuffixedSwitch(token, "/o:", "nedgs-") ||
			knownCMDSuffixedSwitch(token, "/t:", "caw")
	}
}

func knownCMDSuffixedSwitch(token string, prefix string, alphabet string) bool {
	if !strings.HasPrefix(token, prefix) || len(token) == len(prefix) {
		return false
	}
	for _, char := range token[len(prefix):] {
		if !strings.ContainsRune(alphabet, char) {
			return false
		}
	}
	return true
}

func containsFold(value, needle string) bool {
	return strings.Contains(strings.ToLower(value), strings.ToLower(needle))
}

func containsDelimitedFold(lowerValue, lowerNeedle string) bool {
	for start := strings.Index(lowerValue, lowerNeedle); start >= 0; {
		beforeOK := start == 0 ||
			byteBeforeIsSpaceOrDelimiter(lowerValue, start, "|&;(")
		end := start + len(lowerNeedle)
		afterOK := end == len(lowerValue) ||
			byteAtIsSpaceOrDelimiter(lowerValue, end, ":|&;)")
		if beforeOK && afterOK {
			return true
		}
		next := strings.Index(lowerValue[start+1:], lowerNeedle)
		if next < 0 {
			return false
		}
		start += next + 1
	}
	return false
}

func byteBeforeIsSpaceOrDelimiter(value string, index int, delimiters string) bool {
	if index <= 0 || index > len(value) {
		return false
	}
	r, _ := runeBeforeByteIndex(value, index)
	return unicode.IsSpace(r) || strings.ContainsRune(delimiters, r)
}

func byteAtIsSpaceOrDelimiter(value string, index int, delimiters string) bool {
	if index < 0 || index >= len(value) {
		return false
	}
	r, _ := runeAtByteIndex(value, index)
	return unicode.IsSpace(r) || strings.ContainsRune(delimiters, r)
}

func runeBeforeByteIndex(value string, index int) (rune, int) {
	last := value[index-1]
	if last < utf8.RuneSelf {
		return rune(last), 1
	}
	return utf8.DecodeLastRuneInString(value[:index])
}

func runeAtByteIndex(value string, index int) (rune, int) {
	first := value[index]
	if first < utf8.RuneSelf {
		return rune(first), 1
	}
	return utf8.DecodeRuneInString(value[index:])
}

func isASCIIAlpha(char byte) bool {
	return char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
}
