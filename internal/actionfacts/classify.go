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
	"math"
	"net"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
)

func classifyOutput(out *parseOutput) {
	if out == nil {
		return
	}
	for i := range out.commands {
		classifyCommand(out, &out.commands[i])
		if out.status == StatusLimitExceeded {
			return
		}
	}
	deduplicateFacts(out)
}

func classifyCommand(out *parseOutput, command *CommandFact) {
	if command == nil || command.Executable == "" {
		return
	}
	if len(command.Argv) == 0 || command.Argv[0] == "" {
		command.Effect = EffectUncertain
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if command.Effect == "" {
		command.Effect = EffectExecute
	}
	if command.Program == "" {
		command.Program = commandProgram(command.Executable)
	}
	parserClassified := len(command.Operations) > 0
	program := command.Program
	addOperation(command, OperationExecute)
	if parserClassified {
		// Conservative dialect parsers own their operand grammar. Reclassifying
		// those argv values generically can mistake data values or switches for
		// paths, so only their structural redirects are shared here.
		classifyRedirects(out, command)
		return
	}
	if informationalInvocation(command) &&
		informationalNoopProgram(program) {
		command.Effect = EffectPreview
		classifyRedirects(out, command)
		return
	}

	switch program {
	case "cat":
		addOperation(command, OperationRead)
		addPathOperands(out, command, PathAccessRead, optionValues())
	case "head", "tail":
		addOperation(command, OperationRead)
		addPathOperands(out, command, PathAccessRead, optionValues(
			"-n", "--lines", "-c", "--bytes",
		))
	case "less", "more":
		addOperation(command, OperationRead)
		addPathOperands(out, command, PathAccessRead, optionValues())
	case "type":
		switch command.Dialect {
		case DialectCMD:
			addOperation(command, OperationRead)
			addPathOperands(out, command, PathAccessRead, optionValues())
		case DialectPowerShell:
			// PowerShell's type alias owns the Get-Content parameter
			// grammar. In particular, values for parameters such as
			// -Encoding are data and must not become read paths.
			classifyStructuredPowerShellGetContent(out, command)
		case DialectPOSIX:
			// POSIX type inspects command names; its operands are not paths.
		default:
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "get-content":
		classifyStructuredPowerShellGetContent(out, command)
	case "get-acl":
		classifyStructuredGetACL(out, command)
	case "get-itemproperty", "gp", "set-itemproperty", "sp",
		"new-itemproperty", "remove-itemproperty", "rp":
		classifyStructuredPowerShellRegistryProperty(out, command, program)
	case "gc":
		if requireCommandDialect(out, command, DialectPowerShell) {
			addOperation(command, OperationRead)
			addPathOperands(out, command, PathAccessRead, optionValues(
				"-encoding", "-totalcount", "-tail", "-filter", "-include",
				"-exclude",
			))
		}
	case "ls", "dir", "get-childitem":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellGetChildItem(out, command)
		} else {
			addOperation(command, OperationList)
			addPathOperands(out, command, PathAccessList, optionValues())
		}
	case "gci":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellGetChildItem(out, command)
		}
	case "grep", "rg", "ripgrep", "find", "fd":
		addOperation(command, OperationSearch)
		classifySearchPaths(out, command, program)
	case "getcap":
		classifyGetcap(out, command)
	case "where", "where.exe":
		// Windows where.exe has its own /R and /F operand grammar. Preserve
		// the search operation for detection, but keep the unowned argv
		// grammar non-authoritative.
		addOperation(command, OperationSearch)
		out.markPartial(IssueUnknownOperandGrammar)
	case "touch", "truncate":
		addOperation(command, OperationWrite)
		addPathOperands(out, command, PathAccessWrite, optionValues(
			"-s", "--size", "-encoding", "-width",
		))
	case "new-item", "ni":
		classifyStructuredPowerShellNewItem(out, command)
	case "mkdir", "md":
		// PowerShell exposes these names through wrapper functions whose exact
		// parameter binding is not represented by structured argv. Keep them on
		// fallback instead of treating the wrapper invocation as a complete
		// command with no write target.
		if command.Dialect != DialectPowerShell &&
			pathFlavor(command.Executable) != PathFlavorUnknown {
			appendPath(
				out,
				command.ID,
				PathAccessExecute,
				command.Executable,
			)
		}
		out.markPartial(IssueUnknownOperandGrammar)
	case "set-content", "out-file":
		classifyStructuredPowerShellPathMutator(out, command, program)
	case "sc":
		if command.Dialect == DialectPowerShell {
			if len(command.Argv) > 1 {
				classifyStructuredPowerShellPathMutator(out, command, "set-content")
			} else {
				addOperation(command, OperationWrite)
				out.markPartial(IssueUnknownOperandGrammar)
			}
		} else {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "sc.exe":
		classifyWindowsServiceControl(out, command)
	case "tee":
		classifyTee(out, command)
	case "add-content":
		classifyStructuredPowerShellPathMutator(out, command, program)
	case "ac":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellPathMutator(out, command, "add-content")
		}
	case "rm":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "remove-item")
		} else {
			classifyPOSIXRemove(out, command)
		}
	case "unlink":
		addOperation(command, OperationDelete)
		addPathOperands(out, command, PathAccessDelete, optionValues(
			"-filter", "-include", "-exclude",
		))
	case "rmdir":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "remove-item")
		} else {
			addOperation(command, OperationDelete)
			addPathOperands(out, command, PathAccessDelete, optionValues())
		}
	case "remove-item":
		classifyStructuredPowerShellPathMutator(out, command, program)
	case "rd", "del", "erase":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "remove-item")
		} else if requireCommandDialect(out, command, DialectCMD) {
			addOperation(command, OperationDelete)
			addPathOperands(out, command, PathAccessDelete, optionValues(
				"-filter", "-include", "-exclude",
			))
		}
	case "ri":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellPathMutator(out, command, "remove-item")
		}
	case "cp", "copy-item":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "copy-item")
		} else if program == "cp" {
			classifyPOSIXCopyMove(out, command, false)
		} else {
			classifyStructuredPowerShellPathMutator(out, command, program)
		}
	case "copy":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "copy-item")
		} else if requireCommandDialect(out, command, DialectCMD) {
			addOperation(command, OperationCopy)
			addSourceDestinationPaths(out, command, false)
		}
	case "cpi":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellPathMutator(out, command, "copy-item")
		}
	case "mv", "move-item", "rename-item":
		if command.Dialect == DialectPowerShell {
			mutator := program
			if program == "mv" {
				mutator = "move-item"
			}
			classifyStructuredPowerShellPathMutator(out, command, mutator)
		} else if program == "mv" {
			classifyPOSIXCopyMove(out, command, true)
		} else {
			classifyStructuredPowerShellPathMutator(out, command, program)
		}
	case "move", "ren":
		if command.Dialect == DialectPowerShell {
			classifyStructuredPowerShellPathMutator(out, command, "move-item")
		} else if requireCommandDialect(out, command, DialectCMD) {
			addOperation(command, OperationMove)
			addSourceDestinationPaths(out, command, true)
		}
	case "mi":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellPathMutator(out, command, "move-item")
		}
	case "rni":
		if requireCommandDialect(out, command, DialectPowerShell) {
			classifyStructuredPowerShellPathMutator(out, command, "rename-item")
		}
	case "chmod", "chown", "chgrp":
		classifyPOSIXPermissionChange(out, command, program)
	case "install":
		classifyPOSIXInstall(out, command)
	case "setfacl":
		classifySetfacl(out, command)
	case "setcap":
		classifySetcap(out, command)
	case "set-acl":
		classifyStructuredSetACL(out, command)
	case "icacls":
		classifyStructuredICACLS(out, command)
	case "takeown":
		classifyStructuredTakeown(out, command)
	case "curl", "curl.exe", "wget", "wget.exe",
		"invoke-webrequest", "iwr", "invoke-restmethod", "irm":
		classifyWebTransfer(out, command, program)
	case "ssh", "ssh.exe", "autossh", "autossh.exe", "sftp", "sftp.exe":
		classifySSH(out, command, program)
	case "scp":
		classifySCP(out, command)
	case "nc", "ncat", "netcat", "socat":
		classifySocketTool(out, command, program)
	case "chisel", "ligolo-agent", "ligolo-ng-agent", "cloudflared", "ngrok":
		classifyTunnel(out, command, program)
	case "nmap", "masscan", "fping":
		classifyNetworkScanner(out, command, program)
	case "naabu":
		classifyNaabu(out, command)
	case "dd":
		classifyDD(out, command)
	case "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mke2fs",
		"mkfs.xfs", "mkfs.btrfs", "mkfs.f2fs", "mkfs.vfat", "mkdosfs",
		"mkfs.ntfs", "mkntfs", "mkswap", "mkfs.exfat", "mkexfatfs":
		classifyPOSIXFilesystemFormat(out, command, program)
	case "wipefs":
		classifyWipeFS(out, command)
	case "sgdisk":
		classifySGDisk(out, command)
	case "shred", "blkdiscard", "cryptsetup", "hdparm", "nvme", "parted",
		"diskutil":
		classifyDestructiveDeviceTool(out, command, program)
	case "format":
		classifyWindowsFormat(out, command)
	case "format-volume":
		classifyStructuredPowerShellFormatVolume(out, command)
	case "kill", "killall", "pkill", "taskkill":
		if !processProbeInvocation(out, program, command.Argv) {
			addOperation(command, OperationProcessKill)
		}
	case "stop-process":
		classifyStructuredPowerShellStopProcess(out, command)
	case "clear-disk":
		classifyStructuredPowerShellClearDisk(out, command)
	case "base64", "openssl", "openssl.exe":
		classifyDecode(out, command, program)
	case "certutil", "certutil.exe":
		classifyStructuredWindowsArgv(
			out,
			command,
			windowsClassifyCertutil,
			DialectCMD,
		)
	case "sudo":
		classifySudo(out, command)
	case "doas", "su", "pkexec":
		classifyPOSIXPrivilegeShell(out, command)
	case "runas":
		addOperation(command, OperationPrivilege)
		out.markPartial(IssueUnsupportedConstruct)
	case "reg", "reg.exe":
		classifyStructuredWindowsArgv(
			out,
			command,
			windowsClassifyRegistry,
			DialectCMD,
			DialectPowerShell,
		)
	case "crontab", "at", "schtasks", "launchctl", "systemctl":
		classifySchedule(out, command, program)
	case "register-scheduledtask":
		classifyStructuredPowerShellRegisterScheduledTask(out, command)
	case "useradd", "usermod", "adduser", "net", "net1", "new-localuser", "gpasswd",
		"groupmems", "dseditgroup", "dscl":
		classifyAccount(out, command, program)
	case "add-localgroupmember":
		classifyStructuredPowerShellAddLocalGroupMember(out, command)
	case "add-adgroupmember":
		classifyStructuredPowerShellAddADGroupMember(out, command)
	case "get-localgroupmember":
		classifyStructuredPowerShellGroupQuery(out, command, false)
	case "get-adgroupmember":
		classifyStructuredPowerShellGroupQuery(out, command, true)
	case "env", "printenv", "set":
		addOperation(command, OperationEnvironmentRead)
	case "docker", "podman", "nerdctl":
		classifyContainer(out, command)
	case "nsenter":
		classifyNSEnter(out, command)
	case "chroot":
		classifyChroot(out, command)
	case "kubectl", "oc":
		classifyWorkload(out, command, program)
	case "git":
		classifyGit(out, command)
	case "codex", "claude", "gemini", "opencode":
		classifyAgentRuntime(out, command, program)
	case "npx", "pnpm", "bunx":
		classifyAgentPackageRunner(out, command, program)
	case "aws", "gcloud", "az", "vault", "op", "pass", "security", "cmdkey":
		classifyCredentialCLI(out, command, program)
	case "bash", "sh", "zsh", "dash", "ksh", "mksh", "fish":
		classifyShellInvocation(out, command)
	case "python", "python2", "python3", "perl", "ruby":
		classifyPOSIXStdinScriptInterpreter(out, command)
	case "history":
		classifyPOSIXHistory(out, command)
	case "unset":
		classifyPOSIXUnset(out, command)
	case "source", ".":
		classifySourceInvocation(out, command)
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		classifyPowerShellArtifactInvocation(out, command)
	case "cmd", "cmd.exe",
		"echo", "printf", "pwd", "cd", "true", "false", "sleep", "date",
		"whoami", "id", "uname", "test", "[", "expr", "read", "export",
		"setenv", "which", "command", "exec", "eval",
		"write-output", "write-host":
		// Known command grammar; the parser or wrapper analysis owns any nested
		// command source.
	default:
		if posixVersionedPythonProgram(program) {
			classifyPOSIXStdinScriptInterpreter(out, command)
			break
		}
		if pathFlavor(command.Executable) != PathFlavorUnknown {
			appendPath(out, command.ID, PathAccessExecute, command.Executable)
			// A statically named executable path may be a script. Its bytes are
			// intentionally opaque to ActionFacts, but an execution-boundary
			// consumer can reopen and parse the exact artifact conservatively.
			out.markPartial(IssueOpaqueArtifact)
			if _, windowsScript := windowsScriptProgram(
				command.Executable,
				command.Dialect,
			); windowsScript && len(command.Argv) != 1 {
				out.markPartial(IssueUnsupportedConstruct)
			}
			break
		}
		out.markPartial(IssueUnknownOperandGrammar)
	}

	classifyRedirects(out, command)
}

func classifyPOSIXHistory(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX) {
		return
	}
	if command.Executable != "history" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if len(command.Argv) == 1 {
		return
	}
	// History option semantics depend on the concrete shell (for example,
	// Bash and zsh assign different meanings to -c). Preserve the bounded
	// syntax for detection-only fallback, but never make it authoritative
	// without an authenticated shell identity.
	out.markPartial(IssueUnknownOperandGrammar)
}

// ProvesPOSIXHistoryClear reports whether a direct POSIX history builtin uses
// a bounded option grammar that includes the clear operation.
func ProvesPOSIXHistoryClear(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		command.Effect != EffectExecute ||
		!command.ArgvComplete || command.Executable != "history" {
		return false
	}
	return exactPOSIXHistoryClearArguments(command.Argv)
}

func exactPOSIXHistoryClearArguments(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	sawClear := false
	allowsFile := false
	options := true
	operands := 0
	for _, argument := range argv[1:] {
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "-") && argument != "-" {
			if len(argument) < 2 || argument[1] == '-' {
				return false
			}
			for _, option := range argument[1:] {
				switch option {
				case 'c':
					sawClear = true
				case 'a', 'n', 'r', 'w':
					allowsFile = true
				default:
					return false
				}
			}
			continue
		}
		options = false
		operands++
		if operands > 1 {
			return false
		}
	}
	return sawClear && (operands == 0 || allowsFile)
}

func classifyPOSIXUnset(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX) {
		return
	}
	if command.Executable != "unset" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	options := true
	for _, argument := range command.Argv[1:] {
		if options && argument == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(argument, "-") && argument != "-" {
			if !posixUnsetOptionBundle(argument) {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			continue
		}
		options = false
	}
}

func posixUnsetOptionBundle(argument string) bool {
	if len(argument) < 2 || argument[0] != '-' || argument[1] == '-' {
		return false
	}
	for _, option := range argument[1:] {
		if option != 'f' && option != 'v' {
			return false
		}
	}
	return true
}

func commandProgram(executable string) string {
	if strings.TrimSpace(executable) != executable || executable == "" {
		return ""
	}
	executable = strings.ReplaceAll(executable, `\`, "/")
	if strings.Contains(executable, "/") && !trustedExecutablePath(executable) {
		return ""
	}
	executable = path.Base(executable)
	if executable == "." || executable == "/" {
		return ""
	}
	return strings.ToLower(executable)
}

func commandProgramForDialect(executable string, dialect Dialect) string {
	if program, ok := windowsScriptProgram(executable, dialect); ok {
		return program
	}
	program := commandProgram(executable)
	if dialect != DialectCMD && dialect != DialectPowerShell {
		return program
	}
	suffix := ""
	switch {
	case strings.HasSuffix(program, ".exe"):
		suffix = ".exe"
	case strings.HasSuffix(program, ".cmd"):
		suffix = ".cmd"
	default:
		return program
	}
	family := strings.TrimSuffix(program, suffix)
	switch family {
	case "aws", "az", "autossh", "base64", "certutil", "chisel",
		"claude", "cloudflared", "cmd", "cmdkey", "codex", "curl", "dd",
		"docker", "fping", "gcloud", "gemini", "git", "icacls", "kubectl",
		"masscan", "naabu", "nc", "ncat", "net", "net1", "netcat", "nerdctl",
		"ngrok", "nmap", "oc", "opencode", "openssl", "op", "pass", "podman",
		"powershell", "pwsh", "scp", "schtasks", "sftp", "socat", "ssh",
		"takeown", "taskkill", "vault", "wget", "where":
		return family
	default:
		// Some suffixes disambiguate a native executable from a shell alias
		// (for example PowerShell sc versus sc.exe), so unknown families
		// retain the suffix.
		return program
	}
}

func requireCommandDialect(
	out *parseOutput,
	command *CommandFact,
	allowed ...Dialect,
) bool {
	for _, dialect := range allowed {
		if command.Dialect == dialect {
			return true
		}
	}
	out.markPartial(IssueUnknownOperandGrammar)
	return false
}

func informationalInvocation(command *CommandFact) bool {
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "--" {
			break
		}
		lower := strings.ToLower(arg)
		switch command.Dialect {
		case DialectCMD:
			if lower == "/?" {
				return true
			}
		case DialectPowerShell:
			if lower == "-?" {
				return true
			}
		default:
			if lower == "--help" || lower == "--version" {
				return true
			}
		}
	}
	return false
}

func informationalNoopProgram(program string) bool {
	switch program {
	case "unlink", "rmdir", "rd", "del", "erase", "remove-item", "ri",
		"set-acl", "kill", "killall", "pkill", "taskkill":
		return true
	default:
		return false
	}
}

func classifyStructuredPowerShellGetContent(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	pathOptions := exactOptionSet("-path", "-literalpath")
	valueOptions := exactOptionSet(
		"-credential", "-delimiter", "-encoding", "-exclude", "-filter",
		"-include", "-readcount", "-stream", "-tail", "-totalcount",
		"-erroraction", "-errorvariable", "-informationaction",
		"-informationvariable", "-outbuffer", "-outvariable",
		"-pipelinevariable", "-progressaction", "-warningaction",
		"-warningvariable",
	)
	flagOptions := exactOptionSet(
		"-asbytestream", "-debug", "-force", "-raw", "-usetransaction",
		"-verbose", "-wait",
	)

	var paths []string
	complete := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "-?" {
			command.Effect = EffectPreview
			return
		}
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			if arg != "" {
				paths = append(paths, arg)
			} else {
				complete = false
			}
			continue
		}

		key, joinedValue, joined := powerShellParameter(arg)
		if _, pathOption := pathOptions[key]; pathOption {
			value, ok := classifierOptionValue(
				command.Argv,
				&i,
				joinedValue,
				joined,
			)
			if !ok || value == "" {
				complete = false
				continue
			}
			paths = append(paths, value)
			continue
		}
		if _, valueOption := valueOptions[key]; valueOption {
			value, ok := classifierOptionValue(
				command.Argv,
				&i,
				joinedValue,
				joined,
			)
			if !ok || value == "" {
				complete = false
			}
			continue
		}
		if _, flagOption := flagOptions[key]; flagOption && !joined {
			continue
		}
		complete = false
	}

	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(paths) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	filesystem := false
	environment := false
	for _, value := range paths {
		if windowsEnvironmentProviderPath(value) {
			environment = true
			continue
		}
		before := len(out.paths)
		appendCommandPath(out, command, PathAccessRead, value)
		filesystem = filesystem || len(out.paths) > before
	}
	if filesystem {
		addOperation(command, OperationRead)
	}
	if environment {
		addOperation(command, OperationEnvironmentRead)
	}
}

func classifyStructuredPowerShellGetChildItem(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	pathOptions := exactOptionSet("-path", "-literalpath")
	valueOptions := exactOptionSet(
		"-attributes", "-depth", "-exclude", "-filter", "-include",
		"-erroraction", "-errorvariable", "-informationaction",
		"-informationvariable", "-outbuffer", "-outvariable",
		"-pipelinevariable", "-progressaction", "-warningaction",
		"-warningvariable",
	)
	flagOptions := exactOptionSet(
		"-debug", "-directory", "-file", "-follow-symlink", "-force",
		"-hidden", "-name", "-readonly", "-recurse", "-system",
		"-usetransaction", "-verbose",
	)
	var paths []string
	complete := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "-?" {
			command.Effect = EffectPreview
			return
		}
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			if arg == "" {
				complete = false
			} else {
				paths = append(paths, arg)
			}
			continue
		}
		key, joinedValue, joined := powerShellParameter(arg)
		if _, pathOption := pathOptions[key]; pathOption {
			value, ok := classifierOptionValue(
				command.Argv,
				&i,
				joinedValue,
				joined,
			)
			if !ok || value == "" {
				complete = false
			} else {
				paths = append(paths, value)
			}
			continue
		}
		if _, valueOption := valueOptions[key]; valueOption {
			value, ok := classifierOptionValue(
				command.Argv,
				&i,
				joinedValue,
				joined,
			)
			if !ok || value == "" {
				complete = false
			}
			continue
		}
		if _, flagOption := flagOptions[key]; flagOption && !joined {
			continue
		}
		complete = false
	}
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(paths) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	filesystem := false
	environment := false
	for _, value := range paths {
		if windowsEnvironmentProviderPath(value) {
			environment = true
			continue
		}
		before := len(out.paths)
		appendCommandPath(out, command, PathAccessList, value)
		filesystem = filesystem || len(out.paths) > before
	}
	if filesystem {
		addOperation(command, OperationList)
	}
	if environment {
		addOperation(command, OperationEnvironmentRead)
	}
}

func powerShellParameter(arg string) (string, string, bool) {
	key, value, joined := strings.Cut(arg, ":")
	return strings.ToLower(key), value, joined
}

type structuredPowerShellControlState struct {
	whatIfSeen  bool
	confirmSeen bool
	help        bool
	valid       bool
}

func newStructuredPowerShellControlState() structuredPowerShellControlState {
	return structuredPowerShellControlState{valid: true}
}

func (state *structuredPowerShellControlState) consume(
	command *CommandFact,
	arg string,
) bool {
	lower := strings.ToLower(arg)
	if lower == "-?" {
		state.help = true
		return true
	}
	name, value, joined := strings.Cut(lower, ":")
	switch name {
	case "-whatif":
		if state.whatIfSeen {
			state.valid = false
			command.Effect = EffectUncertain
			return true
		}
		state.whatIfSeen = true
		switch {
		case !joined, value == "$true":
			command.Effect = EffectPreview
		case value == "$false":
			command.Effect = EffectExecute
		default:
			state.valid = false
			command.Effect = EffectUncertain
		}
		return true
	case "-confirm":
		if state.confirmSeen || joined &&
			value != "$true" && value != "$false" {
			state.valid = false
		}
		state.confirmSeen = true
		return true
	default:
		return false
	}
}

func structuredPowerShellRequiredValue(
	argv []string,
	index *int,
) (string, bool) {
	if *index+1 >= len(argv) {
		return "", false
	}
	*index++
	value := argv[*index]
	return value, value != "" && !strings.HasPrefix(value, "-")
}

func classifyStructuredPowerShellClearDisk(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	targetSeen := false
	removeDataSeen := false
	removeOEMSeen := false
	passThruSeen := false
	valid := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if controls.consume(command, arg) {
			continue
		}
		switch strings.ToLower(arg) {
		case "-number":
			value, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			)
			if !ok || targetSeen {
				valid = false
				continue
			}
			if _, err := strconv.ParseUint(value, 10, 32); err != nil {
				valid = false
				continue
			}
			targetSeen = true
		case "-inputobject":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			// InputObject may carry a live PowerShell object or pipeline
			// expression that argv alone cannot normalize to a stable disk
			// number. Keep this parameter set on the fallback path.
			if !ok || targetSeen {
				valid = false
				continue
			}
			targetSeen = true
			valid = false
		case "-removedata":
			if removeDataSeen {
				valid = false
			}
			removeDataSeen = true
		case "-removeoem":
			if removeOEMSeen {
				valid = false
			}
			removeOEMSeen = true
		case "-passthru":
			if passThruSeen {
				valid = false
			}
			passThruSeen = true
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !controls.valid || !targetSeen ||
		!removeDataSeen && !removeOEMSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationDiskWrite)
}

func classifyStructuredPowerShellStopProcess(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	selectorSeen := false
	forceSeen := false
	passThruSeen := false
	valid := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if controls.consume(command, arg) {
			continue
		}
		switch strings.ToLower(arg) {
		case "-name", "-inputobject":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			if !ok || selectorSeen {
				valid = false
				continue
			}
			selectorSeen = true
		case "-id":
			value, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			)
			if !ok || selectorSeen ||
				!structuredPowerShellProcessIDs(value) {
				valid = false
				continue
			}
			selectorSeen = true
		case "-force":
			if forceSeen {
				valid = false
			}
			forceSeen = true
		case "-passthru":
			if passThruSeen {
				valid = false
			}
			passThruSeen = true
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !controls.valid || !selectorSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationProcessKill)
}

func structuredPowerShellProcessIDs(value string) bool {
	if value == "" {
		return false
	}
	for _, candidate := range strings.Split(value, ",") {
		if candidate == "" {
			return false
		}
		if _, err := strconv.ParseUint(candidate, 10, 32); err != nil {
			return false
		}
	}
	return true
}

func classifyStructuredPowerShellAddLocalGroupMember(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	memberSeen := false
	groupSeen := false
	valid := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if controls.consume(command, arg) {
			continue
		}
		switch strings.ToLower(arg) {
		case "-member":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			if !ok || memberSeen {
				valid = false
				continue
			}
			memberSeen = true
		case "-group", "-sid":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			if !ok || groupSeen {
				valid = false
				continue
			}
			groupSeen = true
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !controls.valid || !memberSeen || !groupSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationAccountChange)
}

func classifyStructuredPowerShellAddADGroupMember(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	identitySeen := false
	membersSeen := false
	valid := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if controls.consume(command, arg) {
			continue
		}
		lower := strings.ToLower(arg)
		switch lower {
		case "-identity", "-members":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			if !ok ||
				lower == "-identity" && identitySeen ||
				lower == "-members" && membersSeen {
				valid = false
				continue
			}
			if lower == "-identity" {
				identitySeen = true
			} else {
				membersSeen = true
			}
		case "-authtype", "-credential", "-membertimetolive",
			"-partition", "-server":
			if _, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			); !ok {
				valid = false
			}
		case "-disablepermissivemodify", "-passthru":
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !controls.valid || !identitySeen || !membersSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationAccountChange)
}

func classifyStructuredPowerShellGroupQuery(
	out *parseOutput,
	command *CommandFact,
	activeDirectory bool,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	selectorSeen := false
	valid := true
	help := false
	for i := 1; i < len(command.Argv); i++ {
		arg := strings.ToLower(command.Argv[i])
		if arg == "-?" {
			help = true
			continue
		}
		switch {
		case !activeDirectory && (arg == "-group" || arg == "-sid"),
			activeDirectory && arg == "-identity":
			value, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			)
			if !ok || selectorSeen ||
				!structuredPowerShellStaticOperand(value) {
				valid = false
				continue
			}
			selectorSeen = true
		case !activeDirectory && arg == "-member":
			value, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			)
			if !ok || !structuredPowerShellStaticOperand(value) {
				valid = false
			}
		case activeDirectory &&
			(arg == "-authtype" || arg == "-credential" ||
				arg == "-partition" || arg == "-server"):
			value, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			)
			if !ok || !structuredPowerShellStaticOperand(value) {
				valid = false
			}
		case activeDirectory && arg == "-recursive":
		default:
			valid = false
		}
	}
	if help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !selectorSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationList)
}

func structuredPowerShellStaticOperand(value string) bool {
	return value != "" &&
		!strings.ContainsAny(value, "$`*?[]{}")
}

// classifyStructuredPowerShellNewItem owns New-Item's exact core parameter
// binding. In particular, -Name is relative to -Path; the two values must not
// become independent write targets. Provider-specific dynamic parameters and
// PowerShell's mkdir/md wrapper functions remain on fallback.
func classifyStructuredPowerShellNewItem(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	seen := make(map[string]struct{})
	var parent, name, itemType string
	var positional []string
	targetValid := true
	grammarComplete := true
	semanticsComplete := true
	for index := 1; index < len(command.Argv); index++ {
		arg := command.Argv[index]
		if controls.consume(command, arg) {
			continue
		}
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			if !structuredPowerShellStaticOperand(arg) {
				targetValid = false
				structuredPowerShellMarkDynamicEffect(command, arg)
			}
			positional = append(positional, arg)
			continue
		}
		key, joinedValue, joined := powerShellParameter(arg)
		canonicalKey := canonicalPowerShellNewItemParameter(key)
		consume := func() (string, bool) {
			_, duplicate := seen[canonicalKey]
			seen[canonicalKey] = struct{}{}
			if joined {
				return joinedValue, joinedValue != "" && !duplicate
			}
			value, ok := structuredPowerShellRequiredValue(command.Argv, &index)
			return value, ok && !duplicate
		}
		switch canonicalKey {
		case "-path":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				targetValid = false
				structuredPowerShellMarkDynamicEffect(command, value)
			} else {
				parent = value
			}
		case "-name":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				targetValid = false
				structuredPowerShellMarkDynamicEffect(command, value)
			} else {
				name = value
			}
		case "-itemtype":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				semanticsComplete = false
				structuredPowerShellMarkDynamicEffect(command, value)
			} else {
				itemType = value
			}
		case "-value":
			// -Value is file content for ordinary items and the link target
			// for link item types. Neither relationship is represented by the
			// current fact schema, so retain only the proven destination and
			// keep the invocation on fallback.
			value, _ := consume()
			structuredPowerShellMarkDynamicEffect(command, value)
			semanticsComplete = false
		case "-credential", "-erroraction", "-errorvariable", "-informationaction",
			"-informationvariable", "-outbuffer", "-outvariable",
			"-pipelinevariable", "-progressaction", "-warningaction",
			"-warningvariable":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				grammarComplete = false
				structuredPowerShellMarkDynamicEffect(command, value)
			} else if !powerShellNewItemCommonValueAuthoritative(
				canonicalKey,
				value,
			) {
				// The target remains useful as diagnostic intent even though
				// PowerShell parameter binding rejects the typed value.
				semanticsComplete = false
			}
		case "-force":
			if _, duplicate := seen[canonicalKey]; duplicate {
				grammarComplete = false
			}
			seen[canonicalKey] = struct{}{}
			if joined && !structuredPowerShellBooleanLiteral(joinedValue) {
				grammarComplete = false
			}
		case "-debug", "-verbose", "-usetransaction":
			if _, duplicate := seen[canonicalKey]; duplicate {
				grammarComplete = false
			}
			seen[canonicalKey] = struct{}{}
			if joined && !structuredPowerShellBooleanLiteral(joinedValue) {
				grammarComplete = false
			}
		default:
			grammarComplete = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !controls.valid {
		grammarComplete = false
	}
	if parent != "" && len(positional) > 0 || len(positional) > 1 {
		targetValid = false
	} else if parent == "" && len(positional) == 1 {
		parent = positional[0]
	}
	target, flavor, targetOK := structuredPowerShellNewItemTarget(parent, name)
	if !targetValid || !grammarComplete || !targetOK ||
		!appendStructuredPowerShellNewItemPath(
			out,
			command.ID,
			target,
			flavor,
		) {
		if out.status != StatusLimitExceeded {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	addOperation(command, OperationWrite)
	if !powerShellNewItemTypeAuthoritative(itemType, flavor) {
		semanticsComplete = false
	}
	if !semanticsComplete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func structuredPowerShellBooleanLiteral(value string) bool {
	return strings.EqualFold(value, "$true") ||
		strings.EqualFold(value, "$false")
}

func canonicalPowerShellNewItemParameter(key string) string {
	switch strings.ToLower(key) {
	case "-type":
		return "-itemtype"
	case "-target":
		return "-value"
	case "-ea":
		return "-erroraction"
	case "-ev":
		return "-errorvariable"
	case "-infa":
		return "-informationaction"
	case "-iv":
		return "-informationvariable"
	case "-ob":
		return "-outbuffer"
	case "-ov":
		return "-outvariable"
	case "-pv":
		return "-pipelinevariable"
	case "-proga":
		return "-progressaction"
	case "-wa":
		return "-warningaction"
	case "-wv":
		return "-warningvariable"
	case "-db":
		return "-debug"
	case "-vb":
		return "-verbose"
	default:
		return strings.ToLower(key)
	}
}

func powerShellNewItemCommonValueAuthoritative(
	parameter string,
	value string,
) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	switch parameter {
	case "-erroraction", "-informationaction", "-progressaction",
		"-warningaction":
		switch strings.ToLower(value) {
		case "silentlycontinue", "stop", "continue", "inquire", "ignore",
			"suspend", "break":
			return true
		}
		numeric, err := strconv.ParseInt(value, 10, 8)
		return err == nil && numeric >= 0 && numeric <= 6
	case "-outbuffer":
		numeric, err := strconv.ParseInt(value, 10, 32)
		return err == nil && numeric >= 0
	default:
		return true
	}
}

func structuredPowerShellMarkDynamicEffect(
	command *CommandFact,
	value string,
) {
	if command != nil && strings.ContainsAny(value, "$`") {
		command.Effect = EffectUncertain
	}
}

func powerShellNewItemTypeAuthoritative(
	itemType string,
	flavor PathFlavor,
) bool {
	if itemType != strings.TrimSpace(itemType) {
		return false
	}
	switch strings.ToLower(itemType) {
	case "":
		return true
	case "file", "directory":
		// These filesystem item types do not have provider-specific behavior
		// beyond the destination already represented by the write fact.
		return flavor == PathFlavorPOSIX ||
			flavor == PathFlavorWindows ||
			flavor == PathFlavorUnknown
	case "symboliclink", "hardlink", "junction":
		// Link relationships need both a destination and a distinct target;
		// the current fact schema cannot express that relationship.
		return false
	default:
		return false
	}
}

func structuredPowerShellNewItemTarget(
	parent string,
	name string,
) (string, PathFlavor, bool) {
	if parent == "" && name == "" {
		return "", PathFlavorUnknown, false
	}
	if parent != "" && !structuredPowerShellStaticOperand(parent) ||
		name != "" && !structuredPowerShellStaticOperand(name) {
		return "", PathFlavorUnknown, false
	}
	if name == "" {
		flavor, ok := structuredPowerShellNewItemPathFlavor(parent)
		return parent, flavor, ok
	}
	if parent == "" {
		flavor, ok := structuredPowerShellNewItemPathFlavor(name)
		return name, flavor, ok
	}

	parentFlavor, ok := structuredPowerShellNewItemPathFlavor(parent)
	if !ok || strings.HasSuffix(parent, ":") {
		return "", PathFlavorUnknown, false
	}
	if parentFlavor == PathFlavorUnknown {
		return "", PathFlavorUnknown, false
	}
	syntax := syntaxForPath(parent, parentFlavor, "")
	if parentFlavor == PathFlavorRegistry {
		syntax = pathSyntaxWindows
	}
	separator := byte(0)
	switch syntax {
	case pathSyntaxPOSIX:
		if strings.HasPrefix(name, "/") {
			return "", PathFlavorUnknown, false
		}
		separator = '/'
		parentFlavor = PathFlavorPOSIX
	case pathSyntaxWindows:
		if strings.HasPrefix(name, `\`) || strings.HasPrefix(name, "/") ||
			len(name) >= 2 && isASCIILetter(name[0]) && name[1] == ':' ||
			strings.Contains(strings.ToLower(name), "::") {
			return "", PathFlavorUnknown, false
		}
		separator = '\\'
		if lastSlash := strings.LastIndex(parent, "/"); lastSlash >
			strings.LastIndex(parent, `\`) {
			separator = '/'
		}
		if parentFlavor != PathFlavorRegistry &&
			parentFlavor != PathFlavorDevice {
			parentFlavor = PathFlavorWindows
		}
	default:
		// A relative parent such as "tmp" does not identify whether the target
		// is tmp\name or tmp/name. The eventual CWD can resolve a standalone
		// relative target, but it cannot safely repair an already joined value.
		return "", PathFlavorUnknown, false
	}
	if strings.HasSuffix(parent, "/") || strings.HasSuffix(parent, `\`) {
		return parent + name, parentFlavor, true
	}
	return parent + string(separator) + name, parentFlavor, true
}

func structuredPowerShellNewItemPathFlavor(
	value string,
) (PathFlavor, bool) {
	if value == "" {
		return PathFlavorUnknown, false
	}
	if _, ok := canonicalRegistryPath(value); ok {
		return PathFlavorRegistry, true
	}
	if looksLikeRegistryPath(value) {
		return PathFlavorUnknown, false
	}
	if strings.Contains(strings.ToLower(value), "::") {
		return PathFlavorUnknown, false
	}
	if windowsNonFilesystemProviderPath(value) {
		return PathFlavorUnknown, false
	}
	flavor := pathFlavor(value)
	if flavor == PathFlavorUnknown &&
		!strings.ContainsAny(value, `/\`) &&
		!looksWindowsPath(value) {
		return PathFlavorUnknown, true
	}
	switch syntaxForPath(value, flavor, "") {
	case pathSyntaxPOSIX:
		return PathFlavorPOSIX, true
	case pathSyntaxWindows:
		return PathFlavorWindows, true
	default:
		if strings.Contains(value, ":") ||
			strings.Contains(strings.ToLower(value), "::") {
			return PathFlavorUnknown, false
		}
		return PathFlavorUnknown, true
	}
}

func appendStructuredPowerShellNewItemPath(
	out *parseOutput,
	commandID int64,
	value string,
	flavor PathFlavor,
) bool {
	if value == "" || !structuredPowerShellStaticOperand(value) {
		return false
	}
	switch flavor {
	case PathFlavorPOSIX:
		return out.appendPath(PathFact{
			CommandID: commandID,
			Access:    PathAccessWrite,
			Flavor:    PathFlavorPOSIX,
			Value:     value,
		})
	case PathFlavorWindows, PathFlavorRegistry, PathFlavorDevice:
		canonical, ok := windowsCanonicalPathFactValue(value)
		if !ok {
			return false
		}
		return out.appendPath(PathFact{
			CommandID: commandID,
			Access:    PathAccessWrite,
			Flavor:    windowsPathFlavor(canonical),
			Value:     canonical,
		})
	case PathFlavorUnknown:
		if strings.ContainsAny(value, `/\:`) {
			return false
		}
		return out.appendPath(PathFact{
			CommandID: commandID,
			Access:    PathAccessWrite,
			Flavor:    PathFlavorUnknown,
			Value:     value,
		})
	default:
		return false
	}
}

// classifyStructuredPowerShellPathMutator owns the exact structured-argv
// parameter binding for the mutators whose data operands must never be
// mistaken for paths. Raw PowerShell reaches the same classifier after its
// parser has projected a complete argv.
func classifyStructuredPowerShellPathMutator(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	seen := make(map[string]struct{})
	var positional, sources, destinations []string
	valid := true
	for index := 1; index < len(command.Argv); index++ {
		arg := command.Argv[index]
		if controls.consume(command, arg) {
			continue
		}
		if arg == "" || arg == "-" || !strings.HasPrefix(arg, "-") {
			positional = append(positional, arg)
			continue
		}
		key, joinedValue, joined := powerShellParameter(arg)
		consume := func() (string, bool) {
			if _, duplicate := seen[key]; duplicate {
				return "", false
			}
			seen[key] = struct{}{}
			if joined {
				return joinedValue, joinedValue != ""
			}
			return structuredPowerShellRequiredValue(command.Argv, &index)
		}
		switch key {
		case "-path", "-literalpath", "-source":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				sources = append(sources, value)
			}
		case "-filepath":
			value, ok := consume()
			if program != "out-file" || !ok ||
				!structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				sources = append(sources, value)
			}
		case "-destination":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				destinations = append(destinations, value)
			}
		case "-newname":
			value, ok := consume()
			if program != "rename-item" || !ok ||
				!structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				destinations = append(destinations, value)
			}
		case "-value", "-inputobject", "-encoding", "-width", "-stream",
			"-filter", "-include", "-exclude", "-credential",
			"-erroraction", "-errorvariable", "-informationaction",
			"-informationvariable", "-outbuffer", "-outvariable",
			"-pipelinevariable", "-progressaction", "-warningaction",
			"-warningvariable":
			if _, ok := consume(); !ok {
				valid = false
			}
		case "-force", "-recurse", "-passthru", "-container",
			"-nonewline", "-append", "-noclobber", "-debug", "-verbose":
			if joined {
				valid = false
				continue
			}
			if _, duplicate := seen[key]; duplicate {
				valid = false
			}
			seen[key] = struct{}{}
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !controls.valid {
		valid = false
	}

	switch program {
	case "set-content", "add-content", "out-file":
		// The first positional is the path only when no named path was used;
		// remaining positionals are content and deliberately produce no path.
		if len(sources) == 0 && len(positional) > 0 {
			sources = append(sources, positional[0])
			positional = positional[1:]
		}
		if len(sources) != 1 || !structuredPowerShellStaticOperand(sources[0]) ||
			len(destinations) != 0 {
			valid = false
		}
		if !valid {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		access := PathAccessWrite
		operation := OperationWrite
		if program == "add-content" {
			access = PathAccessAppend
			operation = OperationAppend
		}
		addOperation(command, operation)
		appendCommandPath(out, command, access, sources[0])
	case "remove-item":
		if len(sources) > 0 && len(positional) > 0 {
			valid = false
		} else if len(sources) == 0 {
			sources = positional
		}
		if len(sources) == 0 || len(destinations) != 0 {
			valid = false
		}
		for _, source := range sources {
			if !structuredPowerShellStaticOperand(source) {
				valid = false
			}
		}
		if !valid {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationDelete)
		for _, source := range sources {
			appendCommandPath(out, command, PathAccessDelete, source)
		}
	case "copy-item", "move-item", "rename-item":
		if len(sources) == 0 && len(destinations) == 0 &&
			len(positional) == 2 {
			sources = append(sources, positional[0])
			destinations = append(destinations, positional[1])
		} else if len(positional) != 0 {
			valid = false
		}
		if len(sources) != 1 || len(destinations) != 1 {
			valid = false
		}
		if !valid {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		move := program != "copy-item"
		if move {
			addOperation(command, OperationMove)
		} else {
			addOperation(command, OperationCopy)
		}
		appendCommandPath(out, command, PathAccessRead, sources[0])
		appendCommandPath(out, command, PathAccessWrite, destinations[0])
		if move {
			appendCommandPath(out, command, PathAccessDelete, sources[0])
		}
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func classifyStructuredPowerShellRegistryProperty(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	switch program {
	case "gp":
		program = "get-itemproperty"
	case "sp":
		program = "set-itemproperty"
	case "rp":
		program = "remove-itemproperty"
	}
	controls := newStructuredPowerShellControlState()
	seen := make(map[string]struct{})
	pathValue := ""
	nameSeen := false
	valueSeen := false
	valid := true
	for index := 1; index < len(command.Argv); index++ {
		arg := command.Argv[index]
		if controls.consume(command, arg) {
			continue
		}
		if arg == "" || !strings.HasPrefix(arg, "-") {
			valid = false
			continue
		}
		key, joinedValue, joined := powerShellParameter(arg)
		consume := func() (string, bool) {
			if _, duplicate := seen[key]; duplicate {
				return "", false
			}
			seen[key] = struct{}{}
			if joined {
				return joinedValue, joinedValue != ""
			}
			return structuredPowerShellRequiredValue(command.Argv, &index)
		}
		switch key {
		case "-path", "-literalpath":
			value, ok := consume()
			if !ok || pathValue != "" ||
				!structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				pathValue = value
			}
		case "-name":
			value, ok := consume()
			if !ok || !structuredPowerShellStaticOperand(value) {
				valid = false
			} else {
				nameSeen = true
			}
		case "-value":
			if _, ok := consume(); !ok {
				valid = false
			} else {
				valueSeen = true
			}
		case "-type", "-credential", "-filter", "-include", "-exclude",
			"-erroraction", "-errorvariable", "-warningaction",
			"-warningvariable":
			if _, ok := consume(); !ok {
				valid = false
			}
		case "-force", "-passthru", "-debug", "-verbose":
			if joined {
				valid = false
			}
			if _, duplicate := seen[key]; duplicate {
				valid = false
			}
			seen[key] = struct{}{}
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !controls.valid || pathValue == "" {
		valid = false
	}
	mutating := program != "get-itemproperty"
	if mutating && !nameSeen {
		valid = false
	}
	if (program == "set-itemproperty" || program == "new-itemproperty") &&
		!valueSeen {
		valid = false
	}
	if !valid {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if mutating {
		addOperation(command, OperationConfigChange)
	} else {
		addOperation(command, OperationRead)
	}
	access := PathAccessMetadata
	if program == "set-itemproperty" || program == "new-itemproperty" {
		access = PathAccessWrite
	} else if program == "remove-itemproperty" {
		access = PathAccessDelete
	}
	appendCommandPath(out, command, access, pathValue)
}

func classifyStructuredPowerShellRegisterScheduledTask(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	taskSeen := false
	actionSeen := false
	forceSeen := false
	valid := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if controls.consume(command, arg) {
			continue
		}
		lower := strings.ToLower(arg)
		switch lower {
		case "-taskname", "-action":
			_, ok := structuredPowerShellRequiredValue(command.Argv, &i)
			if !ok ||
				lower == "-taskname" && taskSeen ||
				lower == "-action" && actionSeen {
				valid = false
				continue
			}
			if lower == "-taskname" {
				taskSeen = true
			} else {
				actionSeen = true
			}
		case "-description", "-password", "-principal", "-runlevel",
			"-settings", "-taskpath", "-trigger", "-user":
			if _, ok := structuredPowerShellRequiredValue(
				command.Argv,
				&i,
			); !ok {
				valid = false
			}
		case "-force":
			if forceSeen {
				valid = false
			}
			forceSeen = true
		default:
			valid = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !valid || !controls.valid || !taskSeen || !actionSeen {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationSchedule)
}

func classifyPOSIXRemove(out *parseOutput, command *CommandFact) {
	grammarArgv := cloneSlice(command.Argv)
	for i := 1; i < len(grammarArgv); i++ {
		key, _, joined := strings.Cut(grammarArgv[i], "=")
		if joined && validPOSIXRemoveJoinedOption(grammarArgv[i]) {
			grammarArgv[i] = key
		}
	}
	parsed := parseOwnedPOSIXOptions(
		grammarArgv,
		nil,
		exactOptionSet(
			"-d", "--dir", "-f", "--force", "-i", "-I",
			"-P", "-r", "-R", "--recursive", "-v", "--verbose",
			"-W", "-x",
			"--one-file-system", "--no-preserve-root",
			"--interactive", "--preserve-root",
		),
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.positionals) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationDelete)
	for _, target := range parsed.positionals {
		appendPath(out, command.ID, PathAccessDelete, target)
	}
}

func validPOSIXRemoveJoinedOption(arg string) bool {
	key, value, joined := strings.Cut(arg, "=")
	if !joined {
		return true
	}
	switch key {
	case "--interactive":
		return value == "always" || value == "once" || value == "never"
	case "--preserve-root":
		return value == "all"
	default:
		return false
	}
}

func classifyWindowsServiceControl(
	out *parseOutput,
	command *CommandFact,
) {
	if len(command.Argv) == 0 || !strings.EqualFold(
		path.Base(strings.ReplaceAll(command.Argv[0], `\`, "/")),
		"sc.exe",
	) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if len(command.Argv) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	verb := strings.ToLower(command.Argv[1])
	if verb == "/?" || verb == "-?" || verb == "/help" {
		command.Effect = EffectPreview
		return
	}
	for _, arg := range command.Argv[2:] {
		if arg == "/?" || arg == "-?" || strings.EqualFold(arg, "/help") {
			command.Effect = EffectPreview
			return
		}
	}
	switch verb {
	case "create", "config", "delete", "description", "failure",
		"failureflag", "managedaccount", "preferrednode", "privs", "sdset",
		"sidtype", "start", "stop", "pause", "continue", "control",
		"triggerinfo":
		addOperation(command, OperationConfigChange)
	case "enumdepend", "getdisplayname", "getkeyname", "qc", "qdescription",
		"qfailure", "qfailureflag", "qmanagedaccount", "qpreferrednode",
		"qprivs", "qprotection", "qsidtype", "qtriggerinfo", "query",
		"queryex", "showsid":
		addOperation(command, OperationList)
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func classifyStructuredICACLS(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectCMD) {
		return
	}
	if len(command.Argv) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	target := command.Argv[1]
	if strings.EqualFold(target, "/?") {
		command.Effect = EffectPreview
		return
	}
	if target == "" || strings.HasPrefix(target, "/") &&
		!windowsCMDPathOperand(target) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	valid := true
	mutates := false
	help := false
	for i := 2; i < len(command.Argv); i++ {
		arg := strings.ToLower(command.Argv[i])
		switch {
		case arg == "/?":
			help = true
		case arg == "/grant", arg == "/grant:r",
			arg == "/deny", arg == "/deny:r",
			arg == "/remove", arg == "/remove:g",
			arg == "/remove:d", arg == "/setintegritylevel",
			arg == "/setowner":
			if _, ok := structuredCMDRequiredValue(command.Argv, &i); !ok {
				valid = false
				continue
			}
			mutates = true
		case arg == "/reset",
			arg == "/inheritance:e",
			arg == "/inheritance:d",
			arg == "/inheritance:r":
			mutates = true
		case arg == "/findsid":
			if _, ok := structuredCMDRequiredValue(command.Argv, &i); !ok {
				valid = false
			}
		case arg == "/verify", arg == "/t", arg == "/c",
			arg == "/l", arg == "/q":
		default:
			valid = false
		}
	}
	if help {
		command.Effect = EffectPreview
		return
	}
	if !valid {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	appendCommandPath(out, command, PathAccessMetadata, target)
	if mutates {
		addOperation(command, OperationPermissionChange)
	} else {
		addOperation(command, OperationList)
	}
}

func classifyStructuredTakeown(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectCMD) {
		return
	}
	valid := true
	target := ""
	help := false
	for i := 1; i < len(command.Argv); i++ {
		arg := strings.ToLower(command.Argv[i])
		switch arg {
		case "/?":
			help = true
		case "/f":
			value, ok := structuredCMDRequiredPath(command.Argv, &i)
			if !ok || target != "" {
				valid = false
				continue
			}
			target = value
		case "/a", "/r", "/skipsl":
		case "/d":
			value, ok := structuredCMDRequiredValue(command.Argv, &i)
			if !ok || !strings.EqualFold(value, "Y") &&
				!strings.EqualFold(value, "N") {
				valid = false
			}
		case "/s", "/u", "/p":
			if _, ok := structuredCMDRequiredValue(
				command.Argv,
				&i,
			); !ok {
				valid = false
			}
		default:
			valid = false
		}
	}
	if help {
		command.Effect = EffectPreview
		return
	}
	if !valid || target == "" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	appendCommandPath(out, command, PathAccessMetadata, target)
	addOperation(command, OperationPermissionChange)
}

func structuredCMDRequiredValue(
	argv []string,
	index *int,
) (string, bool) {
	if *index+1 >= len(argv) {
		return "", false
	}
	*index++
	value := argv[*index]
	return value, value != "" && !strings.HasPrefix(value, "/")
}

func structuredCMDRequiredPath(
	argv []string,
	index *int,
) (string, bool) {
	if *index+1 >= len(argv) {
		return "", false
	}
	*index++
	value := argv[*index]
	return value, value != "" &&
		(!strings.HasPrefix(value, "/") || windowsCMDPathOperand(value))
}

func processProbeInvocation(
	out *parseOutput,
	program string,
	argv []string,
) bool {
	if program != "kill" && program != "pkill" && program != "killall" {
		return false
	}
	var (
		sawZero    bool
		sawReal    bool
		malformed  bool
		selectors  int
		hasOperand bool
	)
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			hasOperand = hasOperand || arg != ""
			continue
		}

		value := ""
		owned := false
		switch {
		case arg == "--signal" || arg == "-s" && program != "pkill":
			owned = true
			if i+1 >= len(argv) || argv[i+1] == "" {
				malformed = true
				continue
			}
			i++
			value = argv[i]
		case strings.HasPrefix(arg, "--signal="):
			owned = true
			value = strings.TrimPrefix(arg, "--signal=")
		default:
			value, owned = strings.CutPrefix(arg, "-")
			if owned {
				_, _, owned = processSignalValue(value)
			}
		}
		if !owned {
			malformed = true
			continue
		}
		selectors++
		zero, real, valid := processSignalValue(value)
		if !valid {
			malformed = true
			continue
		}
		sawZero = sawZero || zero
		sawReal = sawReal || real
	}

	if malformed || selectors > 1 || sawZero && sawReal {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if malformed || selectors > 1 || sawReal || !sawZero {
		return false
	}
	if !hasOperand {
		out.markPartial(IssueUnknownOperandGrammar)
		return false
	}
	return true
}

func processSignalValue(value string) (zero, real, valid bool) {
	if value == "0" {
		return true, false, true
	}
	if number, err := strconv.ParseUint(value, 10, 8); err == nil {
		return false, number > 0, number > 0
	}
	upper := strings.ToUpper(value)
	upper = strings.TrimPrefix(upper, "SIG")
	switch upper {
	case "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE",
		"KILL", "USR1", "SEGV", "USR2", "PIPE", "ALRM", "TERM", "CHLD",
		"CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG", "XCPU", "XFSZ",
		"VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS":
		return false, true, true
	default:
		return false, false, false
	}
}

func trustedExecutablePath(executable string) bool {
	if executable == "" || path.Clean(executable) != executable {
		return false
	}
	lower := strings.ToLower(executable)
	for _, prefix := range []string{
		"/bin/",
		"/sbin/",
		"/usr/bin/",
		"/usr/sbin/",
	} {
		if strings.HasPrefix(lower, prefix) && len(lower) > len(prefix) {
			return true
		}
	}
	if len(lower) < 4 || !isASCIILetter(lower[0]) ||
		lower[1] != ':' || lower[2] != '/' {
		return false
	}
	systemPath := lower[2:]
	for _, prefix := range []string{
		"/windows/system32/",
		"/windows/syswow64/",
	} {
		if strings.HasPrefix(systemPath, prefix) && len(systemPath) > len(prefix) {
			return true
		}
	}
	return false
}

func addOperation(command *CommandFact, operation OperationKind) {
	for _, existing := range command.Operations {
		if existing == operation {
			return
		}
	}
	command.Operations = append(command.Operations, operation)
}

func optionValues(flags ...string) map[string]struct{} {
	values := make(map[string]struct{}, len(flags))
	for _, flag := range flags {
		values[strings.ToLower(flag)] = struct{}{}
	}
	return values
}

func pathOperands(argv []string, consumesValue map[string]struct{}) []string {
	var operands []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		lower := strings.ToLower(arg)
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if key, _, ok := strings.Cut(lower, "="); ok {
				if _, consumes := consumesValue[key]; consumes {
					continue
				}
			}
			if _, consumes := consumesValue[lower]; consumes && i+1 < len(argv) {
				i++
			}
			continue
		}
		if options && isCMDSlashSwitch(arg) {
			continue
		}
		operands = append(operands, arg)
	}
	return operands
}

func isCMDSlashSwitch(value string) bool {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "/a:") {
		return true
	}
	switch lower {
	case "/a", "/b", "/d", "/e", "/f", "/h", "/i", "/l", "/n", "/p",
		"/q", "/r", "/s", "/v", "/w", "/x", "/y", "/-y":
		return true
	default:
		return false
	}
}

func addPathOperands(out *parseOutput, command *CommandFact, access PathAccess, consumesValue map[string]struct{}) {
	if !command.ArgvComplete {
		out.markPartial(IssueDynamicWord)
	}
	for _, operand := range pathOperands(command.Argv, consumesValue) {
		appendCommandPath(out, command, access, operand)
	}
}

func classifySearchPaths(out *parseOutput, command *CommandFact, program string) {
	switch program {
	case "grep":
		classifyPatternSearchPaths(out, command, program)
	case "rg", "ripgrep":
		classifyPatternSearchPaths(out, command, program)
		if searchCommandOptionPresent(command.Argv, program, "--pre") {
			out.markPartial(IssueUnsupportedConstruct)
		}
	case "find":
		startingPaths := findStartingPaths(command.Argv)
		for _, operand := range startingPaths {
			appendPath(out, command.ID, PathAccessRead, operand)
		}
		if hasAnyArgument(command.Argv, "-delete") {
			addOperation(command, OperationDelete)
			for _, operand := range startingPaths {
				appendPath(out, command.ID, PathAccessDelete, operand)
			}
		}
		if findHasEmbeddedCommand(command.Argv) {
			addOperation(command, OperationExecute)
			out.markPartial(IssueUnsupportedConstruct)
		}
	case "fd":
		operands := pathOperands(command.Argv, optionValues(
			"-c", "-e", "-j", "-d", "-o", "-s", "-t", "-x",
			"--base-directory", "--color", "--exclude", "--extension", "--max-depth",
			"--min-depth", "--owner", "--search-path", "--size", "--type",
			"--exec", "--exec-batch",
		))
		if len(operands) > 1 {
			for _, operand := range operands[1:] {
				appendPath(out, command.ID, PathAccessRead, operand)
			}
		}
		if hasAnyArgument(command.Argv, "-x", "--exec", "-X", "--exec-batch") {
			addOperation(command, OperationExecute)
			out.markPartial(IssueUnsupportedConstruct)
		}
	}
}

func searchCommandOptionPresent(
	argv []string,
	program string,
	option string,
) bool {
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}
		if arg == option || strings.HasPrefix(arg, option+"=") {
			return true
		}
		if searchOptionConsumesValue(program, arg) &&
			!strings.Contains(arg, "=") &&
			i+1 < len(argv) {
			i++
		}
	}
	return false
}

func findHasEmbeddedCommand(argv []string) bool {
	for _, arg := range argv[1:] {
		switch arg {
		case "-exec", "-execdir", "-ok", "-okdir":
			return true
		}
	}
	return false
}

func classifyPatternSearchPaths(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	patternFromOption, patternFiles := searchPatternOptions(command.Argv)
	for _, path := range patternFiles {
		appendPath(out, command.ID, PathAccessRead, path)
	}
	operands := searchOperands(command.Argv, program)
	if !patternFromOption && len(operands) > 0 {
		operands = operands[1:]
	}
	for _, operand := range operands {
		appendPath(out, command.ID, PathAccessRead, operand)
	}
}

func searchOperands(argv []string, program string) []string {
	var operands []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			if searchOptionConsumesValue(program, arg) && i+1 < len(argv) {
				i++
			}
			continue
		}
		operands = append(operands, arg)
	}
	return operands
}

func searchOptionConsumesValue(program, arg string) bool {
	if strings.Contains(arg, "=") {
		return false
	}
	if strings.HasPrefix(arg, "--") {
		lower := strings.ToLower(arg)
		switch lower {
		case "--after-context", "--before-context", "--binary-files", "--color",
			"--context", "--dfa-size-limit", "--devices", "--directories",
			"--encoding", "--engine", "--exclude", "--exclude-dir",
			"--field-context-separator", "--field-match-separator", "--file",
			"--glob", "--iglob", "--include", "--label", "--max-columns",
			"--max-count", "--max-depth", "--max-filesize", "--path-separator",
			"--pre", "--pre-glob", "--regexp", "--replace", "--sort", "--sortr",
			"--type", "--type-not":
			return true
		default:
			return false
		}
	}
	switch program {
	case "grep":
		switch arg {
		case "-A", "-B", "-C", "-D", "-d", "-e", "-f", "-m":
			return true
		}
	case "rg", "ripgrep":
		switch arg {
		case "-A", "-B", "-C", "-E", "-e", "-f", "-g", "-j", "-M", "-m",
			"-r", "-t", "-T":
			return true
		}
	}
	return false
}

func searchPatternOptions(argv []string) (bool, []string) {
	var files []string
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return false, files
		}
		lower := strings.ToLower(arg)
		switch {
		case arg == "-e" || lower == "--regexp":
			if i+1 < len(argv) {
				i++
			}
			return true, files
		case strings.HasPrefix(arg, "-e") && len(arg) > 2,
			strings.HasPrefix(lower, "--regexp="):
			return true, files
		case arg == "-f" || lower == "--file":
			if i+1 < len(argv) {
				i++
				if argv[i] != "" && argv[i] != "-" {
					files = append(files, argv[i])
				}
			}
			return true, files
		case strings.HasPrefix(arg, "-f") && len(arg) > 2:
			files = append(files, arg[2:])
			return true, files
		case strings.HasPrefix(lower, "--file="):
			if value := arg[len("--file="):]; value != "" && value != "-" {
				files = append(files, value)
			}
			return true, files
		}
	}
	return false, files
}

func findStartingPaths(argv []string) []string {
	var paths []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if findExpressionStart(arg) {
			break
		}
		if options {
			switch arg {
			case "-H", "-L", "-P":
				continue
			}
			if strings.HasPrefix(arg, "-") {
				break
			}
		}
		paths = append(paths, arg)
	}
	return paths
}

func findExpressionStart(value string) bool {
	switch value {
	case "!", "(", ")", ",",
		"-a", "-and", "-o", "-or", "-not",
		"-amin", "-anewer", "-atime", "-cmin", "-cnewer", "-ctime",
		"-delete", "-empty", "-exec", "-execdir", "-executable",
		"-false", "-fls", "-fprint", "-fprint0", "-fprintf",
		"-gid", "-group", "-ilname", "-iname", "-inum", "-ipath", "-iregex",
		"-links", "-lname", "-ls", "-maxdepth", "-mindepth", "-mmin",
		"-mount", "-mtime", "-name", "-newer", "-nogroup", "-nouser",
		"-ok", "-okdir", "-path", "-perm", "-print", "-print0", "-printf",
		"-prune", "-quit", "-readable", "-regex", "-size", "-type",
		"-uid", "-used", "-user", "-wholename", "-writable", "-xdev":
		return true
	default:
		return false
	}
}

func classifyGetcap(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if len(command.Argv) == 2 {
		switch command.Argv[1] {
		case "-h", "--help", "-v", "--version":
			command.Effect = EffectPreview
			return
		}
	}
	if len(command.Argv) != 3 ||
		command.Argv[1] != "-r" && command.Argv[1] != "--recursive" ||
		command.Argv[2] == "" ||
		strings.HasPrefix(command.Argv[2], "-") {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationSearch)
	appendCommandPath(out, command, PathAccessMetadata, command.Argv[2])
}

func classifyTee(out *parseOutput, command *CommandFact) {
	grammarArgv := cloneSlice(command.Argv)
	for i := 1; i < len(grammarArgv); i++ {
		lower := strings.ToLower(grammarArgv[i])
		key, value, joined := strings.Cut(lower, "=")
		if key != "--output-error" || !joined {
			continue
		}
		switch value {
		case "warn", "warn-nopipe", "exit", "exit-nopipe":
			grammarArgv[i] = "--output-error"
		}
	}
	parsed := parseOwnedPOSIXOptions(
		grammarArgv,
		nil,
		exactOptionSet(
			"-a", "--append", "-i", "--ignore-interrupts",
			"-p", "--output-error",
		),
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	_, shortAppend := parsed.seen["-a"]
	_, longAppend := parsed.seen["--append"]
	appendMode := shortAppend || longAppend
	operation := OperationWrite
	access := PathAccessWrite
	if appendMode {
		operation = OperationAppend
		access = PathAccessAppend
	}
	addOperation(command, operation)
	for _, operand := range parsed.positionals {
		appendCommandPath(out, command, access, operand)
	}
}

func classifyPOSIXPermissionChange(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	values := exactOptionSet("--reference")
	flags := exactOptionSet(
		"-c", "--changes", "-f", "--silent", "--quiet", "-v", "--verbose",
		"--no-preserve-root", "--preserve-root", "-R", "--recursive",
	)
	switch program {
	case "chown":
		values["--from"] = struct{}{}
		fallthrough
	case "chgrp":
		for option := range exactOptionSet(
			"-H", "-L", "-P", "-h", "--dereference", "--no-dereference",
		) {
			flags[option] = struct{}{}
		}
	}

	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		values,
		flags,
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}

	addOperation(command, OperationPermissionChange)
	reference, referenceMode := parsed.values["--reference"]
	if referenceMode && reference != "" {
		appendPath(out, command.ID, PathAccessRead, reference)
	}

	targets := parsed.positionals
	if !referenceMode {
		if len(targets) == 0 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		// chmod's first positional operand is the mode; chown/chgrp use it for
		// the owner/group specification. Neither is a filesystem path.
		targets = targets[1:]
	}
	if len(targets) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	for _, target := range targets {
		appendPath(out, command.ID, PathAccessMetadata, target)
	}
}

func classifyPOSIXInstall(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		exactOptionSet("-m", "--mode"),
		exactOptionSet("-D", "-d", "-p", "-v"),
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	mode, hasMode := parsed.values["-m"]
	if !hasMode {
		mode, hasMode = parsed.values["--mode"]
	}
	if !parsed.complete || !hasMode || !dangerousInstallMode(mode) ||
		len(parsed.positionals) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationPermissionChange)
	for _, source := range parsed.positionals[:len(parsed.positionals)-1] {
		appendCommandPath(out, command, PathAccessRead, source)
	}
	appendCommandPath(
		out,
		command,
		PathAccessMetadata,
		parsed.positionals[len(parsed.positionals)-1],
	)
}

func dangerousInstallMode(mode string) bool {
	if parsed, err := strconv.ParseUint(mode, 8, 16); err == nil {
		return len(mode) == 4 && parsed&06000 != 0 ||
			(len(mode) == 3 || len(mode) == 4) && parsed&0002 != 0
	}
	lower := strings.ToLower(mode)
	return strings.Contains(lower, "+s") ||
		strings.Contains(lower, "=s") ||
		strings.Contains(lower, "o+w") ||
		strings.Contains(lower, "a+w")
}

func classifySetfacl(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		exactOptionSet("-m", "--modify", "-x", "--remove"),
		exactOptionSet(
			"-R", "--recursive", "-L", "--logical", "-P", "--physical",
			"-b", "--remove-all", "-k", "--remove-default",
		),
		exactOptionSet("-h", "--help", "-v", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	_, shortMutation := parsed.values["-m"]
	_, longMutation := parsed.values["--modify"]
	_, shortRemove := parsed.values["-x"]
	_, longRemove := parsed.values["--remove"]
	_, removeAll := parsed.seen["-b"]
	_, longRemoveAll := parsed.seen["--remove-all"]
	_, removeDefault := parsed.seen["-k"]
	_, longRemoveDefault := parsed.seen["--remove-default"]
	mutation := shortMutation || longMutation || shortRemove || longRemove ||
		removeAll || longRemoveAll || removeDefault || longRemoveDefault
	if !parsed.complete || !mutation ||
		len(parsed.positionals) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationPermissionChange)
	for _, target := range parsed.positionals {
		appendCommandPath(out, command, PathAccessMetadata, target)
	}
}

func classifySetcap(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if len(command.Argv) == 2 {
		switch command.Argv[1] {
		case "-h", "--help", "-v", "--version":
			command.Effect = EffectPreview
			return
		}
	}
	if len(command.Argv) != 3 ||
		command.Argv[1] == "" ||
		strings.HasPrefix(command.Argv[1], "-") ||
		command.Argv[2] == "" ||
		strings.HasPrefix(command.Argv[2], "-") {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationPermissionChange)
	appendCommandPath(out, command, PathAccessMetadata, command.Argv[2])
}

func classifyStructuredSetACL(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	pathValue := ""
	aclObject := false
	complete := true
	for index := 1; index < len(command.Argv); index++ {
		argument := strings.ToLower(command.Argv[index])
		switch argument {
		case "-path", "-literalpath":
			if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
				complete = false
				continue
			}
			index++
			pathValue = command.Argv[index]
		case "-aclobject":
			if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
				complete = false
				continue
			}
			index++
			aclObject = true
		case "-whatif":
			command.Effect = EffectPreview
		case "-confirm":
		default:
			complete = false
		}
	}
	if !complete || pathValue == "" ||
		!aclObject && command.PipelineID == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationPermissionChange)
	appendCommandPath(out, command, PathAccessMetadata, pathValue)
}

func classifyStructuredGetACL(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	pathValue := ""
	switch {
	case len(command.Argv) == 2:
		pathValue = command.Argv[1]
	case len(command.Argv) == 3 &&
		(strings.EqualFold(command.Argv[1], "-Path") ||
			strings.EqualFold(command.Argv[1], "-LiteralPath")):
		pathValue = command.Argv[2]
	default:
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationRead)
	appendCommandPath(out, command, PathAccessMetadata, pathValue)
}

func classifyShellInvocation(out *parseOutput, command *CommandFact) {
	if exactPOSIXPipelineStdinInterpreter(out, command) {
		return
	}
	invocation := parsePOSIXShellInvocation(command.Program, command.Argv)
	if provesIsolatedPOSIXNoExecPreview(
		out,
		command,
		invocation,
		posixShellModeScript,
	) {
		// No-exec shells parse the selected file without running its commands.
		// Preserve the file read only when no surrounding pipeline or redirect
		// can route parser output into another action.
		command.Effect = EffectPreview
		if invocation.scriptIndex >= 0 &&
			invocation.scriptIndex < len(command.Argv) {
			appendPath(
				out,
				command.ID,
				PathAccessRead,
				command.Argv[invocation.scriptIndex],
			)
		}
		return
	}
	if provesIsolatedPOSIXNoExecPreview(
		out,
		command,
		invocation,
		posixShellModeCommand,
	) {
		command.Effect = EffectPreview
		return
	}
	if invocation.valid && invocation.mode == posixShellModeCommand {
		if invocation.noExec {
			out.markPartial(IssueUnsupportedConstruct)
		}
		return
	}
	if exactPOSIXShellPreviewInvocation(command) {
		command.Effect = EffectPreview
		return
	}
	if script, ok := shellScriptOperand(command.Program, command.Argv); ok {
		appendPath(out, command.ID, PathAccessExecute, script)
	}
	// A script file, stdin, or an interactive shell carries action-bearing
	// content that this argv classifier cannot inspect.
	out.markPartial(IssueOpaqueArtifact)
}

func classifyPOSIXStdinScriptInterpreter(
	out *parseOutput,
	command *CommandFact,
) {
	if exactPOSIXPipelineStdinInterpreter(out, command) {
		return
	}
	// A local script, inline command, or unproven stdin source carries
	// executable bytes that ActionFacts does not inspect.
	out.markPartial(IssueOpaqueArtifact)
}

func exactPOSIXPipelineStdinInterpreter(
	out *parseOutput,
	command *CommandFact,
) bool {
	return posixPipelineStdinInterpreter(out, command, true)
}

func structuralPOSIXPipelineStdinInterpreter(
	out *parseOutput,
	command *CommandFact,
) bool {
	return posixPipelineStdinInterpreter(out, command, false)
}

func posixPipelineStdinInterpreter(
	out *parseOutput,
	command *CommandFact,
	requireSourceOperation bool,
) bool {
	if command.PipelineID == 0 ||
		!ProvesPOSIXStdinInterpreter(*command) ||
		!posixCommandHasTargetedPipelineStdin(
			out,
			command.ID,
			requireSourceOperation,
		) {
		return false
	}
	return true
}

// ProvesPOSIXStdinInterpreter reports whether a complete POSIX command reads
// executable source from stdin. Pipeline membership and source-to-sink flow
// are intentionally checked by the caller.
func ProvesPOSIXStdinInterpreter(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		command.Effect != EffectExecute ||
		!command.ArgvComplete ||
		posixCommandRedirectsStdin(&command) {
		return false
	}
	program := strings.ToLower(command.Program)
	if program == "python" || program == "python2" || program == "python3" ||
		program == "perl" || program == "ruby" ||
		posixVersionedPythonProgram(program) {
		return len(command.Argv) == 1 ||
			len(command.Argv) >= 2 && command.Argv[1] == "-"
	}
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh":
	default:
		return false
	}
	return exactPOSIXShellStdinArguments(program, command.Argv)
}

// ProvesPOSIXInteractiveShell reports whether the bounded shell invocation
// parser recognized a final interactive state. It deliberately remains true
// when startup files make the overall action non-authoritative: callers use
// this only as one ingredient in a stronger typed proof, never to suppress a
// conservative fallback.
func ProvesPOSIXInteractiveShell(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		command.Effect != EffectExecute ||
		!command.ArgvComplete {
		return false
	}
	invocation := parsePOSIXShellInvocation(command.Program, command.Argv)
	return invocation.recognized && invocation.interactive &&
		invocation.mode == posixShellModeStdin
}

func exactPOSIXShellStdinArguments(program string, argv []string) bool {
	invocation := parsePOSIXShellInvocation(program, argv)
	return invocation.valid &&
		invocation.mode == posixShellModeStdin &&
		!invocation.noExec
}

func exactPOSIXShellPreviewInvocation(command *CommandFact) bool {
	if command == nil || command.Program != "bash" ||
		!command.ArgvComplete || len(command.Argv) != 2 {
		return false
	}
	switch strings.ToLower(command.Argv[1]) {
	case "--help", "--version":
		return true
	default:
		return false
	}
}

func posixCommandRedirectsStdin(command *CommandFact) bool {
	for _, redirect := range command.Redirects {
		if redirect.FD == 0 {
			return true
		}
	}
	return false
}

func posixCommandHasTargetedPipelineStdin(
	out *parseOutput,
	commandID int64,
	requireSourceOperation bool,
) bool {
	if out == nil {
		return false
	}
	for _, flow := range out.dataFlows {
		if flow.ToCommandID == commandID &&
			flow.From == DataStdout &&
			flow.To == DataStdin {
			for index := range out.commands {
				if out.commands[index].ID == flow.FromCommandID {
					return exactPOSIXPipelineInterpreterSource(
						&out.commands[index],
						requireSourceOperation,
					)
				}
			}
		}
	}
	return false
}

func exactPOSIXPipelineInterpreterSource(
	command *CommandFact,
	requireOperation bool,
) bool {
	if command == nil || command.Dialect != DialectPOSIX ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Argv) == 0 || posixCommandRedirectsStdout(command) {
		return false
	}

	var operation OperationKind
	switch strings.ToLower(command.Program) {
	case "curl", "curl.exe":
		if !exactPOSIXCurlResponseStdout(command.Argv) {
			return false
		}
		operation = OperationFetch
	case "wget", "wget.exe":
		if !exactPOSIXWgetResponseStdout(command.Argv) {
			return false
		}
		operation = OperationFetch
	case "base64", "base64.exe":
		if !exactPOSIXBase64DecodeMode(command.Argv) {
			return false
		}
		operation = OperationDecode
	default:
		return false
	}
	// Structural pipeline discovery runs before classification. Its caller
	// validates only the exact argv/output shape; classification and the final
	// authority pass additionally require the corresponding semantic action.
	if !requireOperation {
		return true
	}
	for _, candidate := range command.Operations {
		if candidate == operation ||
			operation == OperationFetch && candidate == OperationUpload {
			return true
		}
	}
	return false
}

// ProvesPOSIXPipelineInterpreterSource reports whether a complete POSIX
// command emits fetched, uploaded-response, or decoded bytes on stdout. It
// deliberately excludes output/config indirection and unknown option grammar.
func ProvesPOSIXPipelineInterpreterSource(command CommandFact) bool {
	return exactPOSIXPipelineInterpreterSource(&command, true)
}

func posixCommandRedirectsStdout(command *CommandFact) bool {
	for _, redirect := range command.Redirects {
		if redirect.FD == 1 || redirect.FD == -1 {
			return true
		}
	}
	return false
}

func exactPOSIXCurlResponseStdout(argv []string) bool {
	return parseCurlArgv(argv).provesResponseStdout()
}

func curlBundledStdoutOutput(argument string) bool {
	return exactBundledOutputOption(argument, "o-", "fsSLkNg46v")
}

func curlBundledSeparatedOutputOption(argument string) bool {
	return exactBundledOutputOption(argument, "o", "fsSLkNg46v")
}

func exactPOSIXWgetResponseStdout(argv []string) bool {
	parsed := parseWgetArgv(argv)
	if !parsed.provesResponseStdout() {
		return false
	}
	for _, target := range parsed.Targets {
		if _, ok := webTargetFact(0, target, NetworkDownload); ok {
			return true
		}
	}
	return false
}

func wgetBundledStdoutOutput(argument string) bool {
	return exactBundledOutputOption(argument, "O-", "qS")
}

func wgetBundledSeparatedOutputOption(argument string) bool {
	return exactBundledOutputOption(argument, "O", "qS")
}

func exactBundledOutputOption(argument, suffix, allowedPrefix string) bool {
	if len(argument) <= len(suffix)+1 || argument[0] != '-' ||
		argument[1] == '-' || !strings.HasSuffix(argument, suffix) {
		return false
	}
	prefixEnd := len(argument) - len(suffix)
	for _, option := range argument[1:prefixEnd] {
		if !strings.ContainsRune(allowedPrefix, option) {
			return false
		}
	}
	return true
}

func exactPOSIXBase64DecodeMode(argv []string) bool {
	return parsePortableBase64DecodeArgv(argv).provesDecodedStdout()
}

func posixVersionedPythonProgram(program string) bool {
	if !strings.HasPrefix(program, "python") {
		return false
	}
	suffix := strings.TrimPrefix(program, "python")
	if suffix == "" {
		return true
	}
	previousDot := true
	for _, character := range suffix {
		if character == '.' {
			if previousDot {
				return false
			}
			previousDot = true
			continue
		}
		if character < '0' || character > '9' {
			return false
		}
		previousDot = false
	}
	return !previousDot
}

func shellScriptOperand(program string, argv []string) (string, bool) {
	invocation := parsePOSIXShellInvocation(program, argv)
	if !invocation.valid || invocation.mode != posixShellModeScript ||
		invocation.scriptIndex < 0 || invocation.scriptIndex >= len(argv) {
		return "", false
	}
	return argv[invocation.scriptIndex], true
}

// exactPOSIXShellScriptOperand recognizes a reviewed shell launch whose only
// unresolved semantics are the selected script bytes.
func exactPOSIXShellScriptOperand(program string, argv []string) (string, bool) {
	return shellScriptOperand(program, argv)
}

func classifySourceInvocation(out *parseOutput, command *CommandFact) {
	addOperation(command, OperationRead)
	if command.Dialect == DialectPowerShell {
		if len(command.Argv) < 2 {
			out.markPartial(IssueUnsupportedConstruct)
			return
		}
		target, ok := windowsStaticScriptArtifact(
			windowsWord{value: command.Argv[1]},
			DialectPowerShell,
			false,
		)
		if !ok {
			out.markPartial(IssueUnsupportedConstruct)
			return
		}
		appendPath(out, command.ID, PathAccessRead, target)
		out.markPartial(IssueOpaqueArtifact)
		if len(command.Argv) != 2 {
			out.markPartial(IssueUnsupportedConstruct)
		}
		return
	}
	operands := pathOperands(command.Argv, optionValues())
	if len(operands) > 0 {
		appendPath(out, command.ID, PathAccessRead, operands[0])
	}
	// Sourced content executes in the current shell and remains opaque even
	// when its filename is static.
	out.markPartial(IssueOpaqueArtifact)
}

func classifyPowerShellArtifactInvocation(out *parseOutput, command *CommandFact) {
	if script, ok := powerShellFileOperand(command.Argv); ok {
		appendPath(out, command.ID, PathAccessExecute, script)
		out.markPartial(IssueOpaqueArtifact)
	}
}

// powerShellFileOperand accepts only the explicit, profile-disabled file
// form. A profile can run unrelated commands before -File, so it must never
// become artifact authority without -NoProfile.
func powerShellFileOperand(argv []string) (string, bool) {
	if len(argv) != 4 || !strings.EqualFold(argv[1], "-NoProfile") ||
		!strings.EqualFold(argv[2], "-File") {
		return "", false
	}
	program := commandProgramForDialect(argv[0], DialectPowerShell)
	if program != "powershell" && program != "pwsh" {
		return "", false
	}
	return windowsStaticScriptArtifact(
		windowsWord{
			value:    argv[3],
			wildcard: strings.ContainsAny(argv[3], "*?"),
		},
		DialectPowerShell,
		true,
	)
}

func appendPath(out *parseOutput, commandID int64, access PathAccess, value string) {
	if value == "" || value == "-" {
		return
	}
	out.appendPath(PathFact{
		CommandID: commandID,
		Access:    access,
		Flavor:    pathFlavor(value),
		Value:     value,
	})
}

func appendCommandPath(
	out *parseOutput,
	command *CommandFact,
	access PathAccess,
	value string,
) {
	if command == nil || value == "" || value == "-" {
		return
	}
	flavor := pathFlavor(value)
	if command.Dialect == DialectCMD ||
		command.Dialect == DialectPowerShell {
		canonical, ok := windowsCanonicalPathFactValue(value)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		value = canonical
		flavor = windowsPathFlavor(value)
		switch command.Dialect {
		case DialectPowerShell:
			if !structuredPowerShellStaticOperand(value) {
				out.markPartial(IssueDynamicWord)
				return
			}
		case DialectCMD:
			// cmd built-ins expand * and ? in filesystem operands. Structured
			// argv does not carry the raw lexer's wildcard bit, so reject
			// those operands rather than representing a pattern as an exact
			// path.
			if strings.ContainsAny(value, "*?") {
				out.markPartial(IssueDynamicWord)
				return
			}
		}
	}
	out.appendPath(PathFact{
		CommandID: command.ID,
		Access:    access,
		Flavor:    flavor,
		Value:     value,
	})
}

func addSourceDestinationPaths(out *parseOutput, command *CommandFact, removeSource bool) {
	var (
		sources       []string
		positionals   []string
		destination   string
		namedOperands bool
		options       = true
	)
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") {
			positionals = append(positionals, arg)
			continue
		}

		key, joinedValue, joined := strings.Cut(arg, "=")
		switch {
		case strings.EqualFold(key, "-path"),
			strings.EqualFold(key, "-literalpath"),
			strings.EqualFold(key, "-source"):
			namedOperands = true
			value, ok := classifierOptionValue(command.Argv, &i, joinedValue, joined)
			if !ok {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			sources = append(sources, value)
		case strings.EqualFold(key, "-destination"),
			key == "-t",
			key == "--target-directory":
			namedOperands = true
			value, ok := classifierOptionValue(command.Argv, &i, joinedValue, joined)
			if !ok {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if destination != "" && destination != value {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			destination = value
		case key == "-S", key == "--suffix":
			if _, ok := classifierOptionValue(command.Argv, &i, joinedValue, joined); !ok {
				out.markPartial(IssueUnknownOperandGrammar)
			}
		default:
			// Switches and unknown options cannot safely consume a following
			// path. Joined values remain attached to their option.
		}
	}

	if namedOperands {
		sources = append(sources, positionals...)
	} else {
		if len(positionals) >= 2 {
			sources = append(sources, positionals[:len(positionals)-1]...)
			destination = positionals[len(positionals)-1]
		}
	}
	if len(sources) == 0 || destination == "" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	for _, source := range sources {
		appendCommandPath(out, command, PathAccessRead, source)
		if removeSource {
			appendCommandPath(out, command, PathAccessDelete, source)
		}
	}
	appendCommandPath(out, command, PathAccessWrite, destination)
}

func classifyPOSIXCopyMove(
	out *parseOutput,
	command *CommandFact,
	removeSource bool,
) {
	preview, complete := copyMoveOptionGrammar(command.Argv, removeSource)
	if preview {
		command.Effect = EffectPreview
		return
	}
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if removeSource {
		addOperation(command, OperationMove)
	} else {
		addOperation(command, OperationCopy)
	}
	addSourceDestinationPaths(out, command, removeSource)
}

func copyMoveOptionGrammar(argv []string, move bool) (bool, bool) {
	complete := true
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}
		lower := strings.ToLower(arg)
		if lower == "--help" || lower == "--version" {
			return true, complete
		}
		key, _, joined := strings.Cut(lower, "=")
		rawKey, _, _ := strings.Cut(arg, "=")
		switch {
		case rawKey == "-t", rawKey == "-S",
			key == "--target-directory", key == "--suffix":
			if joined {
				if strings.HasSuffix(arg, "=") {
					complete = false
				}
				continue
			}
			if len(arg) > 2 && arg[0] == '-' && arg[1] != '-' {
				// Compact required-value options are valid, but the shared
				// source/destination projector does not own this form.
				complete = false
				continue
			}
			if i+1 >= len(argv) || argv[i+1] == "" {
				complete = false
				continue
			}
			i++
			continue
		case key == "--backup", key == "--context",
			key == "--no-preserve", key == "--preserve",
			key == "--reflink", key == "--sparse", key == "--update":
			continue
		}
		if copyMoveLongFlag(key, move) {
			continue
		}
		if arg[0] == '-' && len(arg) > 1 && arg[1] != '-' &&
			copyMoveShortFlags(arg[1:], move) {
			continue
		}
		complete = false
	}
	return false, complete
}

func copyMoveLongFlag(option string, move bool) bool {
	switch option {
	case "--archive", "--attributes-only", "--copy-contents", "--dereference",
		"--force", "--interactive", "--link", "--no-clobber",
		"--no-dereference", "--no-target-directory", "--one-file-system",
		"--parents", "--recursive", "--remove-destination",
		"--strip-trailing-slashes", "--symbolic-link", "--verbose":
		return true
	case "--exchange", "--no-copy":
		return move
	default:
		return false
	}
}

func copyMoveShortFlags(flags string, move bool) bool {
	if flags == "" {
		return false
	}
	allowed := "abdfHilnprRuvx"
	if move {
		allowed = "bfinTuv"
	}
	for _, flag := range flags {
		if !strings.ContainsRune(allowed, flag) {
			return false
		}
	}
	return true
}

func classifierOptionValue(
	argv []string,
	index *int,
	joinedValue string,
	joined bool,
) (string, bool) {
	if joined {
		return joinedValue, joinedValue != ""
	}
	if *index+1 >= len(argv) || argv[*index+1] == "" {
		return "", false
	}
	*index++
	return argv[*index], true
}

func classifyWebTransfer(out *parseOutput, command *CommandFact, program string) {
	if isCurlProgram(program) {
		classifyParsedCurlTransfer(out, command)
		return
	}
	if isWgetProgram(program) {
		classifyParsedWgetTransfer(out, command)
		return
	}
	preview, spider := webControlMode(command.Argv, program)
	if preview {
		command.Effect = EffectPreview
		return
	}
	pathStart := len(out.paths)
	networkStart := len(out.network)
	flowStart := len(out.dataFlows)
	powerShellWeb := isPowerShellWebProgram(program)
	seenPowerShellParameters := make(map[string]struct{})
	duplicatePowerShellParameter := false
	validPowerShellGrammar := true
	recordPowerShellParameter := func(arg string) {
		if !powerShellWeb {
			return
		}
		key, ok := powerShellWebParameterKey(arg)
		if !ok {
			return
		}
		if _, duplicate := seenPowerShellParameters[key]; duplicate {
			duplicatePowerShellParameter = true
			validPowerShellGrammar = false
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		seenPowerShellParameters[key] = struct{}{}
	}
	var (
		upload           bool
		endpointValues   []string
		hasNetwork       bool
		hasUploadFile    bool
		hasUploadStdin   bool
		hasProcessUpload bool
		hasDownloadFile  bool
		explicitOutput   bool
		downloadOutputs  []string
		outputsValid     = true
		unixSocket       string
		hasUnixSocket    bool
		cookieJar        string
		hasCookieJar     bool
	)
	options := true
	queueEndpoint := func(raw string) {
		endpointValues = append(endpointValues, raw)
	}
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options {
			recordPowerShellParameter(arg)
		}

		if options && isCurlProgram(program) {
			if value, matched := webOptionValue(command.Argv, &i, "-K", "--config"); matched {
				if value != "" && value != "-" {
					appendPath(out, command.ID, PathAccessRead, value)
				}
				// curl configuration can supply URLs, methods, upload sources,
				// output paths, and further configuration files.
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
		}

		var value string
		var matched bool
		if options {
			switch {
			case isCurlProgram(program):
				value, matched = webOptionValue(
					command.Argv,
					&i,
					"",
					"--url",
				)
			case isPowerShellWebProgram(program):
				value, matched = powerShellWebOptionValue(
					command.Argv,
					&i,
					"-uri",
				)
			}
			if matched {
				queueEndpoint(value)
				continue
			}

			switch {
			case isWgetProgram(program):
				value, matched = webOptionValue(
					command.Argv,
					&i,
					"-i",
					"--input-file",
				)
			}
			if matched {
				if value != "" && value != "-" {
					appendPath(out, command.ID, PathAccessRead, value)
				}
				// The transfer targets live in a file that static analysis
				// deliberately does not read.
				out.markPartial(IssueUnsupportedConstruct)
				continue
			}
		}

		switch {
		case options && (arg == "-O" || arg == "--remote-name") &&
			isCurlProgram(program):
			// curl's remote-name flag has no operand. The following argument
			// remains the transfer URL, but the derived destination path is
			// not statically available.
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}

		value, matched = "", false
		if options && isCurlProgram(program) && curlBundledStdoutOutput(arg) {
			explicitOutput = true
			downloadOutputs = append(downloadOutputs, "-")
			continue
		}
		if options && isWgetProgram(program) && wgetBundledStdoutOutput(arg) {
			explicitOutput = true
			continue
		}
		switch {
		case options && isCurlProgram(program) &&
			curlBundledSeparatedOutputOption(arg):
			matched = true
			if i+1 < len(command.Argv) {
				i++
				value = command.Argv[i]
			}
		case options && isWgetProgram(program) &&
			wgetBundledSeparatedOutputOption(arg):
			matched = true
			if i+1 < len(command.Argv) {
				i++
				value = command.Argv[i]
			}
		case options && isCurlProgram(program):
			value, matched = webOptionValue(command.Argv, &i, "-o", "--output")
		case options && isWgetProgram(program):
			value, matched = webOptionValue(command.Argv, &i, "-O", "--output-document")
		case options && isPowerShellWebProgram(program):
			value, matched = powerShellWebOptionValue(
				command.Argv,
				&i,
				"-outfile",
			)
		}
		if matched {
			explicitOutput = true
			if value == "" {
				outputsValid = false
				if powerShellWeb {
					validPowerShellGrammar = false
				}
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if isCurlProgram(program) {
				downloadOutputs = append(downloadOutputs, value)
				continue
			}
			stdoutOutput := value == "-" &&
				isWgetProgram(program)
			powerShellLiteralDash := value == "-" &&
				isPowerShellWebProgram(program)
			if powerShellLiteralDash {
				out.appendPath(PathFact{
					CommandID: command.ID,
					Access:    PathAccessWrite,
					Flavor:    PathFlavorWindows,
					Value:     value,
				})
				hasDownloadFile = true
			} else if value != "" && !stdoutOutput {
				appendPath(out, command.ID, PathAccessWrite, value)
				hasDownloadFile = true
			}
			continue
		}

		value, matched = "", false
		switch {
		case options && isCurlProgram(program):
			value, matched = webOptionValue(command.Argv, &i, "-T", "--upload-file")
		case options && isWgetProgram(program):
			value, matched = webOptionValue(command.Argv, &i, "", "--post-file", "--body-file")
		case options && isPowerShellWebProgram(program):
			value, matched = powerShellWebOptionValue(
				command.Argv,
				&i,
				"-infile",
			)
		}
		if matched {
			if powerShellWeb {
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
					continue
				}
				upload = true
				hasUploadFile = true
				if value == "-" {
					out.appendPath(PathFact{
						CommandID: command.ID,
						Access:    PathAccessRead,
						Flavor:    PathFlavorWindows,
						Value:     value,
					})
				} else {
					appendCommandPath(
						out,
						command,
						PathAccessRead,
						value,
					)
				}
				continue
			}
			value = strings.TrimPrefix(value, "@")
			if value == "" {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if spider {
				continue
			}
			if value == "-" {
				upload = true
				hasUploadStdin = true
			} else if value != "" {
				upload = true
				appendPath(out, command.ID, PathAccessRead, value)
				hasUploadFile = true
			}
			continue
		}

		if options && isCurlProgram(program) {
			if value, rawData := webOptionValue(command.Argv, &i, "", "--data-raw", "--form-string"); rawData {
				if value != "" {
					upload = true
					hasProcessUpload = true
				}
				continue
			}
		}
		value, matched = "", false
		switch {
		case options && isCurlProgram(program):
			value, matched = webOptionValue(
				command.Argv,
				&i,
				"-d",
				"--data", "--data-ascii", "--data-binary", "--data-urlencode", "--json",
			)
		case options && isWgetProgram(program):
			value, matched = webOptionValue(command.Argv, &i, "", "--post-data", "--body-data")
		case options && isPowerShellWebProgram(program):
			value, matched = powerShellWebOptionValue(
				command.Argv,
				&i,
				"-body",
			)
		}
		if matched {
			if value == "" {
				if powerShellWeb {
					continue
				}
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if spider {
				continue
			}
			if powerShellWeb {
				// PowerShell binds -Body as literal/object request data.
				// curl's leading-@ file grammar does not apply.
				upload = true
				hasProcessUpload = true
				continue
			}
			if path, stdin, ok := webDataFile(value); ok {
				upload = true
				if stdin {
					hasUploadStdin = true
				} else {
					appendPath(out, command.ID, PathAccessRead, path)
					hasUploadFile = true
				}
			} else if value != "" {
				upload = true
				hasProcessUpload = true
			}
			continue
		}

		if options && isCurlProgram(program) {
			if value, matched = webOptionValue(command.Argv, &i, "-F", "--form"); matched {
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
					continue
				}
				if path, stdin, ok := webFormFile(value); ok {
					upload = true
					if stdin {
						hasUploadStdin = true
					} else {
						appendPath(out, command.ID, PathAccessRead, path)
						hasUploadFile = true
					}
				} else if value != "" {
					upload = true
					hasProcessUpload = true
				}
				continue
			}
		}

		if options && isCurlProgram(program) {
			if value, matched = webOptionValue(
				command.Argv,
				&i,
				"",
				"--unix-socket",
			); matched {
				// curl applies the final value when this option is repeated.
				// Delay ownership until parsing is complete so an overridden
				// path never survives as an effective connection target.
				unixSocket = value
				hasUnixSocket = true
				continue
			}
		}

		if options && isCurlProgram(program) {
			if value, matched = webOptionValue(
				command.Argv,
				&i,
				"-c",
				"--cookie-jar",
			); matched {
				// curl applies only the final cookie-jar destination.
				cookieJar = value
				hasCookieJar = true
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				continue
			}
		}

		if options && consumeWebNonTargetOption(
			out,
			command,
			program,
			command.Argv,
			&i,
		) {
			continue
		}
		if options && webNoValueOption(program, arg) {
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			out.markPartial(IssueUnknownOperandGrammar)
			if powerShellWeb {
				validPowerShellGrammar = false
			}
			continue
		}
		queueEndpoint(arg)
	}
	if powerShellWeb &&
		(!validPowerShellGrammar || duplicatePowerShellParameter ||
			len(endpointValues) != 1) {
		out.markPartial(IssueUnknownOperandGrammar)
		out.paths = out.paths[:pathStart]
		out.network = out.network[:networkStart]
		out.dataFlows = out.dataFlows[:flowStart]
		return
	}
	if outputsValid {
		for index, output := range downloadOutputs {
			if index >= len(endpointValues) {
				break
			}
			if output == "-" {
				continue
			}
			appendPath(out, command.ID, PathAccessWrite, output)
			hasDownloadFile = true
		}
	}
	if hasUnixSocket {
		if !staticAbsolutePOSIXPath(unixSocket) {
			out.markPartial(IssueUnknownOperandGrammar)
		} else {
			addOperation(command, OperationConnect)
			appendCommandPath(
				out,
				command,
				PathAccessConnect,
				unixSocket,
			)
		}
	}
	if spider {
		upload = false
		explicitOutput = true
	}
	action := NetworkDownload
	if upload {
		action = NetworkUpload
		addOperation(command, OperationUpload)
	} else {
		addOperation(command, OperationFetch)
	}
	for _, raw := range endpointValues {
		fact, ok := webTargetFact(command.ID, raw, action)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if out.appendNetwork(fact) {
			hasNetwork = true
		}
	}
	if hasCookieJar && cookieJar != "" && cookieJar != "-" {
		appendPath(out, command.ID, PathAccessWrite, cookieJar)
		hasDownloadFile = true
	}
	if !hasNetwork {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if isWgetProgram(program) && !explicitOutput {
		// wget writes to a URL-derived file by default. Without -O, the
		// destination path and response flow cannot be projected exactly.
		out.markPartial(IssueUnknownOperandGrammar)
	}
	addWebTransferFlows(
		out,
		command.ID,
		upload,
		hasNetwork,
		hasUploadFile,
		hasUploadStdin,
		hasProcessUpload,
		hasDownloadFile,
	)
}

func webControlMode(argv []string, program string) (preview bool, spider bool) {
	options := true
	ownershipUncertain := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		switch {
		case isCurlProgram(program) &&
			(arg == "-h" || arg == "--help" ||
				strings.HasPrefix(arg, "--help=") ||
				arg == "-V" || arg == "--version" ||
				arg == "--manual"):
			if !ownershipUncertain {
				return true, spider
			}
			continue
		case isWgetProgram(program) &&
			(arg == "-h" || arg == "--help" ||
				arg == "-V" || arg == "--version"):
			if !ownershipUncertain {
				return true, spider
			}
			continue
		case isWgetProgram(program) && arg == "--spider":
			spider = true
			continue
		}
		if webControlOptionConsumesValue(program, arg) {
			if !strings.Contains(arg, "=") &&
				!webShortOptionHasJoinedValue(program, arg) {
				if i+1 >= len(argv) {
					ownershipUncertain = true
					continue
				}
				i++
			}
			continue
		}
		if webNoValueOption(program, arg) {
			continue
		}
		// Until an option's operand grammar is known, a later help-shaped
		// token might be its value rather than a control. Keep execution
		// semantics and let the main classifier force legacy fallback.
		ownershipUncertain = true
	}
	return false, spider
}

func webControlOptionConsumesValue(program, option string) bool {
	if isCurlProgram(program) {
		if curlBundledSeparatedOutputOption(option) {
			return true
		}
		key, _, _ := strings.Cut(option, "=")
		switch key {
		case "--user-agent", "--cookie", "--cookie-jar", "--data",
			"--data-ascii", "--data-binary", "--data-raw",
			"--data-urlencode", "--referer", "--form", "--form-string",
			"--header", "--config", "--output", "--upload-file", "--user",
			"--proxy-user", "--write-out", "--request", "--proxy", "--cacert",
			"--cert", "--connect-to",
			"--connect-timeout", "--dns-servers", "--interface", "--json",
			"--key", "--max-time", "--output-dir", "--request-target",
			"--resolve", "--unix-socket", "--url", "--doh-url",
			"--preproxy", "--proxy1.0", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname":
			return true
		}
		if len(option) >= 2 && option[0] == '-' && option[1] != '-' {
			option = option[:2]
		}
		switch option {
		case "-A", "-b", "-c", "-d", "-e", "-F", "-H", "-K", "-o", "-T",
			"-u", "-w", "-X", "-x":
			return true
		}
	}
	if isWgetProgram(program) {
		if wgetBundledSeparatedOutputOption(option) {
			return true
		}
		key, _, _ := strings.Cut(option, "=")
		switch key {
		case "--append-output", "--bind-address", "--body-data",
			"--body-file", "--execute", "--header", "--input-file",
			"--output-file", "--output-document", "--password", "--post-data",
			"--post-file", "--directory-prefix", "--proxy-password", "--proxy-user",
			"--referer", "--timeout", "--tries", "--user",
			"--user-agent":
			return true
		}
		if len(option) >= 2 && option[0] == '-' && option[1] != '-' {
			option = option[:2]
		}
		switch option {
		case "-a", "-e", "-i", "-o", "-O", "-P", "-T", "-t":
			return true
		}
	}
	if isPowerShellWebProgram(program) {
		if strings.Contains(option, "=") {
			return false
		}
		lower := strings.ToLower(option)
		key, _, _ := strings.Cut(lower, "=")
		switch key {
		case "-body", "-contenttype", "-credential", "-headers", "-infile",
			"-method", "-outfile", "-timeoutsec", "-uri", "-useragent":
			return true
		}
	}
	return false
}

func webShortOptionHasJoinedValue(program, option string) bool {
	if len(option) <= 2 || option[0] != '-' || option[1] == '-' {
		return false
	}
	if isCurlProgram(program) {
		return strings.ContainsRune("AbcdeFHoTuWwxX", rune(option[1]))
	}
	if isWgetProgram(program) {
		return strings.ContainsRune("aeiOoPTt", rune(option[1]))
	}
	return false
}

func consumeWebNonTargetOption(
	out *parseOutput,
	command *CommandFact,
	program string,
	argv []string,
	index *int,
) bool {
	consume := func(short string, long ...string) (string, bool) {
		return webOptionValue(argv, index, short, long...)
	}
	requireValue := func(value string, matched bool) bool {
		if matched && value == "" {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return matched
	}

	if isCurlProgram(program) {
		for _, option := range []struct {
			short string
			long  []string
		}{
			{
				short: "-x",
				long: []string{
					"--proxy", "--proxy1.0", "--preproxy",
					"--socks4", "--socks4a", "--socks5",
					"--socks5-hostname",
				},
			},
			{
				long: []string{
					"--connect-to", "--resolve", "--dns-servers",
					"--doh-url",
				},
			},
		} {
			if value, matched := consume(option.short, option.long...); matched {
				requireValue(value, true)
				// These options can change the actual network peer without
				// changing the logical URL. Until that effective target is
				// modeled, the logical URL facts are diagnostic only.
				out.markPartial(IssueUnsupportedConstruct)
				return true
			}
		}
		for _, option := range []struct {
			short string
			long  []string
		}{
			{short: "-X", long: []string{"--request"}},
			{short: "-H", long: []string{"--header"}},
			{short: "-A", long: []string{"--user-agent"}},
			{short: "-u", long: []string{"--user", "--proxy-user"}},
			{short: "-e", long: []string{"--referer"}},
			{short: "-w", long: []string{"--write-out"}},
			{long: []string{
				"--connect-timeout", "--interface", "--max-time",
				"--request-target",
			}},
		} {
			if value, matched := consume(option.short, option.long...); matched {
				requireValue(value, true)
				return true
			}
		}
		for _, option := range []struct {
			access PathAccess
			short  string
			long   []string
		}{
			{access: PathAccessRead, long: []string{"--cacert", "--key"}},
		} {
			if value, matched := consume(option.short, option.long...); matched {
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
				} else if value != "-" {
					appendCommandPath(out, command, option.access, value)
				}
				return true
			}
		}
		if value, matched := consume("-b", "--cookie"); matched {
			if value == "" {
				out.markPartial(IssueUnknownOperandGrammar)
			} else if value != "-" && !strings.Contains(value, "=") {
				// curl treats a cookie argument without '=' as a cookie
				// input filename. A name=value argument is literal header
				// data and must never become an upload source.
				appendCommandPath(out, command, PathAccessRead, value)
			}
			return true
		}
		// Certificate values can include a password suffix, so their path
		// ownership remains deliberately non-authoritative.
		if value, matched := consume("", "--cert"); matched {
			requireValue(value, true)
			out.markPartial(IssueUnknownOperandGrammar)
			return true
		}
		return false
	}

	if isWgetProgram(program) {
		for _, option := range []struct {
			short string
			long  []string
		}{
			{short: "-o", long: []string{"--output-file"}},
			{short: "-a", long: []string{"--append-output"}},
			{short: "-P", long: []string{"--directory-prefix"}},
			{short: "-T", long: []string{"--timeout"}},
			{short: "-t", long: []string{"--tries"}},
			{long: []string{
				"--bind-address", "--header", "--password", "--proxy-password",
				"--proxy-user", "--referer", "--user", "--user-agent",
			}},
		} {
			if value, matched := consume(option.short, option.long...); matched {
				requireValue(value, true)
				return true
			}
		}
		if value, matched := consume("-e", "--execute"); matched {
			requireValue(value, true)
			out.markPartial(IssueUnknownOperandGrammar)
			return true
		}
		return false
	}

	if isPowerShellWebProgram(program) {
		for _, options := range [][]string{
			{"-method"},
			{"-headers"},
			{"-useragent"},
			{"-credential"},
			{"-contenttype"},
			{"-timeoutsec"},
		} {
			if value, matched := powerShellWebOptionValue(
				argv,
				index,
				options...,
			); matched {
				if !requireValue(value, true) {
					return true
				}
				if strings.EqualFold(options[0], "-method") &&
					!knownHTTPMethod(value) {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				return true
			}
		}
	}
	return false
}

func staticAbsolutePOSIXPath(value string) bool {
	if !strings.HasPrefix(value, "/") || hasUnresolvedPathSyntax(value) {
		return false
	}
	switch pathFlavor(value) {
	case PathFlavorPOSIX, PathFlavorDevice:
		return true
	default:
		return false
	}
}

func webNoValueOption(program, arg string) bool {
	if isCurlProgram(program) {
		switch arg {
		case "-f", "--fail", "--fail-with-body", "-s", "--silent",
			"-S", "--show-error", "-L", "--location", "-l", "-i",
			"--head", "-k", "--insecure", "-N", "--no-buffer", "-g",
			"--globoff", "-4", "--ipv4", "-6", "--ipv6", "-q", "-v",
			"--verbose", "--compressed", "--no-progress-meter", "--remote-name":
			return true
		}
		return curlNoValueShortOptionBundle(arg)
	}
	if isWgetProgram(program) {
		switch arg {
		case "-q", "--quiet", "-S", "--server-response", "--spider",
			"--no-check-certificate", "--content-disposition":
			return true
		}
	}
	if isPowerShellWebProgram(program) {
		lower := strings.ToLower(arg)
		switch lower {
		case "-usebasicparsing", "-skipcertificatecheck":
			return true
		}
	}
	return false
}

func curlNoValueShortOptionBundle(argument string) bool {
	if len(argument) < 3 || argument[0] != '-' || argument[1] == '-' {
		return false
	}
	for _, option := range argument[1:] {
		if !strings.ContainsRune("fsSLkNg46qv", option) {
			return false
		}
	}
	return true
}

func isCurlProgram(program string) bool {
	return program == "curl" || program == "curl.exe"
}

func isWgetProgram(program string) bool {
	return program == "wget" || program == "wget.exe"
}

func isPowerShellWebProgram(program string) bool {
	switch program {
	case "invoke-webrequest", "iwr", "invoke-restmethod", "irm":
		return true
	default:
		return false
	}
}

func powerShellWebParameterKey(value string) (string, bool) {
	if strings.Contains(value, "=") {
		return "", false
	}
	key, _, _ := strings.Cut(strings.ToLower(value), "=")
	switch key {
	case "-uri":
		return "uri", true
	case "-outfile", "-o", "--output":
		return "outfile", true
	case "-infile", "-t", "--upload-file":
		return "infile", true
	case "-body", "-d", "--data", "--data-binary":
		return "body", true
	case "-method", "-x", "--request":
		return "method", true
	case "-headers":
		return "headers", true
	case "-useragent":
		return "useragent", true
	case "-credential":
		return "credential", true
	case "-contenttype":
		return "contenttype", true
	case "-timeoutsec":
		return "timeoutsec", true
	case "-force":
		return "force", true
	case "-usebasicparsing":
		return "usebasicparsing", true
	case "-skipcertificatecheck":
		return "skipcertificatecheck", true
	default:
		return "", false
	}
}

func powerShellWebOptionValue(
	argv []string,
	index *int,
	options ...string,
) (string, bool) {
	lower := strings.ToLower(argv[*index])
	for _, option := range options {
		if lower != strings.ToLower(option) {
			continue
		}
		if *index+1 < len(argv) {
			(*index)++
			return argv[*index], true
		}
		return "", true
	}
	return "", false
}

func webOptionValue(
	argv []string,
	index *int,
	short string,
	longOptions ...string,
) (string, bool) {
	arg := argv[*index]
	if short != "" {
		switch {
		case arg == short:
			if *index+1 < len(argv) {
				(*index)++
				return argv[*index], true
			}
			return "", true
		case strings.HasPrefix(arg, short) && len(arg) > len(short):
			return arg[len(short):], true
		}
	}
	for _, option := range longOptions {
		switch {
		case arg == option:
			if *index+1 < len(argv) {
				(*index)++
				return argv[*index], true
			}
			return "", true
		case strings.HasPrefix(arg, option+"="):
			return arg[len(option)+1:], true
		}
	}
	return "", false
}

func webDataFile(value string) (string, bool, bool) {
	if !strings.HasPrefix(value, "@") {
		return "", false, false
	}
	value = strings.TrimPrefix(value, "@")
	if value == "-" {
		return "", true, true
	}
	if value == "" {
		return "", false, false
	}
	return value, false, true
}

func webFormFile(value string) (string, bool, bool) {
	if _, payload, ok := strings.Cut(value, "="); ok {
		value = payload
	}
	if value == "" || value[0] != '@' && value[0] != '<' {
		return "", false, false
	}
	value = value[1:]
	if separator := strings.Index(value, ";"); separator >= 0 {
		value = value[:separator]
	}
	if value == "-" {
		return "", true, true
	}
	if value == "" {
		return "", false, false
	}
	return value, false, true
}

func addWebTransferFlows(
	out *parseOutput,
	commandID int64,
	upload bool,
	hasNetwork bool,
	hasUploadFile bool,
	hasUploadStdin bool,
	hasProcessUpload bool,
	hasDownloadFile bool,
) {
	if !hasNetwork {
		return
	}
	if upload {
		if hasUploadFile {
			out.appendDataFlow(DataFlowFact{
				ToCommandID: commandID,
				From:        DataFile,
				To:          DataProcess,
			})
		}
		if hasUploadStdin {
			out.appendDataFlow(DataFlowFact{
				FromCommandID: commandID,
				From:          DataStdin,
				To:            DataNetwork,
			})
		}
		if hasUploadFile || hasProcessUpload || !hasUploadStdin {
			out.appendDataFlow(DataFlowFact{
				FromCommandID: commandID,
				From:          DataProcess,
				To:            DataNetwork,
			})
		}
		if hasDownloadFile {
			out.appendDataFlow(DataFlowFact{
				ToCommandID: commandID,
				From:        DataNetwork,
				To:          DataProcess,
			})
			out.appendDataFlow(DataFlowFact{
				FromCommandID: commandID,
				From:          DataProcess,
				To:            DataFile,
			})
		}
		return
	}

	out.appendDataFlow(DataFlowFact{
		ToCommandID: commandID,
		From:        DataNetwork,
		To:          DataProcess,
	})
	if hasDownloadFile {
		out.appendDataFlow(DataFlowFact{
			FromCommandID: commandID,
			From:          DataProcess,
			To:            DataFile,
		})
	}
}

func classifySSH(out *parseOutput, command *CommandFact, program string) {
	options := classifySSHOptionPaths(out, command, program)
	if !options.valid {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if sshInformationalQuery(program, command.Argv) {
		command.Effect = EffectPreview
		addOperation(command, OperationList)
		return
	}
	if sshHasUnownedQuery(program, command.Argv) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if sshConfigurationQuery(program, command.Argv) {
		command.Effect = EffectPreview
		addOperation(command, OperationList)
		return
	}
	if !options.configurationDisabled {
		// Unless the exact `-F none` form is present, OpenSSH can load user and
		// system configuration that changes endpoints, forwarding, and local
		// command execution outside the supplied argv.
		out.markPartial(IssueUnsupportedConstruct)
	}
	if sshAutoSSHProgram(program) {
		// autossh restarts and can substitute its child executable through
		// environment state that is not represented by ActionFacts.
		out.markPartial(IssueUnsupportedConstruct)
	}
	action := NetworkConnect
	if hasSSHTunnel(program, command.Argv) {
		action = NetworkTunnel
		addOperation(command, OperationTunnel)
	} else {
		addOperation(command, OperationConnect)
	}
	hostIndex := options.destinationIndex
	if hostIndex < 0 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	destination, validDestination := parseSSHNetworkDestination(
		program,
		command.Argv[hostIndex],
	)
	if options.hasExplicitPort {
		if !options.portValid || destination.port != 0 {
			// A URI port plus -p/-P has two competing authorities. Do not
			// choose one, even when both happen to contain the same value.
			validDestination = false
		} else {
			destination.port = options.explicitPort
		}
	}
	if validDestination {
		out.appendNetwork(NetworkFact{
			CommandID: command.ID,
			Action:    action,
			Scheme:    "ssh",
			Host:      destination.host,
			Port:      destination.port,
		})
		if destination.remotePath {
			// A remote SFTP path may trigger an automatic download. Until
			// transfer direction, local target, and data flow are projected,
			// retain the endpoint only as a diagnostic fact.
			out.markPartial(IssueUnsupportedConstruct)
		}
	} else {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if hostIndex+1 < len(command.Argv) {
		// The remote command is interpreted by a shell on the destination,
		// whose grammar and environment are unavailable locally.
		addOperation(command, OperationExecute)
		out.markPartial(IssueUnsupportedConstruct)
	}
}

type sshDestination struct {
	host       string
	port       int64
	remotePath bool
}

func parseSSHNetworkDestination(
	program string,
	value string,
) (sshDestination, bool) {
	if value == "" || len(value) > maxScalarBytes ||
		strings.TrimSpace(value) != value {
		return sshDestination{}, false
	}
	if strings.Contains(value, "://") {
		return parseSSHURIDestination(program, value)
	}
	hostToken, remotePath, ok := sshPlainDestinationHost(
		value,
		sshSFTPProgram(program),
	)
	if !ok {
		return sshDestination{}, false
	}
	host, ok := canonicalSSHNetworkHost(hostToken)
	if !ok {
		return sshDestination{}, false
	}
	return sshDestination{host: host, remotePath: remotePath}, true
}

func parseSSHURIDestination(
	program string,
	value string,
) (sshDestination, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return sshDestination{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	sftp := sshSFTPProgram(program)
	if (sftp && scheme != "sftp") || (!sftp && scheme != "ssh") {
		return sshDestination{}, false
	}
	if !sftp && (parsed.Path != "" || parsed.RawPath != "") {
		return sshDestination{}, false
	}
	if parsed.User != nil {
		username := parsed.User.Username()
		if username == "" || !validSSHUsername(username) {
			return sshDestination{}, false
		}
		if _, passwordSet := parsed.User.Password(); passwordSet {
			return sshDestination{}, false
		}
	}
	rawHost := parsed.Host
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(rawHost, ":") {
		return sshDestination{}, false
	}
	if strings.Contains(hostname, ":") {
		if !strings.HasPrefix(rawHost, "[") ||
			net.ParseIP(hostname) == nil {
			return sshDestination{}, false
		}
	} else if strings.HasPrefix(rawHost, "[") {
		return sshDestination{}, false
	}
	host, ok := canonicalSSHNetworkHost(hostname)
	if !ok {
		return sshDestination{}, false
	}
	port := int64(0)
	if rawPort := parsed.Port(); rawPort != "" {
		port, ok = parseNetworkPort(rawPort)
		if !ok {
			return sshDestination{}, false
		}
	}
	return sshDestination{
		host:       host,
		port:       port,
		remotePath: sftp && (parsed.Path != "" || parsed.RawPath != ""),
	}, true
}

func sshPlainDestinationHost(
	value string,
	allowRemotePath bool,
) (string, bool, bool) {
	if !allowRemotePath {
		if strings.Count(value, "@") > 1 {
			return "", false, false
		}
		if user, destination, hasUser := strings.Cut(value, "@"); hasUser {
			if !validSSHUsername(user) || destination == "" {
				return "", false, false
			}
			value = destination
		}
		if strings.ContainsAny(value, "[]") {
			return "", false, false
		}
		if strings.Contains(value, ":") && net.ParseIP(value) == nil {
			return "", false, false
		}
		return value, false, value != ""
	}

	// SFTP's plain form is [user@]host[:path]. Only an @ before the
	// authority/path delimiter identifies a username; @, colons, and brackets
	// after that delimiter are ordinary remote-path characters.
	if at := strings.IndexByte(value, '@'); at >= 0 {
		colon := strings.IndexByte(value, ':')
		if colon < 0 || at < colon {
			if !validSSHUsername(value[:at]) || at+1 >= len(value) {
				return "", false, false
			}
			value = value[at+1:]
		}
	}
	if strings.HasPrefix(value, "[") {
		closeBracket := strings.IndexByte(value, ']')
		if closeBracket <= 1 {
			return "", false, false
		}
		host := value[1:closeBracket]
		if net.ParseIP(host) == nil || !strings.Contains(host, ":") {
			return "", false, false
		}
		remainder := value[closeBracket+1:]
		if remainder == "" {
			return host, false, true
		}
		if !strings.HasPrefix(remainder, ":") {
			return "", false, false
		}
		return host, true, true
	}
	host, _, remotePath := strings.Cut(value, ":")
	if host == "" || strings.ContainsAny(host, "[]") {
		return "", false, false
	}
	return host, remotePath, true
}

func canonicalSSHNetworkHost(host string) (string, bool) {
	if host == "" || strings.TrimSpace(host) != host ||
		strings.HasPrefix(host, "-") ||
		strings.ContainsAny(host, `/\@[]`) {
		return "", false
	}
	if canonical, ok := canonicalNetworkHost(host); ok {
		return canonical, true
	}

	// OpenSSH accepts resolver-backed single-label names and absolute DNS names
	// with a trailing root label. The general network canonicalizer is stricter
	// because most other tools require an unambiguous FQDN or IP.
	candidate := host
	if strings.HasSuffix(candidate, ".") {
		candidate = strings.TrimSuffix(candidate, ".")
	}
	if candidate == "" || len(candidate) > 253 ||
		legacyIPv4Candidate(candidate) {
		return "", false
	}
	for _, label := range strings.Split(candidate, ".") {
		if label == "" || len(label) > 63 ||
			!isASCIIAlphaNumeric(label[0]) ||
			!isASCIIAlphaNumeric(label[len(label)-1]) {
			return "", false
		}
		for index := 1; index+1 < len(label); index++ {
			char := label[index]
			if !isASCIIAlphaNumeric(char) && char != '-' {
				return "", false
			}
		}
	}
	return strings.ToLower(candidate), true
}

func isASCIIAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' ||
		value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9'
}

func validSSHUsername(value string) bool {
	if value == "" || len(value) > maxScalarBytes {
		return false
	}
	for _, char := range value {
		if char <= ' ' || char == 0x7f ||
			char == '@' || char == '/' || char == '\\' {
			return false
		}
	}
	return true
}

func classifySCP(out *parseOutput, command *CommandFact) {
	var operands []string
	options := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if arg == "-h" || arg == "-?" ||
				strings.EqualFold(arg, "--help") {
				command.Effect = EffectPreview
				return
			}
			consumes, joined, known := scpOptionGrammar(arg)
			if !known {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if consumes && !joined {
				if i+1 >= len(command.Argv) || command.Argv[i+1] == "" {
					out.markPartial(IssueUnknownOperandGrammar)
					continue
				}
				i++
			}
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationConnect)

	firstHost, firstRemote := scpRemoteHost(operands[0])
	lastHost, lastRemote := scpRemoteHost(operands[len(operands)-1])
	switch {
	case !firstRemote && lastRemote:
		addOperation(command, OperationUpload)
		for _, source := range operands[:len(operands)-1] {
			if _, remote := scpRemoteHost(source); remote {
				out.markPartial(IssueUnsupportedConstruct)
				continue
			}
			appendPath(out, command.ID, PathAccessRead, source)
		}
		out.appendNetwork(NetworkFact{
			CommandID: command.ID,
			Action:    NetworkUpload,
			Scheme:    "ssh",
			Host:      strings.ToLower(lastHost),
		})
		out.appendDataFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataFile,
			To:          DataProcess,
		})
		out.appendDataFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataNetwork,
		})

	case firstRemote && !lastRemote:
		addOperation(command, OperationFetch)
		for _, source := range operands[:len(operands)-1] {
			host, remote := scpRemoteHost(source)
			if !remote || !strings.EqualFold(host, firstHost) {
				out.markPartial(IssueUnsupportedConstruct)
			}
		}
		appendPath(out, command.ID, PathAccessWrite, operands[len(operands)-1])
		out.appendNetwork(NetworkFact{
			CommandID: command.ID,
			Action:    NetworkDownload,
			Scheme:    "ssh",
			Host:      strings.ToLower(firstHost),
		})
		out.appendDataFlow(DataFlowFact{
			ToCommandID: command.ID,
			From:        DataNetwork,
			To:          DataProcess,
		})
		out.appendDataFlow(DataFlowFact{
			FromCommandID: command.ID,
			From:          DataProcess,
			To:            DataFile,
		})

	default:
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	host := lastHost
	if firstRemote {
		host = firstHost
	}
	out.appendNetwork(NetworkFact{
		CommandID: command.ID,
		Action:    NetworkConnect,
		Scheme:    "ssh",
		Host:      strings.ToLower(host),
	})
}

func scpOptionGrammar(flag string) (consumes, joined, known bool) {
	switch {
	case flag == "-c" || flag == "-D" || flag == "-F" || flag == "-i" ||
		flag == "-I" || flag == "-J" || flag == "-l" || flag == "-o" ||
		flag == "-P" || flag == "-S" || flag == "-X":
		return true, false, true
	case len(flag) > 2 && flag[0] == '-' && flag[1] != '-' &&
		strings.ContainsRune("cDFiIJloPSX", rune(flag[1])):
		return true, true, true
	case len(flag) > 1 && flag[0] == '-' && flag[1] != '-' &&
		scpSwitchBundle(flag[1:]):
		return false, false, true
	default:
		return false, false, false
	}
}

func scpSwitchBundle(flags string) bool {
	if flags == "" {
		return false
	}
	for _, flag := range flags {
		if !strings.ContainsRune("346ABCOpqRrTv", flag) {
			return false
		}
	}
	return true
}

func scpRemoteHost(value string) (string, bool) {
	if strings.Contains(value, "://") || windowsDrivePath(value) {
		return "", false
	}
	colon := strings.Index(value, ":")
	if colon <= 0 {
		return "", false
	}
	host := value[:colon]
	if at := strings.LastIndex(host, "@"); at >= 0 {
		host = host[at+1:]
	}
	if !validNetworkHost(host) {
		return "", false
	}
	return host, true
}

func windowsDrivePath(value string) bool {
	return len(value) >= 3 &&
		((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) &&
		value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}

func sshSFTPProgram(program string) bool {
	return program == "sftp" || program == "sftp.exe"
}

func sshAutoSSHProgram(program string) bool {
	return program == "autossh" || program == "autossh.exe"
}

func sshInformationalQuery(program string, argv []string) bool {
	if sshSFTPProgram(program) || len(argv) < 2 {
		return false
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			break
		}
		if arg == "-V" {
			// OpenSSH exits immediately after displaying its version; any
			// remaining operands are not interpreted as a destination.
			return true
		}
		if sshFlagConsumesValue(program, arg) && len(arg) == 2 {
			if index+1 >= len(argv) {
				return false
			}
			index++
		}
	}
	return len(argv) == 3 && argv[1] == "-Q" &&
		sshKnownQueryOption(argv[2])
}

func sshKnownQueryOption(value string) bool {
	switch strings.ToLower(value) {
	case "cipher", "cipher-auth", "help", "mac", "kex", "key",
		"key-ca-sign", "key-cert", "key-plain", "key-sig",
		"protocol-version", "sig":
		return true
	default:
		return false
	}
}

func sshHasUnownedQuery(program string, argv []string) bool {
	if sshSFTPProgram(program) {
		return false
	}
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			return false
		}
		if arg == "-Q" {
			return true
		}
		if sshFlagConsumesValue(program, arg) && len(arg) == 2 {
			index++
		}
	}
	return false
}

func sshConfigurationQuery(program string, argv []string) bool {
	if sshSFTPProgram(program) {
		return false
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return false
		}
		if arg == "-G" {
			return true
		}
		if sshFlagConsumesValue(program, arg) && len(arg) == 2 {
			i++
		}
	}
	return false
}

func hasSSHTunnel(program string, argv []string) bool {
	if sshSFTPProgram(program) {
		return false
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			return false
		}
		if arg == "-D" || arg == "-L" || arg == "-R" || arg == "-W" ||
			arg == "-w" ||
			len(arg) > 2 && (strings.HasPrefix(arg, "-D") ||
				strings.HasPrefix(arg, "-L") ||
				strings.HasPrefix(arg, "-R") ||
				strings.HasPrefix(arg, "-W") ||
				strings.HasPrefix(arg, "-w")) {
			return true
		}
		if arg == "-o" {
			if i+1 < len(argv) {
				i++
				if sshOptionEnablesTunnel(argv[i]) {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "-o") &&
			sshOptionEnablesTunnel(arg[len("-o"):]) {
			return true
		}
		if sshFlagConsumesValue(program, arg) && len(arg) == 2 {
			i++
		}
	}
	return false
}

func sshOptionEnablesTunnel(value string) bool {
	key, _, ok := splitSSHConfigOption(value)
	if !ok {
		return false
	}
	switch strings.ToLower(key) {
	case "dynamicforward", "localforward", "remoteforward":
		return true
	default:
		return false
	}
}

func classifySSHOptionPaths(
	out *parseOutput,
	command *CommandFact,
	program string,
) sshOptionScan {
	scan := sshOptionScan{
		destinationIndex: -1,
		valid:            true,
		portValid:        true,
	}
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "--" {
			if i+1 < len(command.Argv) {
				scan.destinationIndex = i + 1
			} else {
				scan.valid = false
			}
			return scan
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			scan.destinationIndex = i
			return scan
		}
		access := PathAccess("")
		pathOption := ""
		joinedValue := ""
		switch arg {
		case "-F", "-i":
			access = PathAccessRead
			pathOption = arg
		case "-E":
			if !sshSFTPProgram(program) {
				access = PathAccessWrite
				pathOption = arg
			}
		case "-b":
			if sshSFTPProgram(program) {
				access = PathAccessRead
				pathOption = arg
			}
		default:
			for _, option := range []string{"-F", "-i"} {
				if strings.HasPrefix(arg, option) && len(arg) > len(option) {
					access = PathAccessRead
					pathOption = option
					joinedValue = arg[len(option):]
					break
				}
			}
			if access == "" && !sshSFTPProgram(program) &&
				strings.HasPrefix(arg, "-E") && len(arg) > len("-E") {
				access = PathAccessWrite
				pathOption = "-E"
				joinedValue = arg[len("-E"):]
			}
			if access == "" && sshSFTPProgram(program) &&
				strings.HasPrefix(arg, "-b") && len(arg) > len("-b") {
				access = PathAccessRead
				pathOption = "-b"
				joinedValue = arg[len("-b"):]
			}
		}
		if access != "" {
			if pathOption == "-F" {
				scan.configurationOptions++
				if scan.configurationOptions > 1 {
					scan.valid = false
				}
			}
			if joinedValue != "" {
				classifySSHPathOption(
					out,
					command,
					pathOption,
					access,
					joinedValue,
					sshSFTPProgram(program),
				)
				continue
			}
			if i+1 >= len(command.Argv) {
				scan.valid = false
				return scan
			}
			i++
			if command.Argv[i] == "" {
				scan.valid = false
				continue
			}
			if pathOption == "-F" {
				scan.configurationDisabled =
					scan.configurationOptions == 1 &&
						command.Argv[i] == "none"
			}
			classifySSHPathOption(
				out,
				command,
				pathOption,
				access,
				command.Argv[i],
				sshSFTPProgram(program),
			)
			continue
		}
		if arg == "-o" || strings.HasPrefix(arg, "-o") && len(arg) > 2 {
			value := strings.TrimPrefix(arg, "-o")
			if arg == "-o" {
				if i+1 >= len(command.Argv) {
					scan.valid = false
					return scan
				}
				i++
				value = command.Argv[i]
			}
			if !classifySSHConfigOption(out, command, value) {
				scan.valid = false
			}
			continue
		}
		if !sshSFTPProgram(program) && len(arg) > 2 &&
			strings.ContainsRune("DLR", rune(arg[1])) {
			if !classifySSHForwardValue(
				out,
				arg[:2],
				arg[2:],
			) {
				scan.valid = false
			}
			continue
		}
		if sshFlagConsumesValue(program, arg) && len(arg) == 2 {
			if i+1 >= len(command.Argv) {
				scan.valid = false
				return scan
			}
			i++
			value := command.Argv[i]
			if value == "" {
				scan.valid = false
				continue
			}
			if arg == "-J" {
				// ProxyJump introduces another network endpoint that is not
				// represented by the current single-destination fact.
				scan.valid = false
			}
			if sshAutoSSHProgram(program) && arg == "-M" {
				if !validAutoSSHMonitor(value) {
					scan.valid = false
				}
				out.markPartial(IssueUnsupportedConstruct)
			}
			if sshSFTPProgram(program) {
				switch arg {
				case "-S":
					// The SFTP server program executes locally. Preserve its
					// path, but keep the result diagnostic until local child
					// execution is represented explicitly.
					appendCommandPath(
						out,
						command,
						PathAccessExecute,
						value,
					)
					out.markPartial(IssueUnsupportedConstruct)
				case "-D":
					// Directly connecting to a local SFTP server process
					// bypasses the ordinary remote endpoint semantics.
					if executable, ok :=
						sftpDirectServerExecutable(value); ok {
						appendCommandPath(
							out,
							command,
							PathAccessExecute,
							executable,
						)
					}
					out.markPartial(IssueUnsupportedConstruct)
				case "-s":
					// A path here names a server on the remote host. The
					// destination is still useful, but the remote execution
					// relationship is not represented by ActionFacts.
					out.markPartial(IssueUnsupportedConstruct)
				case "-B":
					if !sshPositiveDecimal(value) {
						scan.valid = false
					}
				case "-X":
					if !validSFTPProtocolOption(value) {
						scan.valid = false
					}
				}
			} else {
				switch arg {
				case "-R", "-L", "-D":
					if !classifySSHForwardValue(out, arg, value) {
						scan.valid = false
					}
				case "-W":
					// Proxy stdio targets have a distinct grammar that this
					// structured classifier does not yet own.
					scan.valid = false
				case "-b":
					if _, ok := canonicalSSHNetworkHost(value); !ok {
						scan.valid = false
					}
				case "-I":
					appendCommandPath(
						out,
						command,
						PathAccessRead,
						value,
					)
					out.markPartial(IssueUnsupportedConstruct)
				case "-S":
					appendCommandPath(
						out,
						command,
						PathAccessConnect,
						value,
					)
					out.markPartial(IssueUnsupportedConstruct)
				case "-O", "-w":
					out.markPartial(IssueUnsupportedConstruct)
				}
			}
			if sshPortOption(program, arg) {
				scan.hasExplicitPort = true
				port, ok := parseNetworkPort(value)
				if !ok || !scan.portValid || scan.explicitPort != 0 {
					scan.portValid = false
					scan.valid = false
					continue
				}
				scan.explicitPort = port
			}
			continue
		}
		if sshSensitiveSwitch(program, arg) {
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		if sshKnownSwitch(program, arg) {
			continue
		}
		if len(arg) > 2 && sshPortOption(program, arg[:2]) {
			scan.hasExplicitPort = true
			scan.portValid = false
		}
		// Joined values for otherwise value-consuming flags and unknown
		// options are not authoritative without an exact owned grammar.
		scan.valid = false
	}
	return scan
}

func classifySSHForwardValue(
	out *parseOutput,
	option string,
	value string,
) bool {
	if windowsValidSSHTunnelSpec(option, value) {
		return true
	}
	if sshUnprojectedStreamLocalForward(option, value) {
		out.markPartial(IssueUnsupportedConstruct)
		return true
	}
	return false
}

func sshSensitiveSwitch(program string, flag string) bool {
	if sshSFTPProgram(program) {
		return flag == "-A"
	}
	switch flag {
	case "-A", "-g", "-K", "-M", "-s", "-X", "-Y":
		return true
	default:
		return false
	}
}

func validAutoSSHMonitor(value string) bool {
	first, second, hasSecond := strings.Cut(value, ":")
	if first == "0" {
		return !hasSecond
	}
	if _, ok := parseNetworkPort(first); !ok {
		return false
	}
	if !hasSecond {
		return true
	}
	_, ok := parseNetworkPort(second)
	return ok
}

func sshPositiveDecimal(value string) bool {
	numeric, err := strconv.ParseUint(value, 10, 31)
	return err == nil && numeric > 0
}

func validSFTPProtocolOption(value string) bool {
	name, rawValue, ok := strings.Cut(value, "=")
	if !ok || (name != "buffer" && name != "nrequests") {
		return false
	}
	return sshPositiveDecimal(rawValue)
}

func sftpDirectServerExecutable(value string) (string, bool) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return "", false
	}
	executable := fields[0]
	if executable == "" || strings.HasPrefix(executable, "-") ||
		strings.ContainsAny(executable, "\"'`$;&|<>()") {
		return "", false
	}
	return executable, true
}

func classifySSHPathOption(
	out *parseOutput,
	command *CommandFact,
	option string,
	access PathAccess,
	value string,
	sftp bool,
) {
	switch option {
	case "-F":
		// OpenSSH's exact sentinel disables user and system configuration
		// files. Any other filename can change hosts, proxies, forwarding, and
		// command execution outside the projected argv.
		if value == "none" {
			return
		}
		appendCommandPath(out, command, access, value)
		out.markPartial(IssueUnsupportedConstruct)
	case "-b":
		appendCommandPath(out, command, access, value)
		if sftp {
			// Batch files can contain transfers and local shell escapes. Keep
			// their read dependency while those commands remain unprojected.
			out.markPartial(IssueUnsupportedConstruct)
		}
	default:
		appendCommandPath(out, command, access, value)
	}
}

type sshOptionScan struct {
	destinationIndex      int
	explicitPort          int64
	configurationOptions  int
	hasExplicitPort       bool
	portValid             bool
	configurationDisabled bool
	valid                 bool
}

func sshPortOption(program, flag string) bool {
	if sshSFTPProgram(program) {
		return flag == "-P"
	}
	return flag == "-p"
}

func sshKnownSwitch(program, flag string) bool {
	if sshSFTPProgram(program) {
		switch flag {
		case "-4", "-6", "-A", "-a", "-C", "-f", "-N", "-p", "-q", "-r",
			"-v":
			return true
		default:
			return false
		}
	}
	switch flag {
	case "-4", "-6", "-A", "-a", "-C", "-f", "-G", "-g", "-K", "-k",
		"-M", "-N", "-n", "-q", "-s", "-T", "-t", "-V", "-v", "-vv",
		"-vvv", "-X", "-x", "-Y", "-y":
		return true
	default:
		return false
	}
}

func splitSSHConfigOption(value string) (string, string, bool) {
	key, optionValue, joined := strings.Cut(value, "=")
	if !joined {
		index := strings.IndexAny(value, " \t")
		if index < 0 {
			return "", "", false
		}
		key = value[:index]
		optionValue = strings.TrimSpace(value[index:])
	}
	if key == "" || strings.TrimSpace(key) != key || optionValue == "" {
		return "", "", false
	}
	return key, optionValue, true
}

func classifySSHConfigOption(
	out *parseOutput,
	command *CommandFact,
	value string,
) bool {
	key, optionValue, ok := splitSSHConfigOption(value)
	if !ok {
		return false
	}
	switch strings.ToLower(key) {
	case "identityfile":
		return classifySSHConfigPaths(
			out,
			command,
			optionValue,
			false,
		)
	case "globalknownhostsfile", "userknownhostsfile":
		return classifySSHConfigPaths(
			out,
			command,
			optionValue,
			true,
		)
	case "dynamicforward":
		spec, ok := sshConfigForwardSpec("-D", optionValue)
		return ok && windowsValidSSHTunnelSpec("-D", spec)
	case "localforward":
		spec, ok := sshConfigForwardSpec("-L", optionValue)
		if !ok {
			return false
		}
		if sshUnprojectedStreamLocalForward("-L", spec) {
			out.markPartial(IssueUnsupportedConstruct)
			return true
		}
		return windowsValidSSHTunnelSpec("-L", spec)
	case "remoteforward":
		spec, ok := sshConfigForwardSpec("-R", optionValue)
		if !ok {
			return false
		}
		if sshUnprojectedStreamLocalForward("-R", spec) {
			out.markPartial(IssueUnsupportedConstruct)
			return true
		}
		return windowsValidSSHTunnelSpec("-R", spec)
	default:
		return false
	}
}

func classifySSHConfigPaths(
	out *parseOutput,
	command *CommandFact,
	value string,
	list bool,
) bool {
	if strings.EqualFold(value, "none") {
		return true
	}
	values := []string{value}
	if list {
		values = strings.Fields(value)
		if len(values) == 0 {
			return false
		}
		for _, candidate := range values {
			if strings.EqualFold(candidate, "none") {
				return false
			}
		}
	}
	for _, path := range values {
		appendPath(out, command.ID, PathAccessRead, path)
		if sshConfigPathRuntimeDependent(path) {
			out.markPartial(IssueUnsupportedConstruct)
		}
	}
	return true
}

func sshConfigPathRuntimeDependent(value string) bool {
	return strings.ContainsAny(value, "%$") ||
		strings.HasPrefix(value, "~")
}

func sshConfigForwardSpec(
	option string,
	value string,
) (string, bool) {
	fields := strings.Fields(value)
	switch {
	case len(fields) == 1:
		return fields[0], true
	case (option == "-L" || option == "-R") && len(fields) == 2:
		return fields[0] + ":" + fields[1], true
	default:
		return "", false
	}
}

func sshUnprojectedStreamLocalForward(option, value string) bool {
	return (option == "-L" || option == "-R") &&
		value != "" &&
		strings.ContainsAny(value, `/\`)
}

func sshFlagConsumesValue(program, flag string) bool {
	if sshAutoSSHProgram(program) && flag == "-M" {
		return true
	}
	if sshSFTPProgram(program) {
		switch flag {
		case "-b", "-B", "-c", "-D", "-F", "-i", "-J", "-l", "-o", "-P",
			"-R", "-S", "-s", "-X":
			return true
		default:
			return false
		}
	}
	switch flag {
	case "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
		"-L", "-l", "-m", "-O", "-o", "-P", "-p", "-Q", "-R", "-S",
		"-W", "-w":
		return true
	default:
		return false
	}
}

func classifySocketTool(out *parseOutput, command *CommandFact, program string) {
	switch program {
	case "nc", "ncat", "netcat":
		classifyNetcat(out, command)
		return
	case "socat":
		classifySocat(out, command)
	}
}

func classifyTunnel(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if program != "chisel" {
		if len(command.Argv) == 2 {
			switch command.Argv[1] {
			case "-h", "--help", "-v", "--version":
				command.Effect = EffectPreview
				return
			}
		}
		addOperation(command, OperationTunnel)
		addNetworkFromArguments(out, command, NetworkTunnel)
		// These tools have distinct nested command grammars. Until an exact
		// grammar is owned here, their facts remain diagnostic and the
		// existing fallback remains authoritative.
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		exactOptionSet(
			"--auth", "--fingerprint", "--header", "--hostname",
			"--keepalive", "--max-retry-count", "--max-retry-interval",
			"--pid", "--proxy", "--tls-ca", "--tls-cert", "--tls-key",
		),
		exactOptionSet(
			"-v", "--verbose", "--reverse", "--socks5", "--stdio",
			"--tls-skip-verify",
		),
		exactOptionSet("-h", "--help", "--version"),
	)
	if parsed.preview {
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		command.Effect = EffectPreview
		return
	}
	addOperation(command, OperationTunnel)
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.positionals) < 2 ||
		parsed.positionals[0] != "client" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	fact, ok := networkURLFact(
		command.ID,
		parsed.positionals[1],
		NetworkTunnel,
	)
	if !ok {
		host, port := splitHostPortLoose(parsed.positionals[1])
		if !validNetworkHost(host) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		fact = NetworkFact{
			CommandID: command.ID,
			Action:    NetworkTunnel,
			Host:      host,
			Port:      port,
		}
	}
	out.appendNetwork(fact)
}

func classifySocat(out *parseOutput, command *CommandFact) {
	addresses := 0
	for _, arg := range command.Argv[1:] {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if fact, ok := socatAddressFact(command.ID, arg); ok {
			addresses++
			out.appendNetwork(fact)
			if fact.Action == NetworkListen {
				addOperation(command, OperationListen)
			} else {
				addOperation(command, OperationConnect)
			}
			continue
		}
		kind, value, ok := strings.Cut(arg, ":")
		if !ok {
			switch strings.ToLower(arg) {
			case "-", "stdio", "stdin", "stdout":
				addresses++
			default:
				out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		switch strings.ToLower(kind) {
		case "exec":
			addresses++
			value = strings.SplitN(value, ",", 2)[0]
			if value == "" || strings.ContainsAny(value, " \t\r\n") {
				out.markPartial(IssueUnsupportedConstruct)
				continue
			}
			appendPath(out, command.ID, PathAccessExecute, value)
		case "system":
			addresses++
			// SYSTEM delegates its operand to a shell. Preserve legacy
			// fallback rather than claiming a complete static projection.
			out.markPartial(IssueUnsupportedConstruct)
		default:
			out.markPartial(IssueUnknownOperandGrammar)
		}
	}
	if addresses != 2 {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func classifyNetcat(out *parseOutput, command *CommandFact) {
	preview, listen, udp := netcatControlMode(command.Argv)
	if preview {
		command.Effect = EffectPreview
		return
	}
	networkStart := len(out.network)
	endpointGrammarValid := true
	action := NetworkConnect
	scheme := "tcp"
	if udp {
		scheme = "udp"
	}
	if listen {
		action = NetworkListen
		addOperation(command, OperationListen)
	} else {
		addOperation(command, OperationConnect)
	}

	var (
		host string
		port int64
	)
	options := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			switch {
			case arg == "--listen":
				continue
			case arg == "--exec", arg == "--sh-exec":
				if i+1 < len(command.Argv) {
					i++
					appendPath(out, command.ID, PathAccessExecute, command.Argv[i])
				} else {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				if arg == "--sh-exec" {
					out.markPartial(IssueUnsupportedConstruct)
				}
				continue
			case strings.HasPrefix(arg, "--exec="):
				appendPath(out, command.ID, PathAccessExecute, arg[len("--exec="):])
				continue
			case strings.HasPrefix(arg, "--sh-exec="):
				appendPath(out, command.ID, PathAccessExecute, arg[len("--sh-exec="):])
				out.markPartial(IssueUnsupportedConstruct)
				continue
			case arg == "--source-port":
				if i+1 < len(command.Argv) {
					i++
					parsed, ok := parseNetworkPort(command.Argv[i])
					if !ok {
						out.markPartial(IssueUnknownOperandGrammar)
						endpointGrammarValid = false
					} else if listen {
						port = parsed
					}
				} else {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				continue
			case strings.HasPrefix(arg, "--source-port="):
				parsed, ok := parseNetworkPort(arg[len("--source-port="):])
				if !ok {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				} else if listen {
					port = parsed
				}
				continue
			case arg == "--source":
				if i+1 < len(command.Argv) {
					i++
					if listen && validNetworkHost(command.Argv[i]) {
						host = command.Argv[i]
					} else if !validNetworkHost(command.Argv[i]) {
						out.markPartial(IssueUnknownOperandGrammar)
						endpointGrammarValid = false
					}
				} else {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				continue
			case strings.HasPrefix(arg, "--source="):
				value := arg[len("--source="):]
				if !validNetworkHost(value) {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				} else if listen {
					host = value
				}
				continue
			case arg == "--wait":
				if i+1 >= len(command.Argv) {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
					continue
				}
				i++
				if !validPositiveNetcatDuration(command.Argv[i]) {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				continue
			case strings.HasPrefix(arg, "--wait="):
				if !validPositiveNetcatDuration(arg[len("--wait="):]) {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				continue
			case netcatLongOptionConsumesValue(arg):
				if i+1 < len(command.Argv) {
					i++
				} else {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
				}
				continue
			case netcatLongFlag(arg):
				continue
			default:
				out.markPartial(IssueUnknownOperandGrammar)
				endpointGrammarValid = false
				continue
			}
		}
		if options && strings.HasPrefix(arg, "-") && len(arg) > 1 {
			parsed := parseNetcatShortOption(arg)
			if !parsed.valid {
				out.markPartial(IssueUnknownOperandGrammar)
				endpointGrammarValid = false
				continue
			}
			if parsed.valueFlag == 0 {
				continue
			}
			value := parsed.value
			if parsed.consumesNext {
				if i+1 >= len(command.Argv) {
					out.markPartial(IssueUnknownOperandGrammar)
					endpointGrammarValid = false
					continue
				}
				i++
				value = command.Argv[i]
			}
			if !validNetcatShortOptionValue(parsed.valueFlag, value) {
				out.markPartial(IssueUnknownOperandGrammar)
				endpointGrammarValid = false
				continue
			}
			switch parsed.valueFlag {
			case 'e', 'c':
				appendPath(out, command.ID, PathAccessExecute, value)
				if parsed.valueFlag == 'c' {
					out.markPartial(IssueUnsupportedConstruct)
				}
			case 'p':
				if listen {
					port, _ = parseNetworkPort(value)
				}
			case 's':
				if listen {
					host = value
				}
			}
			continue
		}

		if fact, ok := networkURLFact(command.ID, arg, action); ok {
			out.appendNetwork(fact)
			continue
		}
		if parsed, ok := parseNetworkPort(arg); ok {
			if port == 0 {
				port = parsed
			}
			continue
		}
		if host == "" && validNetworkHost(arg) {
			host = strings.ToLower(arg)
			continue
		}
		out.markPartial(IssueUnknownOperandGrammar)
		endpointGrammarValid = false
	}

	if !endpointGrammarValid {
		out.network = out.network[:networkStart]
		return
	}
	if action == NetworkListen {
		if host != "" || port != 0 {
			out.appendNetwork(NetworkFact{
				CommandID: command.ID,
				Action:    action,
				Scheme:    scheme,
				Host:      strings.ToLower(host),
				Port:      port,
			})
		} else {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if host != "" {
		out.appendNetwork(NetworkFact{
			CommandID: command.ID,
			Action:    action,
			Scheme:    scheme,
			Host:      strings.ToLower(host),
			Port:      port,
		})
		if port == 0 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	} else {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func netcatControlMode(argv []string) (preview, listen, udp bool) {
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		if arg == "--help" || arg == "--version" ||
			arg == "-h" || arg == "-V" {
			return true, listen, udp
		}
		if arg == "--listen" {
			listen = true
			continue
		}
		if arg == "--udp" {
			udp = true
			continue
		}
		if strings.HasPrefix(arg, "--exec=") ||
			strings.HasPrefix(arg, "--sh-exec=") ||
			strings.HasPrefix(arg, "--source-port=") ||
			strings.HasPrefix(arg, "--source=") ||
			strings.HasPrefix(arg, "--wait=") {
			continue
		}
		if arg == "--exec" || arg == "--sh-exec" ||
			arg == "--source-port" || arg == "--source" ||
			arg == "--wait" ||
			netcatLongOptionConsumesValue(arg) {
			if i+1 < len(argv) {
				i++
			}
			continue
		}
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' {
			parsed := parseNetcatShortOption(arg)
			if !parsed.valid {
				continue
			}
			if parsed.listen {
				listen = true
			}
			if parsed.udp {
				udp = true
			}
			if parsed.consumesNext && i+1 < len(argv) {
				i++
			}
		}
	}
	return false, listen, udp
}

func netcatLongOptionConsumesValue(option string) bool {
	switch option {
	case "--allow", "--deny", "--idle-timeout", "--max-conns", "--output",
		"--proxy", "--proxy-auth", "--proxy-type", "--ssl-ciphers",
		"--ssl-servername", "--ssl-trustfile", "--timeout":
		return true
	default:
		return false
	}
}

func netcatLongFlag(option string) bool {
	switch option {
	case "--broker", "--chat", "--keep-open", "--listen", "--no-shutdown",
		"--recv-only", "--send-only", "--ssl", "--udp", "--verbose",
		"--zero":
		return true
	default:
		return false
	}
}

type netcatShortOption struct {
	valid        bool
	listen       bool
	udp          bool
	consumesNext bool
	valueFlag    byte
	value        string
}

func parseNetcatShortOption(option string) netcatShortOption {
	if len(option) < 2 || option[0] != '-' || option[1] == '-' {
		return netcatShortOption{}
	}
	parsed := netcatShortOption{valid: true}
	flags := option[1:]
	for i := 0; i < len(flags); i++ {
		flag := flags[i]
		if strings.ContainsRune("46bCdklnrtUuvz", rune(flag)) {
			if flag == 'l' {
				parsed.listen = true
			}
			if flag == 'u' {
				parsed.udp = true
			}
			continue
		}
		if !strings.ContainsRune("ceiopqswxX", rune(flag)) {
			return netcatShortOption{}
		}
		parsed.valueFlag = flag
		if i+1 == len(flags) {
			parsed.consumesNext = true
			return parsed
		}
		parsed.value = flags[i+1:]
		if !validNetcatShortOptionValue(flag, parsed.value) {
			return netcatShortOption{}
		}
		return parsed
	}
	return parsed
}

func validNetcatShortOptionValue(flag byte, value string) bool {
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	switch flag {
	case 'i', 'q', 'w':
		return validPositiveNetcatDuration(value)
	case 'p':
		_, ok := parseNetworkPort(value)
		return ok
	case 's':
		return validNetworkHost(value)
	case 'X':
		switch strings.ToLower(value) {
		case "4", "5", "connect":
			return true
		default:
			return false
		}
	case 'c', 'e', 'o', 'x':
		return true
	default:
		return false
	}
}

func validPositiveNetcatDuration(value string) bool {
	if strings.HasPrefix(value, "-") {
		return false
	}
	lower := strings.ToLower(value)
	for _, suffix := range []string{"ms", "s", "m", "h"} {
		if strings.HasSuffix(lower, suffix) {
			lower = strings.TrimSuffix(lower, suffix)
			break
		}
	}
	number, err := strconv.ParseFloat(lower, 64)
	return err == nil && number > 0 &&
		!math.IsInf(number, 0) && !math.IsNaN(number)
}

func parseNetworkPort(value string) (int64, bool) {
	port, err := strconv.ParseInt(value, 10, 64)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

func classifyNetworkScanner(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if scannerPreviewInvocation(command, program) {
		return
	}
	state := classifyNetworkScannerArguments(out, command, program)
	if state.offline {
		if !state.hasOutput {
			command.Effect = EffectPreview
		}
	} else if state.listOnly {
		addOperation(command, OperationList)
		if !state.hasOutput {
			command.Effect = EffectPreview
		}
	} else {
		addOperation(command, OperationNetworkScan)
	}
	if state.unknown || !state.hasSource {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if state.unsupported {
		out.markPartial(IssueUnsupportedConstruct)
	}
}

type networkScannerState struct {
	hasSource           bool
	hasOutput           bool
	hasPortSelection    bool
	portOwnedExternally bool
	fpingGenerate       bool
	listOnly            bool
	offline             bool
	unknown             bool
	unsupported         bool
	targets             []networkScannerTarget
}

type networkScannerTarget struct {
	value string
	kind  NetworkTargetKind
}

func classifyNetworkScannerArguments(
	out *parseOutput,
	command *CommandFact,
	program string,
) networkScannerState {
	state := networkScannerState{}
	options := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && arg != "-" && strings.HasPrefix(arg, "-") {
			key, value, consumes, joined, known := scannerOptionParts(
				program,
				arg,
			)
			if !known || joined && !consumes {
				state.unknown = true
				continue
			}
			if consumes && !joined {
				if i+1 >= len(command.Argv) {
					state.unknown = true
					continue
				}
				i++
				value = command.Argv[i]
			}
			if consumes &&
				!scannerStaticOptionValue(value) &&
				!(value == "-" &&
					scannerOptionAllowsDashValue(program, key)) {
				state.unknown = true
				continue
			}
			if joined && scannerOptionRequiresSeparateValue(program, key) {
				state.unknown = true
				continue
			}
			classifyNetworkScannerOption(
				out,
				command,
				program,
				key,
				value,
				&state,
			)
			continue
		}
		target, ok := normalizeNetworkScannerTarget(program, arg)
		if !ok {
			state.unknown = true
			continue
		}
		state.targets = append(state.targets, target)
		state.hasSource = true
	}
	if program == "masscan" &&
		!state.hasPortSelection &&
		!state.portOwnedExternally {
		state.unknown = true
	}
	if program == "fping" && !state.fpingGenerate {
		for _, target := range state.targets {
			if target.kind != NetworkTargetSingleHost {
				state.unknown = true
				break
			}
		}
	}
	if !state.offline {
		for _, target := range state.targets {
			out.appendNetwork(NetworkFact{
				CommandID: command.ID,
				Action:    NetworkScan,
				Host:      target.value,
			})
		}
	}
	return state
}

func scannerOptionParts(
	program string,
	arg string,
) (key, value string, consumesValue, joinedValue, known bool) {
	consumesValue, joinedValue, known = scannerOptionGrammar(program, arg)
	if !known {
		return "", "", false, false, false
	}
	if strings.HasPrefix(arg, "--") {
		rawKey, rawValue, joined := strings.Cut(arg, "=")
		return strings.ToLower(rawKey), rawValue, consumesValue, joined, true
	}
	if consumesValue {
		for _, prefix := range scannerShortValueOptions(program) {
			if arg == prefix {
				return prefix, "", true, false, true
			}
			if strings.HasPrefix(arg, prefix) && len(arg) > len(prefix) {
				return prefix, arg[len(prefix):], true, true, true
			}
		}
	}
	return arg, "", false, false, true
}

func scannerStaticOptionValue(value string) bool {
	return value != "" && value != "-" &&
		!strings.HasPrefix(value, "-") &&
		!strings.ContainsAny(value, "$`%!{}*?[]")
}

func scannerOptionAllowsDashValue(program string, key string) bool {
	if program != "nmap" {
		return false
	}
	switch key {
	case "-oG", "-oN", "-oS", "-oX":
		return true
	default:
		return false
	}
}

func scannerOptionRequiresSeparateValue(program string, key string) bool {
	switch program {
	case "nmap":
		switch key {
		case "-oA", "-oG", "-oN", "-oS", "-oX":
			return true
		}
	case "masscan":
		switch key {
		case "-oB", "-oG", "-oJ", "-oL", "-oX":
			return true
		}
	}
	return false
}

func classifyNetworkScannerOption(
	out *parseOutput,
	command *CommandFact,
	program string,
	key string,
	value string,
	state *networkScannerState,
) {
	switch program {
	case "nmap":
		classifyNmapOption(out, command, key, value, state)
	case "masscan":
		classifyMasscanOption(out, command, key, value, state)
	case "fping":
		classifyFPingOption(out, command, key, value, state)
	}
}

func classifyNmapOption(
	out *parseOutput,
	command *CommandFact,
	key string,
	value string,
	state *networkScannerState,
) {
	switch key {
	case "-sL":
		state.listOnly = true
	case "--iflist":
		state.listOnly = true
		state.hasSource = true
	case "--script-help":
		state.listOnly = true
		state.hasSource = true
		if scannerExactScriptPath(value) {
			appendNetworkScannerPath(
				out,
				command,
				PathAccessRead,
				value,
				state,
			)
			state.unsupported = true
		}
	case "-iR":
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			state.unknown = true
		} else {
			state.hasSource = true
		}
	case "-iL":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.hasSource = true
		state.unsupported = true
	case "-oA":
		if appendNmapAllOutputPaths(out, command, value, state) {
			state.hasOutput = true
		}
	case "-oG", "-oN", "-oS", "-oX":
		if value == "-" {
			return
		}
		if appendNetworkScannerPath(
			out,
			command,
			PathAccessWrite,
			value,
			state,
		) {
			state.hasOutput = true
		}
	case "--datadir", "--excludefile", "--script-args-file",
		"--stylesheet":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.unsupported = true
	case "--resume":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.hasSource = true
		state.unsupported = true
	case "--script":
		if scannerExactScriptPath(value) {
			appendNetworkScannerPath(
				out,
				command,
				PathAccessRead,
				value,
				state,
			)
		}
		state.unsupported = true
	case "-A", "-sC", "-sI", "--append-output", "--proxies":
		state.unsupported = true
	}
}

func appendNmapAllOutputPaths(
	out *parseOutput,
	command *CommandFact,
	base string,
	state *networkScannerState,
) bool {
	if !networkScannerStaticPath(base) {
		state.unknown = true
		return false
	}
	for _, suffix := range []string{".nmap", ".xml", ".gnmap"} {
		if !appendNetworkScannerPath(
			out,
			command,
			PathAccessWrite,
			base+suffix,
			state,
		) {
			return false
		}
	}
	return true
}

func classifyMasscanOption(
	out *parseOutput,
	command *CommandFact,
	key string,
	value string,
	state *networkScannerState,
) {
	switch key {
	case "-oB", "-oG", "-oJ", "-oL", "-oX", "--output-filename":
		if appendNetworkScannerPath(
			out,
			command,
			PathAccessWrite,
			value,
			state,
		) {
			state.hasOutput = true
		}
	case "--include-file", "--includefile":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.hasSource = true
		state.unsupported = true
	case "-c", "--conf", "--resume", "--readscan":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.hasSource = true
		state.portOwnedExternally = true
		state.unsupported = true
	case "--excludefile", "--pcap-payloads":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.unsupported = true
	case "--append-output":
		state.unsupported = true
	case "-p", "--ports":
		if validMasscanPortSelection(value) {
			state.hasPortSelection = true
		} else {
			state.unknown = true
		}
	case "--offline":
		state.offline = true
	}
}

func validMasscanPortSelection(value string) bool {
	if value == "" {
		return false
	}
	for _, item := range strings.Split(value, ",") {
		first, last, ranged := strings.Cut(item, "-")
		firstPort, err := strconv.ParseUint(first, 10, 16)
		if err != nil {
			return false
		}
		if !ranged {
			continue
		}
		lastPort, err := strconv.ParseUint(last, 10, 16)
		if err != nil || lastPort < firstPort {
			return false
		}
	}
	return true
}

func classifyFPingOption(
	out *parseOutput,
	command *CommandFact,
	key string,
	value string,
	state *networkScannerState,
) {
	switch key {
	case "-f", "--file":
		appendNetworkScannerPath(
			out,
			command,
			PathAccessRead,
			value,
			state,
		)
		state.hasSource = true
		state.unsupported = true
	case "-B", "--backoff":
		factor, err := strconv.ParseFloat(value, 64)
		if err != nil || factor <= 0 ||
			math.IsInf(factor, 0) ||
			math.IsNaN(factor) {
			state.unknown = true
		}
	case "-g", "--generate":
		state.fpingGenerate = true
	}
}

func appendNetworkScannerPath(
	out *parseOutput,
	command *CommandFact,
	access PathAccess,
	value string,
	state *networkScannerState,
) bool {
	if !networkScannerStaticPath(value) {
		state.unknown = true
		return false
	}
	appendCommandPath(out, command, access, value)
	switch access {
	case PathAccessRead:
		addOperation(command, OperationRead)
	case PathAccessWrite:
		addOperation(command, OperationWrite)
	}
	return true
}

func networkScannerStaticPath(value string) bool {
	return scannerStaticOptionValue(value) &&
		!strings.Contains(value, "://") &&
		!strings.ContainsAny(value, "*?[]")
}

func scannerExactScriptPath(value string) bool {
	if !networkScannerStaticPath(value) {
		return false
	}
	return strings.ContainsAny(value, `/\`) ||
		strings.HasSuffix(strings.ToLower(value), ".nse")
}

func normalizeNetworkScannerTarget(
	program string,
	value string,
) (networkScannerTarget, bool) {
	if value == "" || value == "-" ||
		strings.Contains(value, "://") ||
		strings.ContainsAny(value, `@\`) ||
		strings.Contains(value, ",") ||
		strings.HasPrefix(value, "[") ||
		strings.HasSuffix(value, "]") {
		return networkScannerTarget{}, false
	}
	normalized, _, kind, _ := deriveNetworkTarget(value)
	switch kind {
	case NetworkTargetSingleHost,
		NetworkTargetSingleAddressCIDR,
		NetworkTargetMultiAddressCIDR,
		NetworkTargetRange,
		NetworkTargetGenerated:
	default:
		return networkScannerTarget{}, false
	}
	if normalized == "" {
		return networkScannerTarget{}, false
	}
	if program == "masscan" {
		if kind == NetworkTargetGenerated {
			return networkScannerTarget{}, false
		}
		if kind == NetworkTargetSingleHost {
			if _, err := netip.ParseAddr(normalized); err != nil {
				return networkScannerTarget{}, false
			}
		}
	}
	if program == "fping" && kind == NetworkTargetGenerated {
		return networkScannerTarget{}, false
	}
	return networkScannerTarget{value: normalized, kind: kind}, true
}

func classifyNaabu(
	out *parseOutput,
	command *CommandFact,
) {
	valid := true
	haveInput := false
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		key, value, joined := strings.Cut(arg, "=")
		if !joined {
			switch key {
			case "-h", "--help", "-V", "-version", "--version":
				command.Effect = EffectPreview
				return
			}
		}
		key = strings.ToLower(key)
		switch key {
		case "-host", "--host":
			optionValid := joined && value != ""
			if !joined {
				value, optionValid = naabuRequiredValue(command.Argv, &i)
			}
			if !optionValid || !appendNaabuTarget(out, command, value) {
				valid = false
				continue
			}
			haveInput = true
		case "-l", "-list", "--list":
			optionValid := joined && value != ""
			if !joined {
				value, optionValid = naabuRequiredValue(command.Argv, &i)
			}
			if !optionValid || !naabuStaticPathOperand(value) {
				valid = false
				continue
			}
			appendCommandPath(out, command, PathAccessRead, value)
			haveInput = true
		case "-o", "-output", "--output":
			optionValid := joined && value != ""
			if !joined {
				value, optionValid = naabuRequiredValue(command.Argv, &i)
			}
			if !optionValid || !naabuStaticPathOperand(value) {
				valid = false
				continue
			}
			appendCommandPath(out, command, PathAccessWrite, value)
		case "-pf", "-ports-file", "--ports-file",
			"-ef", "-exclude-file", "--exclude-file":
			optionValid := joined && value != ""
			if !joined {
				value, optionValid = naabuRequiredValue(command.Argv, &i)
			}
			if !optionValid || !naabuStaticPathOperand(value) {
				valid = false
				continue
			}
			appendCommandPath(out, command, PathAccessRead, value)
		case "-p", "-port", "--port",
			"-tp", "-top-ports", "--top-ports",
			"-rate", "--rate", "-timeout", "--timeout",
			"-retries", "--retries", "-c",
			"-eh", "-exclude-hosts", "--exclude-hosts":
			optionValid := joined && value != ""
			if !joined {
				value, optionValid = naabuRequiredValue(command.Argv, &i)
			}
			if !optionValid || !naabuStaticValue(value) {
				valid = false
			}
		case "-silent", "--silent", "-j", "-json", "--json",
			"-csv", "--csv", "-ping", "--ping", "-verify", "--verify",
			"-sn", "--host-discovery", "-pn", "--skip-host-discovery",
			"-v", "-verbose", "--verbose", "-nc", "-no-color", "--no-color":
			if joined {
				valid = false
			}
		default:
			valid = false
		}
	}
	if haveInput {
		addOperation(command, OperationNetworkScan)
	}
	if !valid || !haveInput {
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func naabuRequiredValue(
	argv []string,
	index *int,
) (string, bool) {
	if *index+1 >= len(argv) {
		return "", false
	}
	*index++
	value := argv[*index]
	if value == "" || value != "-" && strings.HasPrefix(value, "-") {
		return "", false
	}
	return value, true
}

func naabuStaticValue(value string) bool {
	return value != "" && (value == "-" || !strings.HasPrefix(value, "-")) &&
		!strings.ContainsAny(value, "$`%!{}")
}

func naabuStaticPathOperand(value string) bool {
	return value != "-" && !strings.HasPrefix(value, "-") &&
		naabuStaticValue(value) &&
		!strings.ContainsAny(value, "*?[]")
}

func appendNaabuTarget(
	out *parseOutput,
	command *CommandFact,
	value string,
) bool {
	normalized, _, kind, _ := deriveNetworkTarget(value)
	if normalized == "" || kind == NetworkTargetUnknown {
		return false
	}
	return out.appendNetwork(NetworkFact{
		CommandID: command.ID,
		Action:    NetworkScan,
		Host:      normalized,
	})
}

func scannerPreviewInvocation(
	command *CommandFact,
	program string,
) bool {
	options := true
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}
		lower := strings.ToLower(arg)
		if lower == "--help" || lower == "--version" ||
			program == "nmap" && (arg == "-h" || arg == "-V") ||
			program == "masscan" && (arg == "-h" || lower == "--echo") ||
			program == "fping" && (arg == "-h" || arg == "-v") {
			command.Effect = EffectPreview
			return true
		}
		consumes, joined, known := scannerOptionGrammar(program, arg)
		if !known {
			continue
		}
		if consumes && !joined {
			if i+1 < len(command.Argv) {
				i++
			}
		}
	}
	return false
}

func scannerOptionGrammar(
	program string,
	option string,
) (consumesValue, joinedValue, known bool) {
	if strings.HasPrefix(option, "--") {
		key, _, joined := strings.Cut(option, "=")
		if key != strings.ToLower(key) {
			return false, joined, false
		}
		if networkOptionConsumesNonTarget(program, key) ||
			scannerLongOptionConsumesValue(program, key) {
			return true, joined, true
		}
		return false, joined, scannerLongFlag(program, key)
	}
	if len(option) < 2 || option[0] != '-' {
		return false, false, false
	}
	for _, prefix := range scannerShortValueOptions(program) {
		if option == prefix {
			return true, false, true
		}
		if strings.HasPrefix(option, prefix) && len(option) > len(prefix) {
			return true, true, true
		}
	}
	return false, false, scannerShortFlag(program, option)
}

func scannerLongOptionConsumesValue(program, option string) bool {
	switch program {
	case "nmap":
		switch option {
		case "--data-length",
			"--host-timeout", "--initial-rtt-timeout", "--max-hostgroup",
			"--max-os-tries", "--max-parallelism", "--max-rate",
			"--max-retries", "--max-rtt-timeout", "--max-scan-delay",
			"--min-hostgroup", "--min-parallelism", "--min-rate",
			"--min-rtt-timeout", "--mtu", "--proxies", "--scan-delay",
			"--script-args", "--script-help", "--spoof-mac", "--top-ports", "--ttl",
			"--version-intensity":
			return true
		}
	case "masscan":
		switch option {
		case "--adapter", "--adapter-mac", "--exclude-ports",
			"--hello", "--http-method", "--http-url", "--max-rate",
			"--min-rate", "--output-format", "--ports", "--rate", "--router-ip",
			"--router-mac", "--seed", "--shards", "--source-mac",
			"--source-port", "--wait":
			return true
		}
	case "fping":
		switch option {
		case "--backoff", "--count", "--iface", "--interval", "--period",
			"--reachable", "--retry", "--size", "--squiet", "--src",
			"--timeout", "--tos", "--ttl", "--vcount":
			return true
		}
	}
	return false
}

func scannerLongFlag(program, option string) bool {
	switch program {
	case "nmap":
		switch option {
		case "--allports", "--append-output", "--badsum",
			"--defeat-icmp-ratelimit", "--disable-arp-ping", "--open",
			"--iflist", "--osscan-guess", "--osscan-limit", "--packet-trace",
			"--privileged", "--reason", "--release-memory",
			"--send-eth", "--send-ip", "--system-dns", "--traceroute",
			"--unprivileged", "--version-all", "--version-light":
			return true
		}
	case "masscan":
		switch option {
		case "--append-output", "--banners", "--echo", "--offline", "--open",
			"--packet-trace", "--pfring", "--send-eth",
			"--send-ip", "--version":
			return true
		}
	case "fping":
		switch option {
		case "--addr", "--alive", "--all", "--dontfrag", "--elapsed",
			"--generate", "--loop", "--name", "--netdata", "--numeric",
			"--outage", "--quiet", "--random", "--rdns", "--stats",
			"--timestamp", "--unreach":
			return true
		}
	}
	return false
}

func scannerShortValueOptions(program string) []string {
	switch program {
	case "nmap":
		return []string{
			"-iL", "-iR", "-oA", "-oG", "-oN", "-oS", "-oX", "-sI",
			"-D", "-S", "-e", "-g", "-p", "-T",
		}
	case "masscan":
		return []string{
			"-c", "-e", "-oB", "-oG", "-oJ", "-oL", "-oX", "-p",
		}
	case "fping":
		return []string{
			"-b", "-B", "-c", "-C", "-f", "-H", "-i", "-I", "-O",
			"-p", "-Q", "-r", "-S", "-t", "-x",
		}
	default:
		return nil
	}
}

func scannerShortFlag(program, option string) bool {
	switch program {
	case "nmap":
		switch option {
		case "-6", "-A", "-F", "-n", "-O", "-Pn", "-R", "-sA", "-sC",
			"-sF", "-sL", "-sM", "-sn", "-sN", "-sO", "-sS", "-sT",
			"-sU", "-sV", "-sW", "-sX", "-v", "-vv":
			return true
		}
	case "masscan":
		switch option {
		case "-6", "-v":
			return true
		}
	case "fping":
		switch option {
		case "-4", "-6", "-a", "-A", "-d", "-D", "-e", "-g", "-l",
			"-m", "-M", "-n", "-N", "-o", "-q", "-R", "-s", "-u":
			return true
		}
	}
	return false
}

func addNetworkFromArguments(
	out *parseOutput,
	command *CommandFact,
	action NetworkAction,
) bool {
	hasSource := false
	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if networkOptionConsumesNonTarget(command.Program, arg) {
			if i+1 >= len(command.Argv) || command.Argv[i+1] == "" {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "-") {
			consumes, joined, known := scannerOptionGrammar(
				command.Program,
				arg,
			)
			if known && consumes && !joined {
				if i+1 >= len(command.Argv) || command.Argv[i+1] == "" {
					out.markPartial(IssueUnknownOperandGrammar)
					continue
				}
				i++
			}
			if known && consumes && joined && strings.HasSuffix(arg, "=") {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			continue
		}
		if fact, ok := networkURLFact(command.ID, arg, action); ok {
			hasSource = true
			out.appendNetwork(fact)
			continue
		}
		if _, _, err := net.ParseCIDR(arg); err == nil {
			hasSource = true
			out.appendNetwork(NetworkFact{
				CommandID: command.ID,
				Action:    action,
				Host:      strings.ToLower(arg),
			})
			continue
		}
		host, port := splitHostPortLoose(arg)
		if validNetworkHost(host) {
			hasSource = true
			out.appendNetwork(NetworkFact{CommandID: command.ID, Action: action, Host: strings.ToLower(host), Port: port})
		} else if action == NetworkScan {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	}
	return hasSource
}

func networkOptionConsumesNonTarget(program, option string) bool {
	switch program {
	case "nmap":
		switch option {
		case "-D", "-S", "-e", "-g", "-oA", "-oG", "-oN", "-oS", "-oX",
			"--datadir", "--dns-servers", "--exclude", "--excludefile",
			"--resume", "--script", "--script-args-file", "--source-port",
			"--stylesheet":
			return true
		}
	case "masscan":
		switch option {
		case "-c", "-oB", "-oG", "-oJ", "-oL", "-oX", "--conf",
			"--adapter-ip", "--exclude", "--excludefile", "--include-file",
			"--includefile", "--output-filename", "--pcap-payloads",
			"--readscan", "--resume", "--source-ip":
			return true
		}
	case "fping":
		switch option {
		case "-I", "-S", "--file":
			return true
		}
	case "chisel", "ligolo-agent", "ligolo-ng-agent", "cloudflared", "ngrok":
		switch option {
		case "-c", "--config", "--config-file", "--logfile", "--log-file",
			"--output":
			return true
		}
	}
	return false
}

func socatAddressFact(
	commandID int64,
	raw string,
) (NetworkFact, bool) {
	address := strings.SplitN(raw, ",", 2)[0]
	kind, endpoint, ok := strings.Cut(address, ":")
	if !ok {
		return NetworkFact{}, false
	}
	kind = strings.ToLower(kind)
	scheme := ""
	switch kind {
	case "tcp", "tcp-connect", "tcp4", "tcp4-connect", "tcp6", "tcp6-connect",
		"tcp-listen", "tcp4-listen", "tcp6-listen",
		"tcp-l", "tcp4-l", "tcp6-l":
		scheme = "tcp"
	case "udp", "udp-connect", "udp4", "udp4-connect", "udp6", "udp6-connect",
		"udp-listen", "udp4-listen", "udp6-listen",
		"udp-l", "udp4-l", "udp6-l":
		scheme = "udp"
	case "openssl", "openssl-connect", "openssl-listen", "openssl-l":
		scheme = "tls"
	default:
		return NetworkFact{}, false
	}
	if strings.HasSuffix(kind, "-listen") || strings.HasSuffix(kind, "-l") {
		port, ok := parseNetworkPort(endpoint)
		if !ok {
			return NetworkFact{}, false
		}
		return NetworkFact{
			CommandID: commandID,
			Action:    NetworkListen,
			Scheme:    scheme,
			Port:      port,
		}, true
	}
	host, port := splitHostPortLoose(endpoint)
	if !validNetworkHost(host) {
		return NetworkFact{}, false
	}
	return NetworkFact{
		CommandID: commandID,
		Action:    NetworkConnect,
		Scheme:    scheme,
		Host:      strings.ToLower(host),
		Port:      port,
	}, true
}

func classifyDD(out *parseOutput, command *CommandFact) {
	for _, arg := range command.Argv[1:] {
		if arg == "--help" || arg == "--version" {
			command.Effect = EffectPreview
			return
		}
	}

	recognized := exactOptionSet(
		"if", "of",
		"ibs", "obs", "bs", "cbs",
		"skip", "seek", "iseek", "oseek", "count",
		"status", "conv", "iflag", "oflag",
	)
	values := make(map[string]string, len(command.Argv)-1)
	complete := true
	for _, arg := range command.Argv[1:] {
		key, value, ok := strings.Cut(arg, "=")
		if !ok || key == "" || value == "" {
			complete = false
			continue
		}
		if _, ok := recognized[key]; !ok {
			complete = false
			continue
		}
		if previous, duplicate := values[key]; duplicate &&
			previous != value {
			complete = false
		}
		values[key] = value
	}
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}

	if input := values["if"]; input != "" {
		addOperation(command, OperationRead)
		appendCommandPath(out, command, PathAccessRead, input)
	}
	if output := values["of"]; output != "" {
		addOperation(command, OperationWrite)
		appendCommandPath(out, command, PathAccessWrite, output)
		if isRawBlockDeviceTarget(output) {
			addOperation(command, OperationDiskWrite)
		}
	}
}

func classifyPOSIXFilesystemFormat(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	flags := exactOptionSet()
	previewFlag := ""
	switch program {
	case "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mke2fs":
		flags = exactOptionSet("-F", "-n")
		previewFlag = "-n"
	case "mkfs.xfs":
		flags = exactOptionSet("-f", "-N")
		previewFlag = "-N"
	case "mkfs.btrfs", "mkfs.f2fs", "mkswap":
		flags = exactOptionSet("-f")
	case "mkfs.vfat", "mkdosfs":
		flags = exactOptionSet("-I")
	case "mkfs.ntfs", "mkntfs":
		flags = exactOptionSet("-F")
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		nil,
		flags,
		exactOptionSet("--help", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.positionals) != 1 || parsed.positionals[0] == "-" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if previewFlag != "" {
		if _, preview := parsed.seen[previewFlag]; preview {
			command.Effect = EffectPreview
		}
	}
	addOperation(command, OperationWrite)
	if isRawBlockDeviceTarget(parsed.positionals[0]) {
		addOperation(command, OperationDiskWrite)
	}
	appendCommandPath(out, command, PathAccessWrite, parsed.positionals[0])
}

func classifyWipeFS(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		exactOptionSet("-O", "--output"),
		exactOptionSet(
			"-a", "--all", "-n", "--no-act", "-f", "--force",
			"-q", "--quiet", "-J", "--json", "-i", "--noheadings",
			"-p", "--parsable",
		),
		exactOptionSet("-h", "--help", "-V", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.positionals) != 1 || parsed.positionals[0] == "-" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if _, preview := parsed.seen["-n"]; preview {
		command.Effect = EffectPreview
	}
	if _, preview := parsed.seen["--no-act"]; preview {
		command.Effect = EffectPreview
	}
	_, shortAll := parsed.seen["-a"]
	_, longAll := parsed.seen["--all"]
	if shortAll || longAll {
		addOperation(command, OperationWrite)
		if isRawBlockDeviceTarget(parsed.positionals[0]) {
			addOperation(command, OperationDiskWrite)
		}
		appendCommandPath(out, command, PathAccessWrite, parsed.positionals[0])
		return
	}
	addOperation(command, OperationList)
	appendCommandPath(out, command, PathAccessMetadata, parsed.positionals[0])
}

func classifySGDisk(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv,
		nil,
		exactOptionSet(
			"-Z", "--zap-all", "-o", "--clear", "-P", "--pretend",
			"-p", "--print",
		),
		exactOptionSet("-h", "--help", "-V", "--version"),
	)
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.positionals) != 1 || parsed.positionals[0] == "-" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if _, preview := parsed.seen["-P"]; preview {
		command.Effect = EffectPreview
	}
	if _, preview := parsed.seen["--pretend"]; preview {
		command.Effect = EffectPreview
	}
	for _, option := range []string{"-Z", "--zap-all", "-o", "--clear"} {
		if _, seen := parsed.seen[option]; seen {
			addOperation(command, OperationWrite)
			if isRawBlockDeviceTarget(parsed.positionals[0]) {
				addOperation(command, OperationDiskWrite)
			}
			appendCommandPath(out, command, PathAccessWrite, parsed.positionals[0])
			return
		}
	}
	for _, option := range []string{"-p", "--print"} {
		if _, seen := parsed.seen[option]; seen {
			addOperation(command, OperationList)
			appendCommandPath(out, command, PathAccessMetadata, parsed.positionals[0])
			return
		}
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

func classifyDestructiveDeviceTool(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if len(command.Argv) == 2 &&
		(command.Argv[1] == "-h" || command.Argv[1] == "--help" ||
			command.Argv[1] == "--version") {
		command.Effect = EffectPreview
		return
	}
	target := ""
	destructive := false
	complete := true
	switch program {
	case "shred":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet("-n", "--iterations", "-s", "--size"),
			exactOptionSet("-f", "--force", "-v", "--verbose", "-z", "--zero"),
			exactOptionSet("--help", "--version"),
		)
		complete = parsed.complete && len(parsed.positionals) == 1
		if len(parsed.positionals) == 1 {
			target = parsed.positionals[0]
			destructive = true
		}
	case "blkdiscard":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet("-o", "--offset", "-l", "--length", "-p", "--step"),
			exactOptionSet("-f", "--force", "-s", "--secure", "-z", "--zeroout"),
			exactOptionSet("-h", "--help", "-V", "--version"),
		)
		complete = parsed.complete && len(parsed.positionals) == 1
		if len(parsed.positionals) == 1 {
			target = parsed.positionals[0]
			destructive = true
		}
	case "cryptsetup":
		complete = len(command.Argv) == 3
		if complete {
			switch strings.ToLower(command.Argv[1]) {
			case "luksformat", "lukserase", "reencrypt", "erase":
				target = command.Argv[2]
				destructive = true
			}
		}
	case "hdparm":
		if len(command.Argv) >= 3 {
			target = command.Argv[len(command.Argv)-1]
			for index := 1; index < len(command.Argv)-1; index++ {
				lower := strings.ToLower(command.Argv[index])
				switch {
				case lower == "--security-erase",
					lower == "--security-disable",
					lower == "--trim-sector-ranges",
					lower == "--write-sector",
					lower == "--make-bad-sector",
					lower == "--fallocate":
					destructive = index+1 < len(command.Argv)-1
					index++
				case lower == "--dco-restore":
					destructive = true
				default:
					complete = false
				}
			}
		} else {
			complete = false
		}
	case "nvme":
		complete = len(command.Argv) == 3
		if complete {
			switch strings.ToLower(command.Argv[1]) {
			case "format", "sanitize", "write-zeroes", "write",
				"delete-ns", "detach-ns":
				target = command.Argv[2]
				destructive = true
			}
		}
	case "parted":
		complete = len(command.Argv) >= 3
		if complete {
			target = command.Argv[1]
			switch strings.ToLower(command.Argv[2]) {
			case "mklabel", "mkpart", "mkpartfs", "resizepart", "rescue",
				"mkfs", "rm":
				destructive = true
			default:
				complete = false
			}
		}
	case "diskutil":
		complete = len(command.Argv) >= 3
		if complete {
			switch strings.ToLower(command.Argv[1]) {
			case "erasedisk", "zerodisk", "randomdisk", "secureerase":
				target = command.Argv[len(command.Argv)-1]
				if !isRawBlockDeviceTarget(target) &&
					isRawBlockDeviceTarget("/dev/"+target) {
					target = "/dev/" + target
				}
				destructive = true
			default:
				complete = false
			}
		}
	}
	if !complete || !destructive || !isRawBlockDeviceTarget(target) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationWrite)
	addOperation(command, OperationDiskWrite)
	appendCommandPath(out, command, PathAccessWrite, target)
}

func classifyWindowsFormat(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectCMD, DialectArgv) {
		return
	}
	if len(command.Argv) == 2 &&
		(command.Argv[1] == "/?" || command.Argv[1] == "--help") {
		command.Effect = EffectPreview
		return
	}
	if len(command.Argv) < 2 || !windowsDriveRoot(command.Argv[1]) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	for _, argument := range command.Argv[2:] {
		if !strings.HasPrefix(argument, "/") {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
	}
	addOperation(command, OperationWrite)
	addOperation(command, OperationDiskWrite)
	appendCommandPath(out, command, PathAccessWrite, command.Argv[1])
}

func classifyStructuredPowerShellFormatVolume(
	out *parseOutput,
	command *CommandFact,
) {
	if !requireCommandDialect(out, command, DialectPowerShell) {
		return
	}
	controls := newStructuredPowerShellControlState()
	selector := ""
	complete := true
	for index := 1; index < len(command.Argv); index++ {
		if controls.consume(command, command.Argv[index]) {
			continue
		}
		argument := strings.ToLower(command.Argv[index])
		switch argument {
		case "-driveletter", "-path", "-partition", "-inputobject":
			if index+1 >= len(command.Argv) || command.Argv[index+1] == "" {
				complete = false
				continue
			}
			index++
			if selector != "" {
				complete = false
			}
			selector = command.Argv[index]
		case "-filesystem", "-newfilesystemlabel", "-allocationsize":
			if index+1 >= len(command.Argv) {
				complete = false
				continue
			}
			index++
		case "-force":
		default:
			complete = false
		}
	}
	if controls.help {
		command.Effect = EffectPreview
		return
	}
	if !complete || !controls.valid || selector == "" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationWrite)
	addOperation(command, OperationDiskWrite)
	appendCommandPath(out, command, PathAccessWrite, selector)
}

func windowsDriveRoot(value string) bool {
	value = strings.TrimSpace(value)
	return len(value) == 2 &&
		((value[0] >= 'A' && value[0] <= 'Z') ||
			(value[0] >= 'a' && value[0] <= 'z')) &&
		value[1] == ':'
}

type nsenterInvocation struct {
	paths      []string
	childIndex int
	preview    bool
	complete   bool
}

func parseNSEnterInvocation(argv []string) nsenterInvocation {
	result := nsenterInvocation{childIndex: -1, complete: true}
	target := ""
	type namespaceSelection struct {
		name string
		path string
	}
	var selections []namespaceSelection
	longNamespaces := map[string]string{
		"--mount": "mnt", "--uts": "uts", "--ipc": "ipc",
		"--net": "net", "--pid": "pid", "--user": "user",
		"--cgroup": "cgroup", "--time": "time",
	}
	shortNamespaces := map[byte]string{
		'm': "mnt", 'u': "uts", 'i': "ipc", 'n': "net",
		'p': "pid", 'U': "user", 'C': "cgroup", 'T': "time",
	}
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			result.childIndex = i
			break
		}
		switch arg {
		case "-h", "--help", "-V", "--version":
			result.preview = true
			continue
		case "-F", "--no-fork":
			continue
		case "-t", "--target":
			if i+1 >= len(argv) || argv[i+1] == "" {
				result.complete = false
				continue
			}
			i++
			if target != "" {
				result.complete = false
				continue
			}
			target = argv[i]
			continue
		}
		if strings.HasPrefix(arg, "--target=") {
			value := strings.TrimPrefix(arg, "--target=")
			if value == "" || target != "" {
				result.complete = false
			} else {
				target = value
			}
			continue
		}
		if strings.HasPrefix(arg, "-t") && len(arg) > 2 {
			value := arg[2:]
			if target != "" {
				result.complete = false
			} else {
				target = value
			}
			continue
		}
		if strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			name, known := longNamespaces[key]
			if !known {
				result.complete = false
				continue
			}
			if joined && !staticAbsolutePOSIXPath(value) {
				result.complete = false
				continue
			}
			selections = append(selections, namespaceSelection{
				name: name,
				path: value,
			})
			continue
		}
		validBundle := len(arg) > 1
		for offset := 1; offset < len(arg); offset++ {
			name, known := shortNamespaces[arg[offset]]
			if !known {
				validBundle = false
				break
			}
			selections = append(selections, namespaceSelection{name: name})
		}
		if !validBundle {
			result.complete = false
		}
	}

	canonicalTarget := ""
	if target != "" {
		pid, err := strconv.ParseUint(target, 10, 31)
		if err != nil || pid == 0 {
			result.complete = false
		} else {
			canonicalTarget = strconv.FormatUint(pid, 10)
		}
	}
	for _, selection := range selections {
		if selection.path != "" {
			result.paths = append(result.paths, selection.path)
			continue
		}
		if canonicalTarget == "" {
			result.complete = false
			continue
		}
		result.paths = append(
			result.paths,
			"/proc/"+canonicalTarget+"/ns/"+selection.name,
		)
	}
	if len(selections) == 0 && !result.preview {
		result.complete = false
	}
	return result
}

func classifyNSEnter(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseNSEnterInvocation(command.Argv)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(parsed.paths) == 0 {
		return
	}
	addOperation(command, OperationNamespaceEnter)
	for _, target := range parsed.paths {
		appendCommandPath(out, command, PathAccessRead, target)
	}
}

type chrootInvocation struct {
	root       string
	childIndex int
	preview    bool
	complete   bool
}

func parseChrootInvocation(argv []string) chrootInvocation {
	result := chrootInvocation{childIndex: -1, complete: true}
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			switch {
			case arg == "--help", arg == "--version":
				result.preview = true
			case arg == "--skip-chdir":
			case strings.HasPrefix(arg, "--userspec="),
				strings.HasPrefix(arg, "--groups="):
				if strings.HasSuffix(arg, "=") {
					result.complete = false
				}
			default:
				result.complete = false
			}
			continue
		}
		result.root = arg
		if i+1 < len(argv) {
			result.childIndex = i + 1
		}
		break
	}
	if !result.preview && (result.root == "" || result.root == "-") {
		result.complete = false
	}
	return result
}

func classifyChroot(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := parseChrootInvocation(command.Argv)
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if parsed.root == "" {
		return
	}
	addOperation(command, OperationRootChange)
	appendCommandPath(out, command, PathAccessRead, parsed.root)
}

func classifyContainer(out *parseOutput, command *CommandFact) {
	subcommand, subcommandIndex, ok := containerTopLevelCommand(out, command)
	if !ok {
		return
	}
	if subcommand == "compose" {
		composeAction, actionIndex, found := containerComposeCommand(
			out,
			command,
			subcommandIndex+1,
		)
		if found {
			switch composeAction {
			case "up", "run", "create":
				preview, complete := containerHelpAfterAction(
					command.Argv,
					actionIndex+1,
					containerComposeActionValueOptions(composeAction),
					containerComposeActionFlagOptions(composeAction),
				)
				if preview {
					setContainerPreview(out, command)
					return
				}
				if !complete {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				addOperation(command, OperationContainerRun)
			case "config", "events", "images", "ls", "ps", "top", "version":
				preview, complete := containerReadOnlyControl(
					command.Program,
					composeAction,
					command.Argv,
					actionIndex+1,
				)
				if preview {
					setContainerPreview(out, command)
					return
				}
				if !complete {
					out.markPartial(IssueUnknownOperandGrammar)
				}
			default:
				out.markPartial(IssueUnknownOperandGrammar)
			}
		}
		return
	}
	if subcommand == "run" || subcommand == "create" {
		preview, complete := containerHelpAfterAction(
			command.Argv,
			subcommandIndex+1,
			containerRunValueOptions,
			containerRunFlagOptions,
		)
		if preview {
			setContainerPreview(out, command)
			return
		}
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		addOperation(command, OperationContainerRun)
		classifyContainerRunOptions(out, command, subcommandIndex+1)
		return
	}
	if subcommand == "exec" {
		preview, complete := containerHelpAfterAction(
			command.Argv,
			subcommandIndex+1,
			optionValues(
				"-d", "--detach-keys", "-e", "--env", "--env-file",
				"-u", "--user", "-w", "--workdir",
			),
			optionValues("--detach", "-i", "--interactive", "-t", "--tty"),
		)
		if preview {
			setContainerPreview(out, command)
			return
		}
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		addOperation(command, OperationWorkloadExec)
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	switch subcommand {
	case "help":
		setContainerPreview(out, command)
	case "info", "inspect", "images", "ps", "stats", "version":
		preview, complete := containerReadOnlyControl(
			command.Program,
			subcommand,
			command.Argv,
			subcommandIndex+1,
		)
		if preview {
			setContainerPreview(out, command)
			return
		}
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func containerTopLevelCommand(
	out *parseOutput,
	command *CommandFact,
) (string, int, bool) {
	var (
		selectedEndpoint containerEndpointSelection
		endpointSeen     bool
		endpointRejected bool
		remoteRequested  bool
	)
	applySelectedEndpoint := func() {
		if remoteRequested && !endpointSeen {
			// Podman's remote mode otherwise resolves a named/default
			// connection from external configuration.
			out.markPartial(IssueUnsupportedConstruct)
		}
		if endpointSeen && !endpointRejected {
			appendContainerEndpoint(out, command, selectedEndpoint)
		}
	}

	for i := 1; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "--" {
			if i+1 < len(command.Argv) {
				applySelectedEndpoint()
				return command.Argv[i+1], i + 1, true
			}
			out.markPartial(IssueUnknownOperandGrammar)
			return "", 0, false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			applySelectedEndpoint()
			return arg, i, true
		}
		if arg == "--help" || arg == "--version" || arg == "-v" {
			command.Effect = EffectPreview
			return "", 0, false
		}
		if endpoint, matched, complete := containerEndpointArgument(
			command.Argv,
			&i,
			command.Program,
		); matched {
			parsed, valid := parseContainerEndpoint(
				command.ID,
				command.Program,
				endpoint,
			)
			if !complete || !valid {
				out.markPartial(IssueUnknownOperandGrammar)
				return "", 0, false
			}
			if endpointSeen && command.Program == "docker" {
				// Docker rejects a repeated daemon host before executing its
				// subcommand, even when both values are identical.
				out.markPartial(IssueUnknownOperandGrammar)
				endpointRejected = true
			}
			// Podman and nerdctl use the final effective endpoint. Keeping
			// only that value avoids stale connection ownership.
			selectedEndpoint = parsed
			endpointSeen = true
			continue
		}
		if matched, complete := containerNamedEndpointArgument(
			command.Argv,
			&i,
			command.Program,
		); matched {
			if !complete {
				out.markPartial(IssueUnknownOperandGrammar)
				return "", 0, false
			}
			// Named contexts/connections resolve their endpoint from files
			// outside this bounded argv grammar.
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		key, value, joined := strings.Cut(arg, "=")
		if containerTopLevelValueOption(arg, key) {
			if joined {
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				continue
			}
			if i+1 >= len(command.Argv) || command.Argv[i+1] == "" {
				out.markPartial(IssueUnknownOperandGrammar)
				return "", 0, false
			}
			i++
			continue
		}
		if containerTopLevelFlag(command.Program, arg) {
			if command.Program == "podman" && arg == "--remote" {
				remoteRequested = true
			}
			continue
		}
		out.markPartial(IssueUnknownOperandGrammar)
		return "", 0, false
	}
	command.Effect = EffectPreview
	return "", 0, false
}

func containerTopLevelValueOption(raw, key string) bool {
	if raw == "-l" {
		return true
	}
	switch key {
	case "--api-cors-header", "--config",
		"--log-level", "--tlscacert", "--tlscert", "--tlskey":
		return true
	default:
		return false
	}
}

func containerTopLevelFlag(program, raw string) bool {
	if program == "podman" && raw == "--remote" {
		return true
	}
	return raw == "-D" || raw == "--debug" || raw == "--tls" ||
		raw == "--tlsverify"
}

func containerNamedEndpointArgument(
	argv []string,
	index *int,
	program string,
) (matched bool, complete bool) {
	arg := argv[*index]
	key, value, joined := strings.Cut(arg, "=")
	switch program {
	case "docker":
		matched = arg == "-c" || key == "--context"
	case "podman":
		matched = arg == "-c" || key == "--connection"
	}
	if !matched {
		return false, false
	}
	if joined {
		return true, value != ""
	}
	if *index+1 >= len(argv) || argv[*index+1] == "" {
		return true, false
	}
	*index++
	return true, true
}

func containerEndpointArgument(
	argv []string,
	index *int,
	program string,
) (string, bool, bool) {
	arg := argv[*index]
	lower := strings.ToLower(arg)
	key, joinedValue, joined := strings.Cut(arg, "=")
	matched := false
	short := ""
	switch program {
	case "docker":
		matched = key == "--host"
		short = "-H"
	case "podman":
		matched = key == "--url"
	case "nerdctl":
		matched = key == "--address"
		short = "-a"
	}
	if matched {
		if joined {
			return joinedValue, true, joinedValue != ""
		}
		if *index+1 >= len(argv) || argv[*index+1] == "" {
			return "", true, false
		}
		*index++
		return argv[*index], true, true
	}
	if short == "" || arg == "" {
		return "", false, false
	}
	if arg == short {
		if *index+1 >= len(argv) || argv[*index+1] == "" {
			return "", true, false
		}
		*index++
		return argv[*index], true, true
	}
	if strings.HasPrefix(arg, short) && len(arg) > len(short) &&
		!strings.HasPrefix(lower, strings.ToLower(short)+"=") {
		return arg[len(short):], true, true
	}
	return "", false, false
}

type containerEndpointSelection struct {
	path    string
	network NetworkFact
}

func parseContainerEndpoint(
	commandID int64,
	program string,
	raw string,
) (containerEndpointSelection, bool) {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "%?#") {
		return containerEndpointSelection{}, false
	}
	if program == "nerdctl" && staticAbsolutePOSIXPath(raw) {
		return containerEndpointSelection{path: raw}, true
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Opaque != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" || parsed.RawPath != "" {
		return containerEndpointSelection{}, false
	}
	switch strings.ToLower(parsed.Scheme) {
	case "unix":
		if parsed.Host != "" || parsed.User != nil ||
			!strings.HasPrefix(raw, "unix://") ||
			raw != "unix://"+parsed.Path ||
			!staticAbsolutePOSIXPath(parsed.Path) {
			return containerEndpointSelection{}, false
		}
		return containerEndpointSelection{path: parsed.Path}, true
	case "tcp":
		if parsed.User != nil || parsed.Host == "" || parsed.Path != "" {
			return containerEndpointSelection{}, false
		}
		fact, ok := networkURLFact(commandID, raw, NetworkConnect)
		if !ok {
			return containerEndpointSelection{}, false
		}
		return containerEndpointSelection{network: fact}, true
	case "ssh":
		if parsed.Host == "" ||
			program == "docker" && parsed.Path != "" ||
			program != "docker" && parsed.Path != "" &&
				!staticAbsolutePOSIXPath(parsed.Path) {
			return containerEndpointSelection{}, false
		}
		fact, ok := networkURLFact(commandID, raw, NetworkConnect)
		if !ok {
			return containerEndpointSelection{}, false
		}
		return containerEndpointSelection{network: fact}, true
	case "fd", "http", "https", "npipe":
		// These transports do not fit the current filesystem or network fact
		// model or are rejected by these runtime endpoint grammars. Do not
		// make the surrounding command authoritative.
		return containerEndpointSelection{}, false
	default:
		return containerEndpointSelection{}, false
	}
}

func appendContainerEndpoint(
	out *parseOutput,
	command *CommandFact,
	endpoint containerEndpointSelection,
) {
	addOperation(command, OperationConnect)
	if endpoint.path != "" {
		appendCommandPath(
			out,
			command,
			PathAccessConnect,
			endpoint.path,
		)
	}
	if endpoint.network.Action != "" {
		out.appendNetwork(endpoint.network)
	}
}

func containerComposeCommand(
	out *parseOutput,
	command *CommandFact,
	start int,
) (string, int, bool) {
	valueOptions := optionValues(
		"-f", "--file", "--profile", "--project-directory",
		"--project-name", "--env-file", "--parallel",
	)
	for i := start; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "--" {
			if i+1 < len(command.Argv) {
				return command.Argv[i+1], i + 1, true
			}
			out.markPartial(IssueUnknownOperandGrammar)
			return "", 0, false
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			return arg, i, true
		}
		if arg == "--help" || arg == "--version" {
			setContainerPreview(out, command)
			return "", 0, false
		}
		key, value, joined := strings.Cut(arg, "=")
		if _, consumes := valueOptions[key]; consumes {
			if joined {
				if value == "" {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				continue
			}
			if i+1 >= len(command.Argv) || command.Argv[i+1] == "" {
				out.markPartial(IssueUnknownOperandGrammar)
				return "", 0, false
			}
			i++
			continue
		}
		switch arg {
		case "--dry-run":
			command.Effect = EffectPreview
			continue
		case "--all-resources", "--ansi", "--compatibility",
			"--progress", "--verbose":
			continue
		default:
			out.markPartial(IssueUnknownOperandGrammar)
			return "", 0, false
		}
	}
	setContainerPreview(out, command)
	return "", 0, false
}

func containerHelpAfterAction(
	argv []string,
	start int,
	valueOptions map[string]struct{},
	flagOptions map[string]struct{},
) (preview bool, complete bool) {
	options := true
	for i := start; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			// Runtime options stop at the image/workload positional.
			return false, true
		}
		if arg == "--help" {
			return true, true
		}
		key, value, joined := strings.Cut(arg, "=")
		if _, consumes := valueOptions[key]; consumes {
			if joined {
				if value == "" {
					return false, false
				}
				continue
			}
			if i+1 >= len(argv) || argv[i+1] == "" {
				return false, false
			}
			i++
			continue
		}
		if _, known := flagOptions[arg]; known {
			continue
		}
		if _, known := flagOptions[key]; known &&
			containerRunBooleanFlag(arg) {
			continue
		}
		// An unknown option can own the following help-shaped token. Never
		// let that token suppress execution under an inexact grammar.
		return false, false
	}
	return false, true
}

var (
	containerRunValueOptions = optionValues(
		"-a", "--add-host", "--annotation", "--attach", "--blkio-weight",
		"--cap-add", "--cap-drop", "--cgroup-parent", "--cidfile", "--cpus",
		"--device", "--dns", "--dns-option", "--dns-search", "--domainname",
		"-e", "--env",
		"--env-file", "--entrypoint", "-h", "--hostname", "-l", "--label",
		"--label-file", "--link", "--log-driver", "--log-opt", "-m", "--memory",
		"--mount", "--name", "--network", "--network-alias", "--platform", "-p",
		"--publish", "--restart", "--runtime", "--security-opt", "--shm-size",
		"--stop-signal", "--stop-timeout", "-u", "--user", "--userns",
		"-v", "--volume", "-w", "--workdir",
	)
	containerRunFlagOptions = optionValues(
		"-d", "--detach", "--init", "-i", "--interactive",
		"--oom-kill-disable", "--privileged", "--read-only", "--rm",
		"--tty", "-t",
	)
)

func containerComposeActionValueOptions(action string) map[string]struct{} {
	switch action {
	case "run":
		return optionValues(
			"--cap-add", "--cap-drop", "-e", "--env",
			"--entrypoint", "-l", "--label", "--name", "-p", "--publish",
			"-u", "--user", "-v", "--volume", "-w", "--workdir",
		)
	case "up":
		return optionValues(
			"--attach", "--exit-code-from", "--pull", "--scale", "--timeout",
			"--wait-timeout",
		)
	default:
		return optionValues()
	}
}

func containerComposeActionFlagOptions(action string) map[string]struct{} {
	switch action {
	case "run":
		return optionValues(
			"--build", "-d", "--detach", "--no-deps", "--quiet-pull",
			"--remove-orphans", "--rm", "-T", "--no-tty",
		)
	case "up":
		return optionValues(
			"--abort-on-container-exit", "--always-recreate-deps",
			"--attach-dependencies", "--build", "-d", "--detach",
			"--force-recreate",
			"--no-build", "--no-color", "--no-deps", "--no-log-prefix",
			"--no-recreate", "--no-start", "--quiet-pull",
			"--remove-orphans", "-V", "--renew-anon-volumes", "--wait",
		)
	default:
		return optionValues()
	}
}

func containerReadOnlyControl(
	program string,
	subcommand string,
	argv []string,
	start int,
) (preview bool, complete bool) {
	valueOptions, flagOptions := containerReadOnlyOptions(program, subcommand)
	options := true
	for i := start; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		if arg == "--help" {
			return true, true
		}
		key, value, joined := strings.Cut(arg, "=")
		if _, consumes := valueOptions[key]; consumes {
			if joined {
				if value == "" {
					return false, false
				}
				continue
			}
			if i+1 >= len(argv) || argv[i+1] == "" {
				return false, false
			}
			i++
			continue
		}
		if _, known := flagOptions[arg]; known {
			continue
		}
		return false, false
	}
	return false, true
}

func containerReadOnlyOptions(
	program string,
	subcommand string,
) (map[string]struct{}, map[string]struct{}) {
	switch subcommand {
	case "info":
		return optionValues("-f", "--format"), optionValues("--debug")
	case "inspect":
		return optionValues("-f", "--format", "--type"),
			optionValues("-s", "--size")
	case "images":
		return optionValues("-f", "--filter", "--format"),
			optionValues(
				"-a", "--all", "--digests", "--no-trunc", "-q", "--quiet",
			)
	case "ps":
		values := optionValues(
			"-f", "--filter", "--format", "-n", "--last",
		)
		flags := optionValues(
			"-a", "--all", "-l", "--latest", "--no-trunc", "-q",
			"--quiet", "-s", "--size",
		)
		if program == "podman" {
			values["--namespace"] = struct{}{}
			flags["--external"] = struct{}{}
			flags["--pod"] = struct{}{}
			flags["--sync"] = struct{}{}
		}
		return values, flags
	case "stats":
		return optionValues("--format"),
			optionValues("-a", "--all", "--no-stream", "--no-trunc")
	case "version":
		return optionValues("-f", "--format"), optionValues()
	default:
		return optionValues(), optionValues()
	}
}

func setContainerPreview(out *parseOutput, command *CommandFact) {
	command.Effect = EffectPreview
	operations := command.Operations[:0]
	for _, operation := range command.Operations {
		if operation != OperationConnect {
			operations = append(operations, operation)
		}
	}
	command.Operations = operations

	paths := out.paths[:0]
	for _, fact := range out.paths {
		if fact.CommandID != command.ID || fact.Access != PathAccessConnect {
			paths = append(paths, fact)
		}
	}
	out.paths = paths

	network := out.network[:0]
	for _, fact := range out.network {
		if fact.CommandID != command.ID || fact.Action != NetworkConnect {
			network = append(network, fact)
		}
	}
	out.network = network
}

func classifyContainerRunOptions(
	out *parseOutput,
	command *CommandFact,
	start int,
) {
	for i := start; i < len(command.Argv); i++ {
		arg := command.Argv[i]
		if arg == "--" {
			return
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			// The first positional is the image. Remaining argv belongs to
			// the container entrypoint, not the local runtime.
			return
		}
		var (
			value     string
			longMount bool
		)
		switch {
		case arg == "-v" || arg == "--volume" || arg == "--mount":
			if i+1 >= len(command.Argv) {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			i++
			value = command.Argv[i]
			longMount = arg == "--mount"
		case strings.HasPrefix(arg, "-v="):
			value = arg[len("-v="):]
		case strings.HasPrefix(arg, "--volume="):
			value = arg[len("--volume="):]
		case strings.HasPrefix(arg, "--mount="):
			value = arg[len("--mount="):]
			longMount = true
		default:
			if containerRunOptionConsumesValue(arg) {
				if !strings.Contains(arg, "=") {
					if i+1 >= len(command.Argv) {
						out.markPartial(IssueUnknownOperandGrammar)
						return
					}
					i++
				}
				continue
			}
			if containerRunFlag(arg) {
				continue
			}
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		source, readOnly, ok := containerMountSource(value, longMount)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if source == "" {
			continue
		}
		appendCommandPath(out, command, PathAccessRead, source)
		if !readOnly {
			appendCommandPath(out, command, PathAccessWrite, source)
		}
		if containerRuntimeSocketMountSource(source) {
			addOperation(command, OperationConnect)
			appendCommandPath(out, command, PathAccessConnect, source)
		}
	}
}

func containerRunOptionConsumesValue(option string) bool {
	key, _, _ := strings.Cut(option, "=")
	_, consumes := containerRunValueOptions[key]
	return consumes
}

func containerRunFlag(option string) bool {
	if _, known := containerRunFlagOptions[option]; known {
		return true
	}
	return containerRunBooleanFlag(option)
}

func containerRunBooleanFlag(option string) bool {
	key, value, joined := strings.Cut(option, "=")
	if !joined || key != "--privileged" {
		return false
	}
	_, err := strconv.ParseBool(value)
	return err == nil
}

func containerRuntimeSocketMountSource(value string) bool {
	if !staticAbsolutePOSIXPath(value) {
		return false
	}
	cleaned := path.Clean(value)
	switch cleaned {
	case "/var/run/docker.sock",
		"/run/docker.sock",
		"/run/containerd/containerd.sock",
		"/var/run/containerd/containerd.sock",
		"/run/crio/crio.sock",
		"/var/run/crio/crio.sock",
		"/run/podman/podman.sock",
		"/var/run/podman/podman.sock":
		return true
	}
	parts := strings.Split(strings.Trim(cleaned, "/"), "/")
	if len(parts) == 4 && parts[0] == "run" && parts[1] == "user" &&
		allDecimalDigits(parts[2]) && parts[3] == "docker.sock" {
		return true
	}
	return len(parts) == 5 &&
		parts[0] == "run" &&
		parts[1] == "user" &&
		allDecimalDigits(parts[2]) &&
		parts[3] == "podman" &&
		parts[4] == "podman.sock"
}

func containerMountSource(value string, longMount bool) (string, bool, bool) {
	if longMount {
		value = strings.TrimSpace(value)
		if value == "" {
			return "", false, false
		}
		var (
			source   string
			target   string
			bindType bool
			readOnly bool
		)
		seen := make(map[string]struct{})
		for _, field := range strings.Split(value, ",") {
			key, fieldValue, hasValue := strings.Cut(field, "=")
			if key == "" || strings.TrimSpace(key) != key ||
				hasValue && (fieldValue == "" ||
					strings.TrimSpace(fieldValue) != fieldValue) {
				return "", false, false
			}
			role := strings.ToLower(key)
			switch role {
			case "src":
				role = "source"
			case "dst", "destination":
				role = "target"
			case "ro":
				role = "readonly"
			}
			if _, duplicate := seen[role]; duplicate {
				return "", false, false
			}
			seen[role] = struct{}{}
			switch role {
			case "type":
				bindType = hasValue && strings.EqualFold(fieldValue, "bind")
			case "source":
				if hasValue {
					source = fieldValue
				}
			case "target":
				if hasValue {
					target = fieldValue
				}
			case "readonly":
				switch {
				case !hasValue, strings.EqualFold(fieldValue, "true"):
					readOnly = true
				case strings.EqualFold(fieldValue, "false"):
					readOnly = false
				default:
					return "", false, false
				}
			default:
				return "", false, false
			}
		}
		if !bindType {
			return "", false, true
		}
		if source == "" || !staticContainerDestination(target) ||
			hasUnresolvedPathSyntax(source) {
			return "", false, false
		}
		return source, readOnly, true
	}

	if value == "" || hasUnresolvedPathSyntax(value) {
		return "", false, false
	}
	separator := strings.Index(value, ":")
	if windowsDrivePath(value) {
		separator = strings.Index(value[2:], ":")
		if separator >= 0 {
			separator += 2
		}
	}
	if separator < 0 {
		// A destination-only volume is anonymous and has no host source.
		return "", false, staticContainerDestination(value)
	}
	if separator == 0 {
		return "", false, false
	}
	source := value[:separator]
	remainder := value[separator+1:]
	parts := strings.Split(remainder, ":")
	if len(parts) == 0 || len(parts) > 2 ||
		!staticContainerDestination(parts[0]) {
		return "", false, false
	}
	if pathFlavor(source) == PathFlavorUnknown &&
		source != "." && source != ".." {
		// Docker volume names are not host filesystem paths.
		return "", false, true
	}
	readOnly := false
	if len(parts) > 1 {
		for _, option := range strings.Split(parts[1], ",") {
			switch strings.ToLower(option) {
			case "ro", "readonly":
				readOnly = true
			case "rw", "z", "delegated", "cached", "consistent",
				"rprivate", "private", "rshared", "shared",
				"rslave", "slave":
			default:
				return "", false, false
			}
		}
	}
	return source, readOnly, true
}

func staticContainerDestination(value string) bool {
	return value != "" && strings.HasPrefix(value, "/") &&
		!hasUnresolvedPathSyntax(value) && path.Clean(value) == value
}

func classifyWorkload(out *parseOutput, command *CommandFact, program string) {
	valueOptions := exactOptionSet(
		"--as", "--as-group", "--cache-dir", "--certificate-authority",
		"--client-certificate", "--client-key", "--cluster", "--context",
		"--kubeconfig", "--kuberc", "-n", "--namespace", "--profile",
		"--profile-output", "--proxy-url", "--request-timeout", "-s", "--server",
		"--tls-server-name", "--token", "--user", "-v", "--vmodule",
	)
	subcommand, index, preview, complete := ownedCLISubcommand(
		command.Argv,
		valueOptions,
		exactOptionSet(
			"--disable-compression", "--insecure-skip-tls-verify",
			"--match-server-version", "--warnings-as-errors",
		),
		exactOptionSet("--help", "--version"),
	)
	if preview {
		command.Effect = EffectPreview
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if subcommand != "" && command.Argv[index] != subcommand {
		complete = false
	}
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if subcommand == "" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	for i := 1; i < index; i++ {
		arg := command.Argv[i]
		key, joinedValue, joined := strings.Cut(arg, "=")
		if _, consumes := valueOptions[key]; !consumes {
			continue
		}
		value, found := classifierOptionValue(command.Argv, &i, joinedValue, joined)
		if !found {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		switch key {
		case "--kubeconfig", "--kuberc":
			appendPath(out, command.ID, PathAccessRead, value)
		case "-s", "--server", "--proxy-url":
			if fact, valid := networkURLFact(command.ID, value, NetworkConnect); valid {
				out.appendNetwork(fact)
			} else {
				out.markPartial(IssueUnknownOperandGrammar)
			}
		}
	}

	switch subcommand {
	case "exec", "debug", "attach":
		addOperation(command, OperationWorkloadExec)
		out.markPartial(IssueUnsupportedConstruct)
	case "rsh":
		if program == "oc" || program == "oc.exe" {
			addOperation(command, OperationWorkloadExec)
			out.markPartial(IssueUnsupportedConstruct)
		}
	case "port-forward":
		addOperation(command, OperationTunnel)
		existingNetwork := append([]NetworkFact(nil), out.network...)
		for _, fact := range existingNetwork {
			if fact.CommandID == command.ID && fact.Action == NetworkConnect {
				fact.Action = NetworkTunnel
				out.appendNetwork(fact)
			}
		}
	case "get", "list", "describe":
		addOperation(command, OperationList)
	case "logs":
		addOperation(command, OperationRead)
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func classifyGit(out *parseOutput, command *CommandFact) {
	subcommand, index, preview, complete := ownedCLISubcommand(
		command.Argv,
		exactOptionSet(
			"-c", "-C", "--config-env", "--exec-path", "--git-dir",
			"--namespace", "--super-prefix", "--work-tree",
		),
		exactOptionSet(
			"-p", "--paginate", "--no-pager", "--bare",
			"--no-replace-objects", "--literal-pathspecs",
			"--glob-pathspecs", "--noglob-pathspecs",
			"--icase-pathspecs", "--no-optional-locks",
		),
		exactOptionSet("--help", "--version"),
	)
	if preview {
		command.Effect = EffectPreview
		return
	}
	if !complete || subcommand == "" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	switch subcommand {
	case "commit":
		valueOptions := exactOptionSet(
			"-m", "--message", "-F", "--file", "--author",
			"--date", "--cleanup", "--fixup", "--squash",
			"-C", "--reuse-message", "-c", "--reedit-message",
			"--pathspec-from-file",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv[index:],
			valueOptions,
			exactOptionSet(
				"-n", "--no-verify", "-a", "--all", "-p", "--patch",
				"-s", "--signoff", "-v", "--verbose", "-q", "--quiet",
				"--amend", "--no-edit", "--allow-empty",
				"--allow-empty-message", "--short", "--branch",
				"--porcelain", "--long", "-z", "--null",
				"--no-post-rewrite", "-i", "--include", "-o", "--only",
				"--interactive", "--no-status", "--status",
			),
			exactOptionSet("--help", "--dry-run"),
		)
		if !strictCLIOptionValues(command.Argv[index:], valueOptions) {
			parsed.complete = false
		}
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "push":
		valueOptions := exactOptionSet(
			"--repo", "--receive-pack", "--exec", "--push-option", "-o",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv[index:],
			valueOptions,
			exactOptionSet(
				"--no-verify", "-f", "--force", "--force-with-lease",
				"--force-if-includes", "--all", "--mirror", "--tags",
				"--follow-tags", "--atomic", "--set-upstream", "-u",
				"--delete", "--prune", "--porcelain", "--signed",
				"--no-signed", "--ipv4", "-4", "--ipv6", "-6",
				"--quiet", "-q", "--verbose", "-v",
			),
			exactOptionSet("--help", "--dry-run", "-n"),
		)
		if !strictCLIOptionValues(command.Argv[index:], valueOptions) {
			parsed.complete = false
		}
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "config":
		valueOptions := exactOptionSet(
			"--file", "-f", "--blob", "--default", "--comment",
			"--type",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv[index:],
			valueOptions,
			exactOptionSet(
				"--global", "--system", "--local", "--worktree",
				"--fixed-value", "--null", "-z", "--includes",
				"--no-includes", "--show-origin", "--show-scope",
				"--name-only", "--get", "--get-all", "--get-regexp",
				"--get-urlmatch", "--list", "-l", "--add",
				"--replace-all", "--unset", "--unset-all",
				"--rename-section", "--remove-section", "--edit", "-e",
			),
			exactOptionSet("--help"),
		)
		if !strictCLIOptionValues(command.Argv[index:], valueOptions) {
			parsed.complete = false
		}
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		if gitConfigMutates(command.Argv[index+1:]) {
			addOperation(command, OperationConfigChange)
		}
	case "show", "log", "diff", "whatchanged":
		classifyGitReadOutput(out, command, index)
	case "remote":
		classifyGitRemote(out, command, index)
	case "status":
		valueOptions := exactOptionSet(
			"--ignore-submodules",
			"--untracked-files",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv[index:],
			valueOptions,
			exactOptionSet(
				"-s", "--short", "-b", "--branch", "--show-stash",
				"--porcelain", "--long", "-v", "--verbose", "-z",
				"--null", "--column", "--no-column", "--ahead-behind",
				"--no-ahead-behind", "--renames", "--no-renames",
			),
			exactOptionSet("--help"),
		)
		if !strictCLIOptionValues(command.Argv[index:], valueOptions) {
			parsed.complete = false
		}
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func classifyGitReadOutput(
	out *parseOutput,
	command *CommandFact,
	index int,
) {
	valueOptions := exactOptionSet("--output")
	flagOptions := exactOptionSet(
		"--no-patch", "-s", "--patch", "-p", "--stat",
		"--numstat", "--shortstat", "--name-only", "--name-status",
		"--no-renames", "--no-ext-diff", "--text", "-a", "--binary",
		"--full-index", "--no-prefix", "--raw",
	)
	if !strings.EqualFold(command.Argv[index], "diff") {
		for option := range exactOptionSet(
			"--format", "--date", "--encoding", "-n", "--max-count",
			"--skip", "--since", "--after", "--until", "--before",
			"--author", "--committer", "--grep",
		) {
			valueOptions[option] = struct{}{}
		}
		for option := range exactOptionSet(
			"--oneline", "--abbrev-commit", "--all", "--reverse",
			"--first-parent", "--merges", "--no-merges",
		) {
			flagOptions[option] = struct{}{}
		}
	}
	parsed := parseOwnedPOSIXOptions(
		command.Argv[index:],
		valueOptions,
		flagOptions,
		exactOptionSet("--help"),
	)
	if !strictCLIOptionValues(command.Argv[index:], valueOptions) {
		parsed.complete = false
	}
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	output, hasOutput := parsed.values["--output"]
	if hasOutput {
		if output == "-" {
			parsed.complete = false
		}
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !hasOutput {
		return
	}
	output, complete := gitReadOutputEffectivePath(
		command.Argv[:index],
		output,
	)
	if !complete {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationWrite)
	appendCommandPath(out, command, PathAccessWrite, output)
}

// gitReadOutputEffectivePath applies Git's global -C working-directory
// semantics to a read command's --output operand. Other repository-selection
// globals such as --git-dir, --work-tree, and --bare do not change the process
// working directory, so they do not change where --output writes.
func gitReadOutputEffectivePath(argv []string, output string) (string, bool) {
	workingDirectory := ""
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		directory := ""
		switch {
		case argument == "-C":
			index++
			if index >= len(argv) {
				return "", false
			}
			directory = argv[index]
		case strings.HasPrefix(argument, "-C") && len(argument) > 2:
			directory = argument[2:]
		default:
			continue
		}
		if directory == "" || hasUnresolvedPathSyntax(directory) {
			return "", false
		}
		if workingDirectory == "" || gitReadOutputAbsolutePath(directory) {
			workingDirectory = directory
			continue
		}
		workingDirectory = path.Join(workingDirectory, directory)
	}
	if workingDirectory == "" || gitReadOutputAbsolutePath(output) {
		return output, true
	}
	if output == "" || hasUnresolvedPathSyntax(output) {
		return "", false
	}
	return path.Join(workingDirectory, output), true
}

func gitReadOutputAbsolutePath(value string) bool {
	if staticAbsolutePOSIXPath(value) {
		return true
	}
	if pathFlavor(value) != PathFlavorWindows {
		return false
	}
	parsed := parseWindowsPathWithPolicy(
		value,
		pathExpansionPolicy{literal: true},
	)
	return parsed.absolute && !parsed.unresolved
}

func classifyGitRemote(
	out *parseOutput,
	command *CommandFact,
	index int,
) {
	argv := command.Argv[index:]
	if len(argv) == 1 ||
		len(argv) == 2 &&
			(argv[1] == "-v" || argv[1] == "--verbose") {
		// `git remote` and its verbose form are listings.
		return
	}
	if len(argv) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	action := strings.ToLower(argv[1])
	switch action {
	case "add":
		parsed := parseOwnedPOSIXOptions(
			append([]string{"remote-add"}, argv[2:]...),
			exactOptionSet("-t", "--track", "-m", "--master"),
			exactOptionSet("-f", "--fetch", "--tags", "--no-tags"),
			exactOptionSet("--help"),
		)
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		addOperation(command, OperationConfigChange)
		if !parsed.complete || len(parsed.positionals) != 2 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		appendGitRemoteEndpoint(out, command.ID, parsed.positionals[1])
	case "set-url":
		parsed := parseOwnedPOSIXOptions(
			append([]string{"remote-set-url"}, argv[2:]...),
			exactOptionSet(),
			exactOptionSet("--push"),
			exactOptionSet("--help"),
		)
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		addOperation(command, OperationConfigChange)
		if !parsed.complete || len(parsed.positionals) != 2 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		appendGitRemoteEndpoint(out, command.ID, parsed.positionals[1])
	case "rename":
		if len(argv) != 4 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationConfigChange)
	case "remove":
		if len(argv) != 3 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationConfigChange)
	case "get-url", "show", "update", "prune":
		// Queries and maintenance commands do not introduce a new endpoint
		// from their operands. Keep them quiet for policy purposes.
		return
	default:
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func appendGitRemoteEndpoint(out *parseOutput, commandID int64, raw string) {
	fact, ok := gitRemoteEndpointFact(commandID, raw)
	if !ok {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	out.appendNetwork(fact)
}

func gitRemoteEndpointFact(commandID int64, raw string) (NetworkFact, bool) {
	if raw == "" || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\x00\r\n\t ") {
		return NetworkFact{}, false
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" || parsed.Path == "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" {
			return NetworkFact{}, false
		}
		scheme := strings.ToLower(parsed.Scheme)
		if scheme != "https" && scheme != "ssh" {
			return NetworkFact{}, false
		}
		if parsed.User != nil {
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return NetworkFact{}, false
			}
		}
		host, ok := canonicalNetworkHost(parsed.Hostname())
		if !ok {
			return NetworkFact{}, false
		}
		port := int64(0)
		if rawPort := parsed.Port(); rawPort != "" {
			port, ok = parseNetworkPort(rawPort)
			if !ok {
				return NetworkFact{}, false
			}
		}
		return NetworkFact{
			CommandID: commandID,
			Action:    NetworkConnect,
			Scheme:    scheme,
			Host:      host,
			Port:      port,
		}, true
	}

	authority, remotePath, ok := strings.Cut(raw, ":")
	if !ok || authority == "" || remotePath == "" ||
		strings.Contains(authority, "/") ||
		strings.Contains(remotePath, `\`) {
		return NetworkFact{}, false
	}
	host := authority
	if user, candidate, hasUser := strings.Cut(authority, "@"); hasUser {
		if user == "" || candidate == "" || strings.Contains(candidate, "@") {
			return NetworkFact{}, false
		}
		host = candidate
	}
	host, ok = canonicalNetworkHost(host)
	if !ok {
		return NetworkFact{}, false
	}
	return NetworkFact{
		CommandID: commandID,
		Action:    NetworkConnect,
		Scheme:    "ssh",
		Host:      host,
	}, true
}

func ownedCLISubcommand(
	argv []string,
	valueOptions map[string]struct{},
	flagOptions map[string]struct{},
	previewOptions map[string]struct{},
) (string, int, bool, bool) {
	complete := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			if i+1 >= len(argv) {
				return "", 0, false, false
			}
			return strings.ToLower(argv[i+1]), i + 1, false, complete
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			return strings.ToLower(arg), i, false, complete
		}
		if strings.HasPrefix(arg, "--") {
			key, value, joined := strings.Cut(arg, "=")
			if _, preview := previewOptions[key]; preview && !joined {
				return "", 0, true, complete
			}
			if _, consumes := valueOptions[key]; consumes {
				if joined {
					if value == "" {
						complete = false
					}
					continue
				}
				if i+1 >= len(argv) || argv[i+1] == "" {
					complete = false
					continue
				}
				i++
				if argv[i] != "-" && strings.HasPrefix(argv[i], "-") {
					complete = false
				}
				continue
			}
			if _, flag := flagOptions[key]; flag && !joined {
				continue
			}
			complete = false
			continue
		}
		key := arg
		if len(arg) > 2 {
			key = arg[:2]
		}
		if _, preview := previewOptions[key]; preview {
			return "", 0, true, complete
		}
		if _, consumes := valueOptions[key]; consumes {
			if len(arg) > 2 {
				continue
			}
			if i+1 >= len(argv) || argv[i+1] == "" {
				complete = false
				continue
			}
			i++
			if argv[i] != "-" && strings.HasPrefix(argv[i], "-") {
				complete = false
			}
			continue
		}
		if _, flag := flagOptions[arg]; flag {
			continue
		}
		complete = false
	}
	return "", 0, false, false
}

func classifyAgentRuntime(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	var (
		parsed       ownedPOSIXOptionParse
		valueOptions map[string]struct{}
		preview      map[string]struct{}
	)
	switch program {
	case "codex":
		valueOptions = exactOptionSet(
			"-c", "--config", "--enable", "--disable",
			"-i", "--image", "-m", "--model",
			"--local-provider", "-p", "--profile",
			"-s", "--sandbox", "-C", "--cd", "--add-dir",
			"--remote", "--remote-auth-token-env",
			"-a", "--ask-for-approval",
			"--output-schema", "--color",
			"-o", "--output-last-message",
		)
		preview = exactOptionSet("-h", "--help", "-V", "--version")
		parsed = parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet(
				"--strict-config", "--oss",
				"--dangerously-bypass-approvals-and-sandbox",
				"--dangerously-bypass-hook-trust",
				"--search", "--no-alt-screen",
				"--full-auto", "--skip-git-repo-check",
				"--ephemeral", "--ignore-user-config",
				"--ignore-rules", "--json",
			),
			preview,
		)
		hasExecSubcommand := len(parsed.positionals) > 0 &&
			(parsed.positionals[0] == "exec" ||
				parsed.positionals[0] == "e")
		if !hasExecSubcommand &&
			(!parsed.preview || len(parsed.positionals) > 0) {
			parsed.complete = false
		}
		if !validCodexAgentRuntimeOptions(parsed, hasExecSubcommand) {
			parsed.complete = false
		}
	case "claude":
		valueOptions = exactOptionSet(
			"--permission-mode", "--model", "--output-format",
			"--input-format", "--system-prompt",
			"--append-system-prompt", "--max-budget-usd",
			"--fallback-model", "--json-schema",
			"--permission-prompt-tool", "--mcp-config", "--add-dir",
		)
		preview = exactOptionSet("-h", "--help", "-v", "--version")
		parsed = parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet(
				"-p", "--print", "--dangerously-skip-permissions",
				"--verbose", "--debug", "--continue",
			),
			preview,
		)
		if !validClaudeAgentRuntimeOptions(parsed) {
			parsed.complete = false
		}
	case "gemini":
		valueOptions = exactOptionSet(
			"-p", "--prompt", "-o", "--output-format",
			"--approval-mode", "-m", "--model",
		)
		preview = exactOptionSet("-h", "--help", "-v", "--version")
		parsed = parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet("--yolo", "--debug"),
			preview,
		)
	case "opencode":
		valueOptions = exactOptionSet(
			"-m", "--model", "--agent", "-f", "--file",
			"--format", "--attach", "-s", "--session", "--title",
		)
		preview = exactOptionSet("-h", "--help", "-v", "--version")
		parsed = parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet("--continue"),
			preview,
		)
		if !parsed.preview &&
			(len(parsed.positionals) == 0 ||
				parsed.positionals[0] != "run") {
			parsed.complete = false
		}
	default:
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	argumentsComplete, quotedPreview := agentRuntimeArgumentsOwned(
		command,
		preview,
	)
	if !argumentsComplete {
		parsed.complete = false
	}
	if quotedPreview {
		parsed.preview = false
	}
	if !strictCLIOptionValues(command.Argv, valueOptions) {
		parsed.complete = false
	}
	if parsed.repeatedFlag {
		parsed.complete = false
	}
	bypass, conflictingBypass := agentRuntimePolicyBypass(program, parsed)
	if conflictingBypass {
		parsed.complete = false
	}
	if parsed.preview {
		command.Effect = EffectPreview
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		return
	}
	if !parsed.complete {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if bypass {
		addOperation(command, OperationPolicyBypass)
	}
}

func classifyAgentPackageRunner(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	childIndex := 0
	switch program {
	case "npx":
		switch {
		case len(command.Argv) > 2 && command.Argv[1] == "-y":
			childIndex = 2
		case len(command.Argv) > 1:
			childIndex = 1
		}
	case "pnpm":
		if len(command.Argv) > 2 && command.Argv[1] == "dlx" {
			childIndex = 2
		}
	case "bunx":
		if len(command.Argv) > 1 {
			childIndex = 1
		}
	}
	if childIndex == 0 || childIndex >= len(command.Argv) {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	childProgram := strings.ToLower(command.Argv[childIndex])
	if childProgram != "claude" &&
		childProgram != "codex" &&
		childProgram != "gemini" {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	child := CommandFact{
		ID:           command.ID,
		Dialect:      command.Dialect,
		Effect:       command.Effect,
		Executable:   command.Argv[childIndex],
		Program:      childProgram,
		Argv:         cloneSlice(command.Argv[childIndex:]),
		ArgvComplete: command.ArgvComplete,
	}
	if childIndex < len(command.Arguments) {
		child.Arguments = cloneSlice(command.Arguments[childIndex:])
	}
	childOut := newParseOutput(command.Dialect, command.ID+1)
	classifyAgentRuntime(&childOut, &child, childProgram)
	if childOut.status != StatusComplete {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	command.Effect = child.Effect
	for _, operation := range child.Operations {
		addOperation(command, operation)
	}
}

func agentRuntimePolicyBypass(
	program string,
	parsed ownedPOSIXOptionParse,
) (bypass, conflicting bool) {
	switch program {
	case "claude":
		_, direct := parsed.seen["--dangerously-skip-permissions"]
		permissionMode, modeSeen, modeUnique := ownedAgentRuntimeValue(
			parsed,
			"--permission-mode",
		)
		modeBypass := modeSeen && modeUnique &&
			permissionMode == "bypassPermissions"
		return direct || modeBypass, direct && modeBypass
	case "codex":
		_, direct := parsed.seen["--dangerously-bypass-approvals-and-sandbox"]
		sandbox, sandboxSeen, sandboxUnique := ownedAgentRuntimeValue(
			parsed,
			"--sandbox",
			"-s",
		)
		approval, approvalSeen, approvalUnique := ownedAgentRuntimeValue(
			parsed,
			"--ask-for-approval",
			"-a",
		)
		paired := sandboxSeen && sandboxUnique &&
			sandbox == "danger-full-access" &&
			approvalSeen && approvalUnique && approval == "never"
		return direct || paired, direct && paired
	case "gemini":
		_, yolo := parsed.seen["--yolo"]
		return yolo, false
	default:
		return false, false
	}
}

func validCodexAgentRuntimeOptions(
	parsed ownedPOSIXOptionParse,
	hasExecSubcommand bool,
) bool {
	for option, position := range parsed.optionPositions {
		switch option {
		case "--remote", "--remote-auth-token-env",
			"-a", "--ask-for-approval",
			"--search", "--no-alt-screen":
			if hasExecSubcommand &&
				position > parsed.firstPositionalPosition {
				return false
			}
		case "--output-schema", "--color",
			"-o", "--output-last-message",
			"--full-auto", "--skip-git-repo-check",
			"--ephemeral", "--ignore-user-config",
			"--ignore-rules", "--json":
			if !hasExecSubcommand ||
				position < parsed.firstPositionalPosition {
				return false
			}
		}
	}
	sandbox, sandboxSeen, sandboxUnique := ownedAgentRuntimeValue(
		parsed,
		"--sandbox",
		"-s",
	)
	if sandboxSeen &&
		(!sandboxUnique || !knownCodexSandbox(sandbox)) {
		return false
	}
	approval, approvalSeen, approvalUnique := ownedAgentRuntimeValue(
		parsed,
		"--ask-for-approval",
		"-a",
	)
	if approvalSeen &&
		(!approvalUnique || !knownCodexApproval(approval)) {
		return false
	}
	if color, present := parsed.values["--color"]; present {
		switch color {
		case "always", "never", "auto":
		default:
			return false
		}
	}
	return true
}

func validClaudeAgentRuntimeOptions(parsed ownedPOSIXOptionParse) bool {
	mode, present, unique := ownedAgentRuntimeValue(
		parsed,
		"--permission-mode",
	)
	if !present {
		return true
	}
	if !unique {
		return false
	}
	switch mode {
	case "acceptEdits", "auto", "bypassPermissions", "manual", "dontAsk",
		"plan":
		return true
	default:
		return false
	}
}

func ownedAgentRuntimeValue(
	parsed ownedPOSIXOptionParse,
	options ...string,
) (value string, present, unique bool) {
	unique = true
	for _, option := range options {
		candidate, ok := parsed.values[option]
		if !ok {
			continue
		}
		if present {
			unique = false
		}
		value = candidate
		present = true
	}
	return value, present, unique
}

func knownCodexSandbox(value string) bool {
	switch value {
	case "read-only", "workspace-write", "danger-full-access":
		return true
	default:
		return false
	}
}

func knownCodexApproval(value string) bool {
	switch value {
	case "untrusted", "on-failure", "on-request", "never":
		return true
	default:
		return false
	}
}

func agentRuntimeArgumentsOwned(
	command *CommandFact,
	previewOptions map[string]struct{},
) (complete, quotedPreview bool) {
	if len(command.Arguments) != len(command.Argv) {
		return false, false
	}
	complete = true
	for _, argument := range command.Arguments[1:] {
		if argument.Expands {
			complete = false
		}
		if argument.Quote == QuoteNone ||
			!strings.HasPrefix(argument.Value, "-") {
			continue
		}
		complete = false
		if _, preview := previewOptions[argument.Value]; preview {
			quotedPreview = true
		}
	}
	return complete, quotedPreview
}

func strictCLIOptionValues(
	argv []string,
	valueOptions map[string]struct{},
) bool {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--" {
			return true
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			continue
		}
		key := arg
		joined := false
		value := ""
		if strings.HasPrefix(arg, "--") {
			key, value, joined = strings.Cut(arg, "=")
		} else if len(arg) > 2 {
			key = arg[:2]
			value = arg[2:]
			joined = true
		}
		if _, consumes := valueOptions[key]; !consumes {
			continue
		}
		if joined {
			if value == "" || value == "=" {
				return false
			}
			continue
		}
		if i+1 >= len(argv) || argv[i+1] == "" ||
			argv[i+1] != "-" && strings.HasPrefix(argv[i+1], "-") {
			return false
		}
		i++
	}
	return true
}

func gitConfigMutates(argv []string) bool {
	var positionals int
	readOnly := false
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		lower := strings.ToLower(arg)
		switch {
		case lower == "--add", lower == "--replace-all", lower == "--unset",
			lower == "--unset-all", lower == "--rename-section",
			lower == "--remove-section", lower == "--edit", lower == "-e":
			return true
		case lower == "--file", lower == "-f", lower == "--blob",
			lower == "--default", lower == "--comment", lower == "--type":
			if i+1 < len(argv) {
				i++
			}
			continue
		case strings.HasPrefix(lower, "--file="), strings.HasPrefix(lower, "--blob="),
			strings.HasPrefix(lower, "--default="), strings.HasPrefix(lower, "--comment="),
			strings.HasPrefix(lower, "--type="):
			continue
		case lower == "--get", lower == "--get-all", lower == "--get-regexp",
			lower == "--get-urlmatch", lower == "--list", lower == "-l",
			lower == "--show-origin", lower == "--show-scope", lower == "--name-only":
			readOnly = true
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		default:
			positionals++
		}
	}
	return !readOnly && positionals >= 2
}

func classifyCredentialCLI(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	var (
		positionals []string
		match       bool
	)
	switch program {
	case "aws", "aws.exe", "aws.cmd":
		valueOptions := exactOptionSet(
			"--ca-bundle", "--cli-connect-timeout", "--cli-read-timeout",
			"--cli-binary-format", "--cli-input-json", "--cli-input-yaml",
			"--color", "--endpoint-url", "--output", "--profile", "--query",
			"--region", "--duration-seconds", "--external-id", "--filters",
			"--generate-cli-skeleton", "--max-results", "--name", "--names",
			"--next-token", "--page-size", "--parameter", "--parameters", "--policy",
			"--policy-arns", "--provided-contexts", "--role-arn",
			"--role-session-name", "--secret-id", "--secret-id-list",
			"--serial-number", "--source-identity", "--starting-token",
			"--tags", "--token-code", "--transitive-tag-keys",
			"--version-id", "--version-stage", "--web-identity-token",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet(
				"--cli-auto-prompt", "--debug", "--include-planned-deletion",
				"--no-cli-auto-prompt", "--no-cli-pager",
				"--no-include-planned-deletion", "--no-paginate",
				"--no-recursive", "--no-sign-request",
				"--no-verify-ssl", "--no-with-decryption",
				"--recursive", "--with-decryption",
			),
			exactOptionSet("--help", "--version"),
		)
		complete := parsed.complete &&
			strictCLIOptionValues(command.Argv, valueOptions)
		positionals = parsed.positionals
		positionalHelp := len(positionals) > 0 &&
			positionals[0] == "help" ||
			len(positionals) > 2 &&
				positionals[len(positionals)-1] == "help"
		if parsed.preview || positionalHelp {
			if !complete {
				out.markPartial(IssueUnknownOperandGrammar)
				break
			}
			command.Effect = EffectPreview
			break
		}
		if preview, malformed := awsSkeletonPreview(command.Argv); preview {
			if !complete {
				out.markPartial(IssueUnknownOperandGrammar)
				break
			}
			command.Effect = EffectPreview
			break
		} else if malformed {
			out.markPartial(IssueUnknownOperandGrammar)
			break
		}
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		match = positionalPrefixExact(positionals, "secretsmanager", "get-secret-value") ||
			positionalPrefixExact(positionals, "secretsmanager", "batch-get-secret-value") ||
			positionalPrefixExact(positionals, "ssm", "get-parameter") ||
			positionalPrefixExact(positionals, "ssm", "get-parameters") ||
			positionalPrefixExact(positionals, "sts", "get-session-token") ||
			positionalPrefixExact(positionals, "sts", "assume-role") ||
			positionalPrefixExact(positionals, "sts", "assume-role-with-web-identity") ||
			positionalPrefixExact(positionals, "sts", "get-federation-token")
	case "gcloud", "gcloud.exe", "gcloud.cmd":
		consumes := optionValues(
			"--access-token-file", "--account", "--billing-project",
			"--configuration", "--flags-file", "--flatten", "--format",
			"--impersonate-service-account", "--project", "--trace-token",
			"--verbosity", "--secret",
		)
		positionals = cliPositionals(command.Argv, consumes)
		if cliHelpRequestedOwned(command.Argv, positionals, consumes, false) {
			command.Effect = EffectPreview
			break
		}
		match = positionalPrefix(positionals, "secrets", "versions", "access") ||
			positionalPrefix(positionals, "auth", "print-access-token") ||
			positionalPrefix(positionals, "auth", "print-identity-token") ||
			positionalPrefix(positionals, "auth", "application-default", "print-access-token")
	case "az", "az.exe", "az.cmd":
		consumes := optionValues(
			"--file", "--id", "--name", "-n", "--output", "-o", "--query",
			"--subscription", "--vault-name",
		)
		positionals = cliPositionals(command.Argv, consumes)
		if cliHelpRequestedOwned(command.Argv, positionals, consumes, false) {
			command.Effect = EffectPreview
			break
		}
		match = positionalPrefix(positionals, "keyvault", "secret", "show") ||
			positionalPrefix(positionals, "keyvault", "secret", "download") ||
			positionalPrefix(positionals, "account", "get-access-token")
	case "vault", "vault.exe":
		consumes := optionValues(
			"-address", "-agent-address", "-ca-cert", "-client-cert",
			"-client-key", "-field", "-format", "-mount", "-namespace",
		)
		positionals = cliPositionals(command.Argv, consumes)
		if cliHelpRequestedOwned(command.Argv, positionals, consumes, false) {
			command.Effect = EffectPreview
			break
		}
		match = positionalPrefix(positionals, "kv", "get") ||
			positionalPrefix(positionals, "read")
	case "op", "op.exe":
		consumes := optionValues(
			"--account", "--cache", "--config", "--encoding", "--format",
			"--iso-timestamps", "--fields", "--output",
		)
		positionals = cliPositionals(command.Argv, consumes)
		if cliHelpRequestedOwned(command.Argv, positionals, consumes, false) {
			command.Effect = EffectPreview
			break
		}
		match = positionalPrefix(positionals, "read") ||
			positionalPrefix(positionals, "item", "get") ||
			positionalPrefix(positionals, "document", "get")
	case "pass", "pass.exe":
		consumes := optionValues()
		positionals = cliPositionals(command.Argv, consumes)
		if cliHelpRequestedOwned(command.Argv, positionals, consumes, true) ||
			len(positionals) == 0 {
			if len(positionals) > 0 {
				command.Effect = EffectPreview
			}
			break
		}
		switch strings.ToLower(positionals[0]) {
		case "ls", "list", "find", "grep":
			addOperation(command, OperationList)
		case "insert", "edit", "generate", "rm", "remove", "mv", "rename",
			"cp", "copy", "git", "init":
		default:
			match = true
		}
	case "security":
		consumes := optionValues(
			"-a", "-c", "-d", "-j", "-l", "-p", "-s", "-t",
		)
		positionals = cliPositionals(command.Argv, consumes)
		help := cliHelpRequestedOwned(
			command.Argv,
			positionals,
			consumes,
			true,
		)
		if help {
			command.Effect = EffectPreview
		}
		match = !help &&
			(positionalPrefix(positionals, "find-generic-password") ||
				positionalPrefix(positionals, "find-internet-password")) &&
			hasAnyArgument(command.Argv, "-w", "-g")
	case "cmdkey", "cmdkey.exe":
		if hasAnyArgument(command.Argv, "/list", "-list") {
			addOperation(command, OperationList)
		}
	}
	if match {
		addOperation(command, OperationCredentialRead)
	}
}

func cliHelpRequestedOwned(
	argv []string,
	positionals []string,
	consumesValue map[string]struct{},
	positionalHelp bool,
) bool {
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		lower := strings.ToLower(arg)
		if arg == "-h" || lower == "--help" {
			return true
		}
		key, _, joined := strings.Cut(lower, "=")
		if _, consumes := consumesValue[key]; consumes && !joined &&
			i+1 < len(argv) {
			i++
		}
	}
	return positionalHelp && len(positionals) > 0 &&
		strings.EqualFold(positionals[0], "help") ||
		positionalHelp && len(positionals) > 2 &&
			strings.EqualFold(positionals[len(positionals)-1], "help")
}

func awsSkeletonPreview(argv []string) (preview, malformed bool) {
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		value := ""
		switch {
		case arg == "--generate-cli-skeleton":
			if i+1 >= len(argv) {
				return false, true
			}
			i++
			value = argv[i]
		case strings.HasPrefix(arg, "--generate-cli-skeleton="):
			value = arg[len("--generate-cli-skeleton="):]
		default:
			continue
		}
		switch value {
		case "input", "output", "yaml-input":
			return true, false
		default:
			return false, true
		}
	}
	return false, false
}

func cliPositionals(argv []string, consumesValue map[string]struct{}) []string {
	var positionals []string
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		lower := strings.ToLower(arg)
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") {
			key, _, joined := strings.Cut(lower, "=")
			if _, consumes := consumesValue[key]; consumes && !joined && i+1 < len(argv) {
				i++
			}
			continue
		}
		positionals = append(positionals, arg)
	}
	return positionals
}

func positionalPrefix(positionals []string, want ...string) bool {
	if len(positionals) < len(want) {
		return false
	}
	for index, value := range want {
		if !strings.EqualFold(positionals[index], value) {
			return false
		}
	}
	return true
}

func positionalPrefixExact(positionals []string, want ...string) bool {
	if len(positionals) < len(want) {
		return false
	}
	for index, value := range want {
		if positionals[index] != value {
			return false
		}
	}
	return true
}

func classifyStructuredWindowsArgv(
	out *parseOutput,
	command *CommandFact,
	classifier func(*CommandFact, []windowsWord, *windowsFactBuilder),
	dialects ...Dialect,
) {
	if !requireCommandDialect(out, command, dialects...) {
		return
	}
	args := make([]windowsWord, 0, len(command.Argv)-1)
	for _, value := range command.Argv[1:] {
		args = append(args, windowsWord{value: value, quote: QuoteNone})
	}
	classifier(command, args, newWindowsFactBuilder(out))
}

func classifyDecode(out *parseOutput, command *CommandFact, program string) {
	switch program {
	case "base64", "base64.exe":
		portable := parsePortableBase64DecodeArgv(command.Argv)
		if portable.Complete {
			if portable.InputSet && portable.Input != "-" {
				appendCommandPath(
					out,
					command,
					PathAccessRead,
					portable.Input,
				)
				appendFileToProcessFlow(out, command.ID)
			}
			if portable.Decode {
				addOperation(command, OperationDecode)
			}
			return
		}
		valueOptions := exactOptionSet("-w", "--wrap")
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet(
				"-d", "-D", "--decode", "-i", "--ignore-garbage",
			),
			exactOptionSet("--help", "--version"),
		)
		complete := parsed.complete &&
			strictCLIOptionValues(command.Argv, valueOptions)
		if wrap := parsed.values["-w"]; wrap != "" &&
			!allDecimalDigits(wrap) {
			complete = false
		}
		if wrap := parsed.values["--wrap"]; wrap != "" &&
			!allDecimalDigits(wrap) {
			complete = false
		}
		decodeBundle := false
		for _, arg := range command.Argv[1:] {
			if !isBase64DecodeBundle(arg) {
				continue
			}
			decodeBundle = true
			// Retain diagnostics for non-portable or malformed bundles. The
			// portable bundle subset returned above is authoritative.
			complete = false
		}
		if parsed.preview {
			if !complete {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			command.Effect = EffectPreview
			return
		}
		if !complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		_, shortDecode := parsed.seen["-d"]
		_, darwinDecode := parsed.seen["-D"]
		_, longDecode := parsed.seen["--decode"]
		decode := shortDecode || darwinDecode || longDecode || decodeBundle
		if !decode {
			return
		}
		addOperation(command, OperationDecode)
		if len(parsed.positionals) > 0 {
			appendPath(
				out,
				command.ID,
				PathAccessRead,
				parsed.positionals[0],
			)
			appendFileToProcessFlow(out, command.ID)
		}
		if len(parsed.positionals) > 1 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "openssl", "openssl.exe":
		classifyOpenSSLDecode(out, command)
	}
}

func classifyOpenSSLDecode(out *parseOutput, command *CommandFact) {
	if len(command.Argv) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	switch command.Argv[1] {
	case "base64", "enc":
	default:
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if openSSLDecodeHelpInvocation(command.Argv[2:]) {
		command.Effect = EffectPreview
		return
	}

	decode := false
	seenValues := make(map[string]struct{}, 2)
	for i := 2; i < len(command.Argv); i++ {
		option := command.Argv[i]
		switch option {
		case "-d":
			if decode {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			decode = true
		case "-in", "-out":
			if _, duplicate := seenValues[option]; duplicate {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			seenValues[option] = struct{}{}
			i++
			if i >= len(command.Argv) || command.Argv[i] == "" ||
				strings.HasPrefix(command.Argv[i], "-") {
				out.markPartial(IssueUnknownOperandGrammar)
				continue
			}
			if option == "-in" {
				appendPath(out, command.ID, PathAccessRead, command.Argv[i])
				appendFileToProcessFlow(out, command.ID)
			} else {
				appendPath(out, command.ID, PathAccessWrite, command.Argv[i])
				appendProcessToFileFlow(out, command.ID)
			}
		default:
			out.markPartial(IssueUnknownOperandGrammar)
		}
	}
	if !decode {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationDecode)
}

func openSSLDecodeHelpInvocation(args []string) bool {
	switch len(args) {
	case 1:
		return args[0] == "-help"
	case 2:
		return args[0] == "-d" && args[1] == "-help" ||
			args[0] == "-help" && args[1] == "-d"
	default:
		return false
	}
}

func isBase64DecodeBundle(option string) bool {
	if len(option) < 3 || option[0] != '-' || option[1] == '-' {
		return false
	}
	hasDecode := false
	for _, flag := range option[1:] {
		switch flag {
		case 'd', 'D':
			hasDecode = true
		case 'i':
		default:
			return false
		}
	}
	return hasDecode
}

func allDecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func appendFileToProcessFlow(out *parseOutput, commandID int64) {
	out.appendDataFlow(DataFlowFact{
		ToCommandID: commandID,
		From:        DataFile,
		To:          DataProcess,
	})
}

func appendProcessToFileFlow(out *parseOutput, commandID int64) {
	out.appendDataFlow(DataFlowFact{
		FromCommandID: commandID,
		From:          DataProcess,
		To:            DataFile,
	})
}

func classifySudo(out *parseOutput, command *CommandFact) {
	if len(command.Argv) == 2 {
		switch command.Argv[1] {
		case "-h", "--help", "-V", "--version":
			command.Effect = EffectPreview
			return
		case "-l", "-ll", "--list", "-s", "--shell", "-i", "--login",
			"-v", "--validate":
			addOperation(command, OperationPrivilege)
			return
		}
	}
	if len(command.Argv) > 1 {
		addOperation(command, OperationPrivilege)
		return
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

func classifyPOSIXPrivilegeShell(out *parseOutput, command *CommandFact) {
	addOperation(command, OperationPrivilege)
	exact := false
	switch command.Program {
	case "doas":
		exact = len(command.Argv) == 2 &&
			command.Argv[1] == "-s" ||
			exactPrivilegeShellArgv(command.Argv[1:])
	case "su":
		exact = len(command.Argv) == 1 ||
			len(command.Argv) == 2 &&
				(command.Argv[1] == "root" || command.Argv[1] == "-" ||
					command.Argv[1] == "-l" || command.Argv[1] == "--login") ||
			len(command.Argv) == 3 &&
				(command.Argv[1] == "-" || command.Argv[1] == "-l" ||
					command.Argv[1] == "--login") &&
				command.Argv[2] == "root"
	case "pkexec":
		exact = exactPrivilegeShellArgv(command.Argv[1:])
	}
	if !exact {
		out.markPartial(IssueUnsupportedConstruct)
	}
}

func exactPrivilegeShellArgv(argv []string) bool {
	if len(argv) == 0 || !posixShellProgram(commandProgram(argv[0])) {
		return false
	}
	for _, argument := range argv[1:] {
		switch argument {
		case "-i", "-l", "--login", "--noprofile", "--norc":
			continue
		default:
			return false
		}
	}
	return true
}

func classifySchedule(out *parseOutput, command *CommandFact, program string) {
	switch program {
	case "crontab":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet("-u", "--user"),
			exactOptionSet("-e", "-i", "-l", "-r"),
			exactOptionSet("-h", "--help", "--version"),
		)
		if parsed.preview {
			if !parsed.complete {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		_, list := parsed.seen["-l"]
		if list {
			if parsed.sawAnyExcept("-l", "-u", "--user") ||
				len(parsed.positionals) != 0 {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			addOperation(command, OperationList)
			return
		}
		addOperation(command, OperationSchedule)
		if len(parsed.positionals) > 1 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		if len(parsed.positionals) > 0 && parsed.positionals[0] != "-" {
			appendPath(
				out,
				command.ID,
				PathAccessRead,
				parsed.positionals[0],
			)
			appendFileToProcessFlow(out, command.ID)
		}
	case "at":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet("-f", "-q", "-t"),
			exactOptionSet("-b", "-c", "-d", "-l", "-m", "-M", "-r", "-v"),
			exactOptionSet("-h", "--help", "-V", "--version"),
		)
		if parsed.preview {
			command.Effect = EffectPreview
			if !parsed.complete {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		if _, list := parsed.seen["-l"]; list {
			addOperation(command, OperationList)
			return
		}
		if _, display := parsed.seen["-c"]; display {
			addOperation(command, OperationList)
			return
		}
		addOperation(command, OperationSchedule)
		if file := parsed.values["-f"]; file != "" {
			appendPath(out, command.ID, PathAccessRead, file)
			appendFileToProcessFlow(out, command.ID)
		}
	case "schtasks", "schtasks.exe":
		if !requireCommandDialect(
			out,
			command,
			DialectCMD,
			DialectPowerShell,
		) {
			return
		}
		args := make([]windowsWord, 0, len(command.Argv)-1)
		for _, value := range command.Argv[1:] {
			args = append(args, windowsWord{
				value: value,
				quote: QuoteNone,
			})
		}
		windowsClassifySchtasks(
			command,
			args,
			newWindowsFactBuilder(out),
		)
	case "launchctl":
		classifyLaunchctlSchedule(out, command)
	case "systemctl":
		valueOptions := exactOptionSet(
			"-H", "--host", "-M", "--machine", "-n", "--lines", "-o", "--output",
			"-p", "--property", "--root", "--runtime-scope", "--state",
			"-t", "--type",
		)
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			valueOptions,
			exactOptionSet(
				"-a", "--all", "--failed", "--force", "--global",
				"--no-ask-password", "--no-block", "--no-legend",
				"--no-pager", "--no-reload", "--now", "-q", "--quiet",
				"--recursive", "--runtime", "--system", "--user",
			),
			exactOptionSet("--dry-run", "--help", "--version"),
		)
		if !ownedOptionValuesArePlain(parsed, valueOptions) {
			parsed.complete = false
		}
		if parsed.preview {
			if !parsed.complete {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		if len(parsed.positionals) == 0 {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		verb := strings.ToLower(parsed.positionals[0])
		if parsed.positionals[0] != verb {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		switch verb {
		case "add-requires", "add-wants", "daemon-reload", "disable", "edit",
			"enable", "link", "mask", "preset", "reenable", "reload",
			"restart", "set-default", "start", "stop", "unmask":
			addOperation(command, OperationSchedule)
			if verb == "daemon-reload" {
				if len(parsed.positionals) != 1 {
					out.markPartial(IssueUnknownOperandGrammar)
				}
				return
			}
			if len(parsed.positionals) < 2 {
				out.markPartial(IssueUnknownOperandGrammar)
				return
			}
			if verb == "link" {
				if !parsed.complete ||
					!allStaticAbsolutePOSIXPaths(parsed.positionals[1:]) {
					out.markPartial(IssueUnknownOperandGrammar)
					return
				}
				for _, candidate := range parsed.positionals[1:] {
					appendPath(out, command.ID, PathAccessRead, candidate)
				}
				appendFileToProcessFlow(out, command.ID)
			}
		case "status", "show", "list-units", "list-unit-files", "is-active",
			"is-enabled", "cat":
			addOperation(command, OperationList)
		case "help":
			command.Effect = EffectPreview
		default:
			out.markPartial(IssueUnknownOperandGrammar)
		}
	}
}

func classifyLaunchctlSchedule(
	out *parseOutput,
	command *CommandFact,
) {
	if len(command.Argv) == 2 {
		switch command.Argv[1] {
		case "-h", "--help", "--version":
			command.Effect = EffectPreview
			return
		}
	}
	if len(command.Argv) < 2 {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	verb := command.Argv[1]
	if strings.HasPrefix(verb, "-") || verb != strings.ToLower(verb) {
		if launchctlMutationPresent(command.Argv[2:]) {
			addOperation(command, OperationSchedule)
		}
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}

	switch verb {
	case "list":
		addOperation(command, OperationList)
		if len(command.Argv) != 2 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "load", "unload":
		addOperation(command, OperationSchedule)
		paths := command.Argv[2:]
		if len(paths) == 0 || !allLaunchctlStaticOperands(paths) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		for _, candidate := range paths {
			appendPath(out, command.ID, PathAccessRead, candidate)
		}
		appendFileToProcessFlow(out, command.ID)
	case "bootstrap":
		addOperation(command, OperationSchedule)
		if len(command.Argv) < 4 ||
			!launchctlStaticOperand(command.Argv[2]) ||
			!allLaunchctlStaticOperands(command.Argv[3:]) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		for _, candidate := range command.Argv[3:] {
			appendPath(out, command.ID, PathAccessRead, candidate)
		}
		appendFileToProcessFlow(out, command.ID)
	case "bootout":
		addOperation(command, OperationSchedule)
		targets := command.Argv[2:]
		if len(targets) == 0 || !allLaunchctlStaticOperands(targets) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		switch {
		case len(targets) > 1:
			for _, candidate := range targets[1:] {
				appendPath(out, command.ID, PathAccessRead, candidate)
			}
			appendFileToProcessFlow(out, command.ID)
		case staticAbsolutePOSIXPath(targets[0]):
			appendPath(out, command.ID, PathAccessRead, targets[0])
			appendFileToProcessFlow(out, command.ID)
		}
	case "enable", "disable", "kickstart":
		addOperation(command, OperationSchedule)
		if len(command.Argv) != 3 ||
			!launchctlStaticOperand(command.Argv[2]) {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "submit":
		addOperation(command, OperationSchedule)
		out.markPartial(IssueUnknownOperandGrammar)
	case "print", "print-cache", "procinfo":
		addOperation(command, OperationList)
		out.markPartial(IssueUnknownOperandGrammar)
	default:
		if launchctlMutationPresent(command.Argv[1:]) {
			addOperation(command, OperationSchedule)
		}
		out.markPartial(IssueUnknownOperandGrammar)
	}
}

func launchctlMutationPresent(arguments []string) bool {
	for _, argument := range arguments {
		switch argument {
		case "bootstrap", "bootout", "enable", "disable", "kickstart",
			"load", "unload", "submit":
			return true
		}
	}
	return false
}

func launchctlStaticOperand(value string) bool {
	return value != "" &&
		strings.TrimSpace(value) == value &&
		!strings.HasPrefix(value, "-") &&
		!hasUnresolvedPathSyntax(value)
}

func allLaunchctlStaticOperands(values []string) bool {
	for _, value := range values {
		if !launchctlStaticOperand(value) {
			return false
		}
	}
	return true
}

func ownedOptionValuesArePlain(
	parsed ownedPOSIXOptionParse,
	valueOptions map[string]struct{},
) bool {
	for option, value := range parsed.values {
		if _, owned := valueOptions[option]; !owned {
			continue
		}
		if value == "" || value == "-" || strings.HasPrefix(value, "-") {
			return false
		}
	}
	return true
}

func allStaticAbsolutePOSIXPaths(values []string) bool {
	for _, value := range values {
		if !staticAbsolutePOSIXPath(value) {
			return false
		}
	}
	return true
}

type ownedPOSIXOptionParse struct {
	positionals             []string
	values                  map[string]string
	seen                    map[string]struct{}
	optionPositions         map[string]int
	firstPositionalPosition int
	preview                 bool
	complete                bool
	repeatedFlag            bool
}

func exactOptionSet(options ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(options))
	for _, option := range options {
		set[option] = struct{}{}
	}
	return set
}

func parseOwnedPOSIXOptions(
	argv []string,
	valueOptions map[string]struct{},
	flagOptions map[string]struct{},
	previewOptions map[string]struct{},
) ownedPOSIXOptionParse {
	result := ownedPOSIXOptionParse{
		values:                  make(map[string]string),
		seen:                    make(map[string]struct{}),
		optionPositions:         make(map[string]int),
		firstPositionalPosition: -1,
		complete:                true,
	}
	options := true
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			if result.firstPositionalPosition < 0 {
				result.firstPositionalPosition = i
			}
			result.positionals = append(result.positionals, arg)
			continue
		}

		if strings.HasPrefix(arg, "--") {
			key, joinedValue, joined := strings.Cut(arg, "=")
			if _, preview := previewOptions[key]; preview && !joined {
				result.recordOptionPosition(key, i)
				result.preview = true
				continue
			}
			if _, consumes := valueOptions[key]; consumes {
				result.recordOptionPosition(key, i)
				if _, duplicate := result.seen[key]; duplicate {
					result.complete = false
				}
				result.seen[key] = struct{}{}
				if joined {
					result.values[key] = joinedValue
					if joinedValue == "" {
						result.complete = false
					}
					continue
				}
				if i+1 >= len(argv) || argv[i+1] == "" {
					result.complete = false
					continue
				}
				i++
				result.values[key] = argv[i]
				continue
			}
			if _, flag := flagOptions[key]; flag && !joined {
				result.recordOptionPosition(key, i)
				if _, duplicate := result.seen[key]; duplicate {
					result.repeatedFlag = true
				}
				result.seen[key] = struct{}{}
				continue
			}
			result.complete = false
			continue
		}

		for offset := 1; offset < len(arg); offset++ {
			key := "-" + arg[offset:offset+1]
			if _, preview := previewOptions[key]; preview {
				result.recordOptionPosition(key, i)
				result.preview = true
				continue
			}
			if _, consumes := valueOptions[key]; consumes {
				result.recordOptionPosition(key, i)
				if _, duplicate := result.seen[key]; duplicate {
					result.complete = false
				}
				result.seen[key] = struct{}{}
				if offset+1 < len(arg) {
					value := arg[offset+1:]
					if strings.HasPrefix(value, "=") {
						value = strings.TrimPrefix(value, "=")
					}
					result.values[key] = value
					if value == "" {
						result.complete = false
					}
				} else if i+1 >= len(argv) || argv[i+1] == "" {
					result.complete = false
				} else {
					i++
					result.values[key] = argv[i]
				}
				break
			}
			if _, flag := flagOptions[key]; flag {
				result.recordOptionPosition(key, i)
				if _, duplicate := result.seen[key]; duplicate {
					result.repeatedFlag = true
				}
				result.seen[key] = struct{}{}
				continue
			}
			result.complete = false
		}
	}
	return result
}

func (p *ownedPOSIXOptionParse) recordOptionPosition(
	option string,
	position int,
) {
	if _, present := p.optionPositions[option]; !present {
		p.optionPositions[option] = position
	}
}

func (p ownedPOSIXOptionParse) sawAnyExcept(excluded ...string) bool {
	for option := range p.seen {
		exclude := false
		for _, candidate := range excluded {
			if option == candidate {
				exclude = true
				break
			}
		}
		if !exclude {
			return true
		}
	}
	return false
}

func classifyAccount(
	out *parseOutput,
	command *CommandFact,
	program string,
) {
	switch program {
	case "gpasswd":
		if len(command.Argv) == 2 &&
			(command.Argv[1] == "-h" || command.Argv[1] == "--help" ||
				command.Argv[1] == "--version") {
			command.Effect = EffectPreview
			return
		}
		if len(command.Argv) != 4 ||
			command.Argv[1] != "-a" && command.Argv[1] != "--add" ||
			!staticAccountOperand(command.Argv[2]) ||
			!staticAccountOperand(command.Argv[3]) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationAccountChange)
	case "groupmems":
		if len(command.Argv) == 2 &&
			(command.Argv[1] == "-h" || command.Argv[1] == "--help") {
			command.Effect = EffectPreview
			return
		}
		if len(command.Argv) != 5 ||
			!staticAccountOperand(command.Argv[2]) ||
			!staticAccountOperand(command.Argv[4]) ||
			!((command.Argv[1] == "-g" && command.Argv[3] == "-a") ||
				(command.Argv[1] == "-a" && command.Argv[3] == "-g")) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationAccountChange)
	case "dseditgroup":
		if !exactDSEditGroupAdd(command.Argv) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationAccountChange)
	case "dscl":
		if len(command.Argv) != 6 ||
			command.Argv[1] != "." ||
			!strings.EqualFold(command.Argv[2], "-append") ||
			!strings.HasPrefix(
				strings.ToLower(command.Argv[3]),
				"/groups/",
			) ||
			!strings.EqualFold(command.Argv[4], "groupmembership") ||
			!staticAccountOperand(command.Argv[5]) {
			out.markPartial(IssueUnknownOperandGrammar)
			return
		}
		addOperation(command, OperationAccountChange)
	case "useradd":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet(
				"-b", "--base-dir", "-c", "--comment", "-d", "--home-dir",
				"-e", "--expiredate", "-f", "--inactive", "-g", "--gid",
				"-G", "--groups", "-k", "--skel", "-K", "--key",
				"-p", "--password", "-P", "--prefix", "-R", "--root",
				"-s", "--shell", "-u", "--uid", "-Z", "--selinux-user",
			),
			exactOptionSet(
				"-D", "--defaults", "-l", "--no-log-init",
				"-m", "--create-home", "-M", "--no-create-home",
				"-N", "--no-user-group", "-o", "--non-unique",
				"-r", "--system", "-U", "--user-group",
				"--add-subids-for-system", "--badname",
				"--btrfs-subvolume-home",
			),
			exactOptionSet("-h", "--help", "--version"),
		)
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		_, shortDefaults := parsed.seen["-D"]
		_, longDefaults := parsed.seen["--defaults"]
		if shortDefaults || longDefaults {
			if len(parsed.positionals) != 0 {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			if parsed.sawAnyExcept("-D", "--defaults") {
				addOperation(command, OperationConfigChange)
			} else {
				addOperation(command, OperationList)
			}
			return
		}
		addOperation(command, OperationAccountChange)
		if len(parsed.positionals) != 1 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
	case "usermod":
		parsed := parseOwnedPOSIXOptions(
			command.Argv,
			exactOptionSet(
				"-c", "--comment", "-d", "--home", "-e", "--expiredate",
				"-f", "--inactive", "-g", "--gid", "-G", "--groups",
				"-l", "--login", "-p", "--password", "-P", "--prefix",
				"-R", "--root", "-s", "--shell", "-u", "--uid",
				"-v", "--add-subuids", "-V", "--del-subuids",
				"-w", "--add-subgids", "-W", "--del-subgids",
				"-Z", "--selinux-user",
			),
			exactOptionSet(
				"-a", "--append", "-b", "--badname", "-L", "--lock",
				"-m", "--move-home", "-o", "--non-unique",
				"-r", "--remove", "-U", "--unlock",
			),
			exactOptionSet("-h", "--help", "--version"),
		)
		if parsed.preview {
			command.Effect = EffectPreview
			return
		}
		if !parsed.complete || len(parsed.positionals) != 1 {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		addOperation(command, OperationAccountChange)
	case "adduser":
		if hasAnyArgument(command.Argv, "--help", "--version", "-h") {
			command.Effect = EffectPreview
			return
		}
		addOperation(command, OperationAccountChange)
	case "new-localuser":
		if !requireCommandDialect(out, command, DialectPowerShell) {
			return
		}
		if hasAnyArgument(
			command.Argv,
			"-?", "--help", "--version", "-h",
		) {
			command.Effect = EffectPreview
			return
		}
		addOperation(command, OperationAccountChange)
	case "net", "net.exe", "net1", "net1.exe":
		if !requireCommandDialect(
			out,
			command,
			DialectCMD,
			DialectPowerShell,
		) {
			return
		}
		if netHelpInvocation(command.Argv) {
			command.Effect = EffectPreview
			return
		}
		positionals := command.Argv[1:]
		if len(positionals) == 0 {
			return
		}
		verb := strings.ToLower(positionals[0])
		switch verb {
		case "user", "group", "localgroup":
			if netAccountMutation(positionals[1:]) {
				addOperation(command, OperationAccountChange)
			} else {
				addOperation(command, OperationList)
			}
		case "accounts":
			mutation, complete := netAccountsMode(positionals[1:])
			if !complete {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			if mutation {
				addOperation(command, OperationAccountChange)
			} else if complete {
				addOperation(command, OperationList)
			}
		}
	}
}

func exactDSEditGroupAdd(argv []string) bool {
	if len(argv) < 4 {
		return false
	}
	member := ""
	group := argv[len(argv)-1]
	if !staticAccountOperand(group) {
		return false
	}
	for index := 1; index < len(argv)-1; index++ {
		switch argv[index] {
		case "-a":
			if index+1 >= len(argv)-1 ||
				!staticAccountOperand(argv[index+1]) {
				return false
			}
			index++
			member = argv[index]
		case "-t":
			if index+1 >= len(argv)-1 ||
				!strings.EqualFold(argv[index+1], "user") {
				return false
			}
			index++
		default:
			return false
		}
	}
	return member != ""
}

func staticAccountOperand(value string) bool {
	return value != "" && !strings.HasPrefix(value, "-") &&
		!strings.ContainsAny(value, "$`*?[]{} \t\r\n")
}

func netHelpInvocation(argv []string) bool {
	if len(argv) < 2 {
		return false
	}
	first := strings.ToLower(argv[1])
	if first == "help" || first == "/help" || first == "/?" {
		return true
	}
	last := strings.ToLower(argv[len(argv)-1])
	return last == "/help" || last == "/?"
}

func netAccountMutation(arguments []string) bool {
	for _, arg := range arguments {
		lower := strings.ToLower(arg)
		if lower == "/add" || lower == "/delete" ||
			strings.HasPrefix(lower, "/active:") ||
			strings.HasPrefix(lower, "/comment:") ||
			strings.HasPrefix(lower, "/expires:") ||
			strings.HasPrefix(lower, "/fullname:") ||
			strings.HasPrefix(lower, "/homedir:") ||
			strings.HasPrefix(lower, "/passwordchg:") ||
			strings.HasPrefix(lower, "/passwordreq:") ||
			strings.HasPrefix(lower, "/profilepath:") ||
			strings.HasPrefix(lower, "/scriptpath:") ||
			strings.HasPrefix(lower, "/times:") ||
			strings.HasPrefix(lower, "/usercomment:") ||
			strings.HasPrefix(lower, "/workstations:") {
			return true
		}
	}
	if len(arguments) >= 2 {
		second := strings.ToLower(arguments[1])
		return !strings.HasPrefix(second, "/") || second == "*"
	}
	return false
}

func netAccountsMode(arguments []string) (mutation, complete bool) {
	complete = true
	domainSeen := false
	for _, arg := range arguments {
		lower := strings.ToLower(arg)
		if lower == "/domain" {
			if domainSeen {
				complete = false
			}
			domainSeen = true
			continue
		}
		key, value, joined := strings.Cut(lower, ":")
		switch key {
		case "/forcelogoff", "/maxpwage", "/minpwage", "/minpwlen",
			"/uniquepw":
			if !joined || !validNetAccountsValue(key, value) {
				complete = false
				continue
			}
			mutation = true
		default:
			complete = false
		}
	}
	return mutation, complete
}

func validNetAccountsValue(key, value string) bool {
	if value == "" || strings.ContainsAny(value, " \t\r\n/:") {
		return false
	}
	switch key {
	case "/forcelogoff":
		return value == "no" || allDecimalDigits(value)
	case "/maxpwage":
		return value == "unlimited" || allDecimalDigits(value)
	default:
		return allDecimalDigits(value)
	}
}

func classifyRedirects(out *parseOutput, command *CommandFact) {
	for _, redirect := range command.Redirects {
		if redirect.Target == "" {
			continue
		}
		if network, ok := devNetworkRedirect(command.ID, redirect.Target); ok {
			addOperation(command, OperationConnect)
			out.appendNetwork(network)
			if redirect.Access == PathAccessRead {
				to := DataProcess
				if redirect.FD == 0 {
					to = DataStdin
				}
				out.appendDataFlow(DataFlowFact{
					ToCommandID: command.ID,
					From:        DataNetwork,
					To:          to,
				})
			} else {
				from := DataProcess
				if redirect.FD == 1 || redirect.FD == -1 {
					from = DataStdout
				}
				out.appendDataFlow(DataFlowFact{
					FromCommandID: command.ID,
					From:          from,
					To:            DataNetwork,
				})
			}
			continue
		}
		flavor := pathFlavor(redirect.Target)
		if command.Dialect == DialectCMD ||
			command.Dialect == DialectPowerShell {
			flavor = windowsPathFlavor(redirect.Target)
		}
		out.appendPath(PathFact{
			CommandID: command.ID,
			Access:    redirect.Access,
			Flavor:    flavor,
			Value:     redirect.Target,
		})
		switch redirect.Access {
		case PathAccessRead:
			addOperation(command, OperationRead)
			to := DataProcess
			if redirect.FD == 0 {
				to = DataStdin
			}
			out.appendDataFlow(DataFlowFact{ToCommandID: command.ID, From: DataFile, To: to})
		case PathAccessWrite:
			addOperation(command, OperationWrite)
			from := DataProcess
			if redirect.FD == 1 || redirect.FD == -1 {
				from = DataStdout
			}
			out.appendDataFlow(DataFlowFact{FromCommandID: command.ID, From: from, To: DataFile})
		case PathAccessAppend:
			addOperation(command, OperationAppend)
			from := DataProcess
			if redirect.FD == 1 || redirect.FD == -1 {
				from = DataStdout
			}
			out.appendDataFlow(DataFlowFact{FromCommandID: command.ID, From: from, To: DataFile})
		}
	}
}

func devNetworkRedirect(commandID int64, target string) (NetworkFact, bool) {
	if target == "" || strings.TrimSpace(target) != target {
		return NetworkFact{}, false
	}
	lower := strings.ToLower(target)
	scheme := ""
	prefix := ""
	switch {
	case strings.HasPrefix(lower, "/dev/tcp/"):
		scheme = "tcp"
		prefix = "/dev/tcp/"
	case strings.HasPrefix(lower, "/dev/udp/"):
		scheme = "udp"
		prefix = "/dev/udp/"
	default:
		return NetworkFact{}, false
	}
	endpoint := target[len(prefix):]
	host, rawPort, ok := strings.Cut(endpoint, "/")
	if !ok || !validNetworkHost(host) || strings.Contains(rawPort, "/") {
		return NetworkFact{}, false
	}
	port, ok := parseNetworkPort(rawPort)
	if !ok {
		return NetworkFact{}, false
	}
	return NetworkFact{
		CommandID: commandID,
		Action:    NetworkConnect,
		Scheme:    scheme,
		Host:      strings.ToLower(host),
		Port:      port,
	}, true
}

func pathFlavor(value string) PathFlavor {
	if value == "" || strings.TrimSpace(value) != value {
		return PathFlavorUnknown
	}
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "hkey_"),
		strings.HasPrefix(lower, "hkcu\\"), strings.HasPrefix(lower, "hklm\\"):
		return PathFlavorRegistry
	case strings.HasPrefix(lower, "/dev/"), strings.HasPrefix(lower, `\\.\physicaldrive`):
		return PathFlavorDevice
	case strings.HasPrefix(value, `\\`), len(value) >= 3 &&
		isASCIILetter(value[0]) && value[1] == ':' &&
		(value[2] == '\\' || value[2] == '/'):
		return PathFlavorWindows
	case strings.HasPrefix(value, "/"), strings.HasPrefix(value, "./"),
		strings.HasPrefix(value, "../"), strings.HasPrefix(value, "~/"):
		return PathFlavorPOSIX
	case strings.Contains(value, `\`):
		return PathFlavorWindows
	default:
		return PathFlavorUnknown
	}
}

func networkURLFact(commandID int64, raw string, action NetworkAction) (NetworkFact, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return NetworkFact{}, false
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "ftp", "ftps", "ssh", "tcp", "udp", "ws", "wss":
	default:
		return NetworkFact{}, false
	}
	host, ok := canonicalNetworkHost(parsed.Hostname())
	if !ok {
		return NetworkFact{}, false
	}
	port := int64(0)
	if rawPort := parsed.Port(); rawPort != "" {
		value, ok := parseNetworkPort(rawPort)
		if !ok {
			return NetworkFact{}, false
		}
		port = value
	}
	return NetworkFact{
		CommandID: commandID,
		Action:    action,
		Scheme:    scheme,
		Host:      host,
		Port:      port,
	}, true
}

func webTargetFact(commandID int64, raw string, action NetworkAction) (NetworkFact, bool) {
	if fact, ok := networkURLFact(commandID, raw, action); ok {
		return fact, true
	}
	if raw == "" || strings.Contains(raw, "://") {
		return NetworkFact{}, false
	}
	candidate := "http://" + raw
	if strings.HasPrefix(raw, "//") {
		candidate = "http:" + raw
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.Hostname() == "" {
		return NetworkFact{}, false
	}
	host, ok := canonicalNetworkHost(parsed.Hostname())
	if !ok {
		return NetworkFact{}, false
	}
	port := int64(0)
	if rawPort := parsed.Port(); rawPort != "" {
		port, ok = parseNetworkPort(rawPort)
		if !ok {
			return NetworkFact{}, false
		}
	}
	return NetworkFact{
		CommandID: commandID,
		Action:    action,
		Scheme:    "http",
		Host:      host,
		Port:      port,
	}, true
}

func splitHostPortLoose(value string) (string, int64) {
	if value == "" || strings.TrimSpace(value) != value ||
		strings.Contains(value, "://") || strings.ContainsAny(value, `/\`) {
		return "", 0
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err == nil {
		port, ok := parseNetworkPort(rawPort)
		if ok {
			return host, port
		}
		return "", 0
	}
	if strings.Count(value, ":") == 1 {
		host, rawPort, _ = strings.Cut(value, ":")
		port, ok := parseNetworkPort(rawPort)
		if ok {
			return host, port
		}
	}
	return value, 0
}

func validNetworkHost(host string) bool {
	if host == "" || strings.TrimSpace(host) != host ||
		strings.HasPrefix(host, "-") ||
		strings.ContainsAny(host, `/\@[]`) {
		return false
	}
	_, ok := canonicalNetworkHost(host)
	return ok
}

func canonicalNetworkHost(host string) (string, bool) {
	if host == "" || strings.TrimSpace(host) != host ||
		strings.HasPrefix(host, "-") ||
		strings.ContainsAny(host, `/\@[]`) {
		return "", false
	}
	if parsed := net.ParseIP(host); parsed != nil {
		return strings.ToLower(parsed.String()), true
	}
	if parsed, ok := parseLegacyIPv4(host); ok {
		return parsed, true
	}
	if legacyIPv4Candidate(host) {
		// Numeric inet_aton-shaped hosts that exceed their component widths
		// are invalid IP spellings, not DNS names. Falling through would let
		// overflow and invalid-octal forms bypass IP scope classification.
		return "", false
	}
	if len(host) > 253 || !strings.Contains(host, ".") {
		if strings.EqualFold(host, "localhost") {
			return "localhost", true
		}
		return "", false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
				(char < '0' || char > '9') && char != '-' {
				return "", false
			}
		}
	}
	return strings.ToLower(host), true
}

func parseLegacyIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	var widths []uint
	switch len(parts) {
	case 1:
		widths = []uint{32}
	case 2:
		widths = []uint{8, 24}
	case 3:
		widths = []uint{8, 8, 16}
	case 4:
		widths = []uint{8, 8, 8, 8}
	default:
		return "", false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" {
			return "", false
		}
		base := 10
		digits := part
		switch {
		case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
			base = 16
			digits = part[2:]
		case len(part) > 1 && part[0] == '0':
			base = 8
			digits = part[1:]
		}
		if digits == "" {
			if base == 16 {
				return "", false
			}
			digits = "0"
		}
		value, err := strconv.ParseUint(digits, base, 32)
		if err != nil || value > (uint64(1)<<widths[i])-1 {
			return "", false
		}
		values[i] = value
	}
	address := values[len(values)-1]
	shift := widths[len(widths)-1]
	for i := len(values) - 2; i >= 0; i-- {
		address |= values[i] << shift
		shift += widths[i]
	}
	return net.IPv4(
		byte(address>>24),
		byte(address>>16),
		byte(address>>8),
		byte(address),
	).String(), true
}

func legacyIPv4Candidate(host string) bool {
	for _, part := range strings.Split(host, ".") {
		if part == "" {
			return false
		}
		base := 10
		digits := part
		if strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X") {
			base = 16
			digits = part[2:]
		}
		if digits == "" {
			return base == 16
		}
		for _, char := range digits {
			switch {
			case char >= '0' && char <= '9':
			case base == 16 && char >= 'a' && char <= 'f':
			case base == 16 && char >= 'A' && char <= 'F':
			default:
				return false
			}
		}
	}
	return true
}

func hasAnyArgument(argv []string, values ...string) bool {
	if len(argv) < 2 || len(values) == 0 {
		return false
	}
	needles := make(map[string]struct{}, len(values))
	for _, value := range values {
		needles[strings.ToLower(value)] = struct{}{}
	}
	for _, arg := range argv[1:] {
		if _, ok := needles[strings.ToLower(arg)]; ok {
			return true
		}
	}
	return false
}

func deduplicateFacts(out *parseOutput) {
	out.paths = deduplicate(out.paths, func(fact PathFact) string {
		return strconv.FormatInt(fact.CommandID, 10) + "\x00" + string(fact.Access) + "\x00" +
			string(fact.Flavor) + "\x00" + fact.Value
	})
	out.network = deduplicate(out.network, func(fact NetworkFact) string {
		return strconv.FormatInt(fact.CommandID, 10) + "\x00" + string(fact.Action) + "\x00" +
			fact.Scheme + "\x00" + fact.Host + "\x00" + strconv.FormatInt(fact.Port, 10)
	})
	out.dataFlows = deduplicate(out.dataFlows, func(fact DataFlowFact) string {
		return strconv.FormatInt(fact.FromCommandID, 10) + "\x00" +
			strconv.FormatInt(fact.ToCommandID, 10) + "\x00" +
			string(fact.From) + "\x00" + string(fact.To)
	})
}

func deduplicate[T any](values []T, key func(T) string) []T {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		encoded := key(value)
		if _, exists := seen[encoded]; exists {
			continue
		}
		seen[encoded] = struct{}{}
		out = append(out, value)
	}
	return out
}
