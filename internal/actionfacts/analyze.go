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

// Analyze derives a bounded, deterministic semantic projection. It never
// returns attacker-controlled parser errors and never evaluates commands,
// expands variables, reads files, or opens network connections.
func Analyze(input Input) (facts Facts) {
	defer func() {
		if recover() != nil {
			facts = Facts{
				Parse: ParseResult{
					Status:  StatusInvalid,
					Dialect: DialectNone,
					Issues:  []IssueCode{IssueInternalParserFailure},
				},
			}
		}
	}()

	return analyze(input)
}

func analyze(input Input) Facts {
	base := newParseOutput(DialectNone, 1)
	base.status = StatusNotApplicable
	for _, issue := range []IssueCode{
		validateToolName(input.Tool),
		validateScalar(input.CWD, maxScalarBytes),
		validateActiveHome(input.ActiveHome),
	} {
		if issue == "" {
			continue
		}
		if issue == IssueInputLimit {
			base.markLimit(issue)
		} else {
			base.markInvalid(issue)
		}
	}
	if base.status == StatusInvalid || base.status == StatusLimitExceeded {
		return base.factsWithContext(
			safeToolName(input.Tool),
			safeScalar(input.CWD, maxScalarBytes),
			"",
		)
	}

	extracted := extractArgsForTool(input.Args, input.Tool)
	for _, issue := range extracted.issues {
		base.addIssue(issue)
	}
	base.status = mergeParseStatus(base.status, extracted.status, base.hasFacts())
	if (extracted.command != "" || len(extracted.argv) > 0) &&
		!argsExecutionTool(input.Tool) {
		// Command-shaped fields inside an opaque tool argument object are only
		// authoritative for exact execution-capable tool schemas. Explicit
		// Input.Command and Input.Argv are normalized trusted inputs and are
		// intentionally unaffected by this gate.
		base.markPartial(IssueUnknownOperandGrammar)
	}

	command := input.Command
	if command != "" && extracted.command != "" && command != extracted.command {
		base.markAmbiguous(IssueConflictingSources)
	} else if command == "" {
		command = extracted.command
	}
	argv := cloneSlice(input.Argv)
	if len(argv) > 0 && len(extracted.argv) > 0 && !equalStrings(argv, extracted.argv) {
		base.markAmbiguous(IssueConflictingSources)
	} else if len(argv) == 0 {
		argv = cloneSlice(extracted.argv)
	}
	cwd := input.CWD
	if cwd != "" && extracted.cwd != "" && cwd != extracted.cwd {
		base.markAmbiguous(IssueConflictingSources)
	} else if cwd == "" {
		cwd = extracted.cwd
	}

	if command != "" {
		if issue := validateCommandText(command); issue != "" {
			if issue == IssueInputLimit {
				base.markLimit(issue)
			} else {
				base.markInvalid(issue)
			}
			command = ""
		}
	}
	if issue := validateArgv(argv); issue != "" {
		if issue == IssueInputLimit {
			base.markLimit(issue)
		} else {
			base.markInvalid(issue)
		}
		argv = nil
	}
	dialectHint := input.DialectHint
	if !validDialect(dialectHint) {
		base.markAmbiguous(IssueConflictingSources)
		dialectHint = DialectNone
	}

	if command != "" && len(argv) > 0 {
		matches, comparable := commandMatchesArgv(
			command,
			argv,
			input.Tool,
			dialectHint,
		)
		if comparable && !matches {
			base.markAmbiguous(IssueConflictingSources)
		} else if !comparable {
			// An unprovable comparison is not evidence of a conflict, but it
			// must still prevent the structured source from restoring
			// authority on its own.
			base.markPartial(IssueUnsupportedConstruct)
		}
	}

	startID := int64(1)
	if len(argv) > 0 {
		dialect := dialectHint
		if dialect == "" || dialect == DialectNone {
			dialect = DialectArgv
		}
		parsed := analyzeStructuredArgv(argv, startID, 0, dialect)
		classifyOutput(&parsed)
		enforceAnalyzeAuthority(&parsed)
		base.merge(parsed)
		startID = base.nextID
	}
	if command != "" && len(argv) == 0 {
		dialect, ambiguous := chooseRawCommandDialect(
			input.Tool,
			dialectHint,
			command,
		)
		if ambiguous {
			base.markAmbiguous(IssueConflictingSources)
		}
		parsed := parseCommandAs(command, dialect, startID, 0)
		classifyOutput(&parsed)
		enforceAnalyzeAuthority(&parsed)
		base.merge(parsed)
	}

	addToolArgumentFacts(&base, input.Tool, extracted)
	deduplicateFacts(&base)
	if base.hasFacts() && base.status == StatusNotApplicable {
		base.status = StatusComplete
	}
	activeHome, _ := normalizeActiveHome(input.ActiveHome)
	return base.factsWithContext(
		safeToolName(input.Tool),
		safeScalar(cwd, maxScalarBytes),
		activeHome,
	)
}

func analyzeStructuredArgv(
	argv []string,
	startID int64,
	wrapperDepth int,
	dialect Dialect,
) parseOutput {
	if !validDialect(dialect) {
		out := newParseOutput(DialectNone, startID)
		out.markAmbiguous(IssueConflictingSources)
		return out
	}
	if dialect == "" || dialect == DialectNone {
		dialect = DialectArgv
	}
	out := newParseOutput(dialect, startID)
	if len(argv) == 0 {
		out.markInvalid(IssueInvalidSyntax)
		return out
	}
	if wrapperDepth > maxWrapperDepth {
		out.markLimit(IssueWrapperLimit)
		return out
	}
	if issue := validateArgv(argv); issue != "" {
		if issue == IssueInputLimit {
			out.markLimit(issue)
		} else {
			out.markInvalid(issue)
		}
		return out
	}

	command := commandFromArgvAs(out.nextCommandID(), argv, dialect)
	if !out.appendCommand(command) {
		return out
	}
	program := command.Program
	var (
		child         parseOutput
		nestedDialect = DialectNone
	)
	switch program {
	case "env", "sudo", "command", "exec", "nsenter", "chroot":
		nestedArgv, ok, uncertain := staticPOSIXWrapperArgv(argv, program)
		if uncertain {
			out.markUnsupported(IssueUnsupportedConstruct)
			return out
		}
		if !ok {
			return out
		}
		if wrapperDepth >= maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return out
		}
		child = analyzeStructuredArgv(
			nestedArgv,
			out.nextID,
			wrapperDepth+1,
			DialectPOSIX,
		)
	case "eval":
		if len(argv) < 2 {
			return out
		}
		nested := strings.Join(argv[1:], " ")
		if strings.TrimSpace(nested) == "" {
			return out
		}
		if wrapperDepth >= maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return out
		}
		nestedDialect = DialectPOSIX
		child = parsePOSIX(nested, out.nextID, wrapperDepth+1)
	default:
		nested, dialect, ok, unsafe := nestedCommand(argv, program)
		if unsafe {
			if _, exactScript := powerShellFileOperand(argv); exactScript {
				// The script bytes remain opaque, but -NoProfile plus an exact
				// absolute -File operand proves there is no nested command text
				// to parse at this boundary. Classification publishes the path.
				return out
			}
			out.markUnsupported(IssueUnsupportedConstruct)
			return out
		}
		if !ok {
			return out
		}
		if wrapperDepth >= maxWrapperDepth {
			out.markLimit(IssueWrapperLimit)
			return out
		}
		nestedDialect = dialect
		child = parseCommandAs(nested, nestedDialect, out.nextID, wrapperDepth+1)
	}

	// Exact wrappers determine their child's grammar. The argv envelope is
	// transport structure, not a conflicting command dialect.
	if nestedDialect != DialectNone {
		out.dialect = nestedDialect
	} else if child.dialect != DialectNone && child.dialect != DialectArgv {
		out.dialect = child.dialect
	}
	attachStructuredChild(&out, command, child)
	return out
}

func attachStructuredChild(
	out *parseOutput,
	command CommandFact,
	child parseOutput,
) {
	for i := range child.commands {
		if child.commands[i].ParentCommandID == 0 {
			child.commands[i].ParentCommandID = command.ID
			child.appendDataFlow(DataFlowFact{
				FromCommandID: child.commands[i].ID,
				ToCommandID:   command.ID,
				From:          DataStdout,
				To:            DataProcess,
			})
		}
		child.commands[i].Wrappers = append(
			[]WrapperFact{{Executable: command.Executable, Argv: cloneSlice(command.Argv)}},
			child.commands[i].Wrappers...,
		)
	}
	out.merge(child)
}

func commandFromArgv(id int64, argv []string) CommandFact {
	return commandFromArgvAs(id, argv, DialectArgv)
}

func commandFromArgvAs(id int64, argv []string, dialect Dialect) CommandFact {
	arguments := make([]ArgumentFact, len(argv))
	for i, value := range argv {
		arguments[i] = ArgumentFact{Value: value, Quote: QuoteNone}
	}
	return CommandFact{
		ID:           id,
		Dialect:      dialect,
		Effect:       EffectExecute,
		Executable:   argv[0],
		Program:      commandProgramForDialect(argv[0], dialect),
		Argv:         cloneSlice(argv),
		Arguments:    arguments,
		ArgvComplete: true,
	}
}

func nestedCommand(argv []string, program string) (string, Dialect, bool, bool) {
	switch program {
	case "bash", "sh", "zsh", "dash", "ksh", "mksh":
		commandIndex, ok, unsafe := posixShellCommandIndex(argv)
		if unsafe || !ok || commandIndex >= len(argv) ||
			strings.TrimSpace(argv[commandIndex]) == "" {
			return "", DialectPOSIX, false, true
		}
		return argv[commandIndex], DialectPOSIX, true, false
	case "powershell", "pwsh", "powershell.exe", "pwsh.exe":
		// A profile can execute commands before the statically supplied body.
		// Only unwrap when that ambient startup path is exactly disabled.
		noProfileSeen := false
		for i := 1; i < len(argv); i++ {
			option := strings.ToLower(argv[i])
			switch option {
			case "-encodedcommand", "-enc", "-e", "-file", "-f":
				return "", DialectPowerShell, false, true
			case "-command", "-c":
				if !noProfileSeen || i+2 != len(argv) ||
					strings.TrimSpace(argv[i+1]) == "" ||
					argv[i+1] == "-" {
					return "", DialectPowerShell, false, true
				}
				return argv[i+1], DialectPowerShell, true, false
			case "-noprofile":
				if noProfileSeen {
					return "", DialectPowerShell, false, true
				}
				noProfileSeen = true
			case "-noninteractive", "-nologo":
				continue
			case "-workingdirectory":
				// This option changes the nested command's path-resolution
				// context. Until wrapper-local cwd is represented in Facts,
				// parsing the child against Input.CWD would publish incorrect
				// authoritative paths.
				return "", DialectPowerShell, false, true
			case "-executionpolicy":
				i++
				if i >= len(argv) || strings.TrimSpace(argv[i]) == "" {
					return "", DialectPowerShell, false, true
				}
			default:
				return "", DialectPowerShell, false, true
			}
		}
		return "", DialectPowerShell, false, true
	case "cmd", "cmd.exe":
		// Command Processor AutoRun entries execute before /c unless /d is
		// present, so the nested body is not the complete action otherwise.
		disableAutoRunSeen := false
		for i := 1; i < len(argv); i++ {
			switch strings.ToLower(argv[i]) {
			case "/k":
				return "", DialectCMD, false, true
			case "/c":
				if !disableAutoRunSeen || i+2 != len(argv) ||
					strings.TrimSpace(argv[i+1]) == "" {
					return "", DialectCMD, false, true
				}
				return argv[i+1], DialectCMD, true, false
			case "/d":
				if disableAutoRunSeen {
					return "", DialectCMD, false, true
				}
				disableAutoRunSeen = true
			case "/q", "/s":
				continue
			default:
				return "", DialectCMD, false, true
			}
		}
		return "", DialectCMD, false, true
	}
	return "", DialectNone, false, false
}

func posixShellCommandIndex(argv []string) (int, bool, bool) {
	if len(argv) < 2 {
		return 0, false, true
	}
	for i := 1; i < len(argv); i++ {
		option := argv[i]
		switch option {
		case "-c", "--command":
			if i+1 >= len(argv) {
				return 0, false, true
			}
			return i + 1, true, false
		case "--":
			return 0, false, true
		case "--login", "--noprofile", "--norc", "--posix", "--restricted":
			continue
		}
		if len(option) > 1 && option[0] == '-' && option[1] != '-' {
			valid := true
			hasCommand := false
			for _, flag := range option[1:] {
				if !strings.ContainsRune("abcefhiklmnprstuvxBCEHPT", flag) {
					valid = false
					break
				}
				hasCommand = hasCommand || flag == 'c'
			}
			if !valid {
				return 0, false, true
			}
			if hasCommand {
				if i+1 >= len(argv) {
					return 0, false, true
				}
				return i + 1, true, false
			}
			continue
		}
		return 0, false, true
	}
	return 0, false, true
}

func parseCommandAs(source string, dialect Dialect, startID int64, wrapperDepth int) parseOutput {
	switch dialect {
	case DialectPowerShell:
		return parsePowerShell(source, startID, wrapperDepth)
	case DialectCMD:
		return parseCMD(source, startID, wrapperDepth)
	case DialectPOSIX, DialectNone:
		return parsePOSIX(source, startID, wrapperDepth)
	default:
		out := newParseOutput(dialect, startID)
		out.markUnsupported(IssueUnsupportedConstruct)
		return out
	}
}

func argsExecutionTool(tool string) bool {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return false
	}
	name := strings.ToLower(tool)
	if genericRawExecutionTool(name) {
		return true
	}
	switch name {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe",
		"cmd", "cmd.exe",
		"bash", "sh", "zsh", "dash", "ksh", "mksh", "fish":
		return true
	default:
		return false
	}
}

func addToolArgumentFacts(out *parseOutput, tool string, extracted extractedInput) {
	if len(extracted.paths) == 0 && len(extracted.urls) == 0 &&
		len(extracted.patchChanges) == 0 && extracted.method == "" &&
		len(extracted.payload) == 0 {
		return
	}
	// Malformed or conflicting argument objects may retain statically safe
	// scalar fragments, but they cannot establish a complete tool schema.
	// Preserve the existing parse status without manufacturing tool semantics.
	if extracted.status != StatusComplete {
		return
	}
	semantics, known := lookupToolArgumentSemantics(tool)
	if !known {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	hasOutboundPayload := extractedHasOutboundPayload(extracted.payload)
	hasOutboundBody := extractedHasOutboundBody(extracted.payload)
	badMethod := extracted.method != "" &&
		(!semantics.acceptsMethod || !knownHTTPMethod(extracted.method))
	missingPayload := semantics.requiresPayload && !hasOutboundBody
	if badMethod ||
		!toolPayloadFieldsAllowed(extracted.payload, semantics) ||
		missingPayload {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if semantics.acceptsHTTPPayload && hasOutboundPayload {
		semantics.networkAction = NetworkUpload
		semantics.networkOperation = OperationUpload
		semantics.flow = toolFlowPayloadUpload
	}

	projectedPaths, pathsValid := projectToolPaths(extracted, semantics)
	hasPaths := len(projectedPaths) > 0
	hasURLs := len(extracted.urls) > 0 && semantics.acceptsURLs
	if !pathsValid ||
		len(extracted.paths) > 0 && !semantics.acceptsPaths ||
		len(extracted.urls) > 0 && !semantics.acceptsURLs ||
		semantics.requiresPaths && !hasPaths ||
		semantics.requiresURLs && !hasURLs {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	if !hasPaths && !hasURLs {
		return
	}
	if len(out.commands) > 0 {
		out.markAmbiguous(IssueConflictingSources)
		return
	}

	toolArgv := []string{tool}
	if issue := validateArgv(toolArgv); issue != "" {
		if issue == IssueInputLimit {
			out.markLimit(issue)
		} else {
			out.markInvalid(issue)
		}
		return
	}
	command := commandFromArgv(out.nextCommandID(), toolArgv)
	addToolOperations(&command, semantics, extracted, projectedPaths, hasURLs)
	addOperation(&command, OperationExecute)
	if !out.appendCommand(command) {
		return
	}
	commandID := command.ID
	if out.dialect == DialectNone {
		out.dialect = DialectArgv
	}

	if hasPaths {
		for _, path := range projectedPaths {
			out.appendPath(PathFact{
				CommandID: commandID,
				Access:    path.access,
				Flavor:    pathFlavor(path.value),
				Value:     path.value,
			})
		}
	}
	if hasURLs {
		for _, rawURL := range extracted.urls {
			if fact, ok := networkURLFact(commandID, rawURL, semantics.networkAction); ok {
				out.appendNetwork(fact)
			} else {
				out.markPartial(IssueUnknownOperandGrammar)
			}
		}
	}
	if hasURLs && semantics.flow == toolFlowPayloadUpload {
		out.appendDataFlow(DataFlowFact{
			FromCommandID: commandID,
			From:          DataProcess,
			To:            DataNetwork,
		})
	} else if hasPaths && semantics.flow == toolFlowFileTransfer {
		out.appendDataFlow(DataFlowFact{
			ToCommandID: commandID,
			From:        DataFile,
			To:          DataProcess,
		})
		out.appendDataFlow(DataFlowFact{
			FromCommandID: commandID,
			From:          DataProcess,
			To:            DataFile,
		})
	} else if hasPaths && hasURLs {
		switch semantics.flow {
		case toolFlowUpload:
			out.appendDataFlow(DataFlowFact{
				ToCommandID: commandID,
				From:        DataFile,
				To:          DataProcess,
			})
			out.appendDataFlow(DataFlowFact{
				FromCommandID: commandID,
				From:          DataProcess,
				To:            DataNetwork,
			})
		case toolFlowDownload:
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
	}
	enforceAnalyzeAuthority(out)
}

type toolFlow uint8

const (
	toolFlowNone toolFlow = iota
	toolFlowUpload
	toolFlowDownload
	toolFlowPayloadUpload
	toolFlowFileTransfer
)

type toolPathShape uint8

const (
	toolPathNone toolPathShape = iota
	toolPathInput
	toolPathOutput
	toolPathTarget
	toolPathCopy
	toolPathMove
	toolPathPatch
)

type projectedToolPath struct {
	access PathAccess
	value  string
}

type toolArgumentSemantics struct {
	acceptsPaths       bool
	pathAccess         PathAccess
	pathOperation      OperationKind
	pathShape          toolPathShape
	acceptsURLs        bool
	networkAction      NetworkAction
	networkOperation   OperationKind
	requiresPaths      bool
	requiresURLs       bool
	requiresPayload    bool
	acceptsMethod      bool
	acceptsHTTPPayload bool
	acceptsContent     bool
	flow               toolFlow
}

func lookupToolArgumentSemantics(tool string) (toolArgumentSemantics, bool) {
	if tool == "" || strings.TrimSpace(tool) != tool {
		return toolArgumentSemantics{}, false
	}
	switch strings.ToLower(tool) {
	case "read",
		"readfile", "read_file", "read-file",
		"fsread", "fs_read", "fs-read", "fs.read", "fs.read_file",
		"fileread", "file_read", "file-read",
		"catfile", "cat_file", "cat-file",
		"openfile", "open_file", "open-file",
		"viewfile", "view_file", "view-file",
		"getfile", "get_file", "get-file":
		return pathToolSemantics(PathAccessRead, OperationRead), true
	case "applypatch", "apply_patch", "apply-patch":
		return toolArgumentSemantics{
			acceptsPaths:  true,
			pathShape:     toolPathPatch,
			requiresPaths: true,
		}, true
	case "write", "edit",
		"multiedit", "multi_edit", "multi-edit",
		"notebookedit", "notebook_edit", "notebook-edit",
		"writefile", "write_file", "write-file",
		"fswrite", "fs_write", "fs-write", "fs.write", "fs.write_file",
		"filewrite", "file_write", "file-write",
		"createfile", "create_file", "create-file",
		"editfile", "edit_file", "edit-file":
		semantics := pathToolSemantics(PathAccessWrite, OperationWrite)
		semantics.acceptsContent = true
		return semantics, true
	case "appendfile", "append_file", "append-file":
		semantics := pathToolSemantics(PathAccessAppend, OperationAppend)
		semantics.acceptsContent = true
		return semantics, true
	case "deletefile", "delete_file", "delete-file",
		"removefile", "remove_file", "remove-file":
		return pathToolSemantics(PathAccessDelete, OperationDelete), true
	case "listfiles", "list_files", "list-files",
		"listdirectory", "list_directory", "list-directory":
		return pathToolSemantics(PathAccessList, OperationList), true
	case "search",
		"searchfiles", "search_files", "search-files",
		"filesearch", "file_search", "file-search",
		"glob", "globfiles", "glob_files", "glob-files":
		return pathToolSemantics(PathAccessRead, OperationSearch), true
	case "copyfile", "copy_file", "copy-file":
		return transferPathToolSemantics(OperationCopy, toolPathCopy), true
	case "movefile", "move_file", "move-file":
		return transferPathToolSemantics(OperationMove, toolPathMove), true
	case "webfetch", "web_fetch", "web-fetch",
		"httpfetch", "http_fetch", "http-fetch",
		"fetch",
		"fetchurl", "fetch_url", "fetch-url",
		"urlfetch", "url_fetch", "url-fetch",
		"httpget", "http_get", "http-get", "http.get":
		return networkToolSemantics(NetworkDownload, OperationFetch), true
	case "httprequest", "http_request", "http-request":
		semantics := networkToolSemantics(NetworkConnect, OperationConnect)
		semantics.acceptsMethod = true
		semantics.acceptsHTTPPayload = true
		return semantics, true
	case "webupload", "web_upload", "web-upload",
		"uploadurl", "upload_url", "upload-url",
		"httppost", "http_post", "http-post":
		semantics := networkToolSemantics(NetworkUpload, OperationUpload)
		semantics.acceptsMethod = true
		semantics.acceptsHTTPPayload = true
		semantics.requiresPayload = true
		return semantics, true
	case "uploadfile", "upload_file", "upload-file":
		return toolArgumentSemantics{
			acceptsPaths:     true,
			pathAccess:       PathAccessRead,
			pathOperation:    OperationRead,
			pathShape:        toolPathInput,
			acceptsURLs:      true,
			networkAction:    NetworkUpload,
			networkOperation: OperationUpload,
			requiresPaths:    true,
			requiresURLs:     true,
			flow:             toolFlowUpload,
		}, true
	case "downloadfile", "download_file", "download-file":
		return toolArgumentSemantics{
			acceptsPaths:     true,
			pathAccess:       PathAccessWrite,
			pathOperation:    OperationWrite,
			pathShape:        toolPathOutput,
			acceptsURLs:      true,
			networkAction:    NetworkDownload,
			networkOperation: OperationFetch,
			requiresPaths:    true,
			requiresURLs:     true,
			flow:             toolFlowDownload,
		}, true
	default:
		return toolArgumentSemantics{}, false
	}
}

func pathToolSemantics(access PathAccess, operation OperationKind) toolArgumentSemantics {
	shape := toolPathTarget
	switch access {
	case PathAccessRead, PathAccessList:
		shape = toolPathInput
	case PathAccessWrite, PathAccessAppend:
		shape = toolPathOutput
	}
	return toolArgumentSemantics{
		acceptsPaths:  true,
		pathAccess:    access,
		pathOperation: operation,
		pathShape:     shape,
		requiresPaths: true,
	}
}

func transferPathToolSemantics(
	operation OperationKind,
	shape toolPathShape,
) toolArgumentSemantics {
	return toolArgumentSemantics{
		acceptsPaths:  true,
		pathOperation: operation,
		pathShape:     shape,
		requiresPaths: true,
		flow:          toolFlowFileTransfer,
	}
}

func networkToolSemantics(action NetworkAction, operation OperationKind) toolArgumentSemantics {
	return toolArgumentSemantics{
		acceptsURLs:      true,
		networkAction:    action,
		networkOperation: operation,
		requiresURLs:     true,
	}
}

func toolPayloadFieldsAllowed(
	fields []extractedPayload,
	semantics toolArgumentSemantics,
) bool {
	for _, field := range fields {
		switch field.key {
		case "content":
			if !semantics.acceptsContent && !semantics.acceptsHTTPPayload {
				return false
			}
		case "body", "data", "payload", "headers":
			if !semantics.acceptsHTTPPayload {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func extractedHasOutboundPayload(fields []extractedPayload) bool {
	for _, field := range fields {
		if field.nonEmpty {
			return true
		}
	}
	return false
}

func extractedHasOutboundBody(fields []extractedPayload) bool {
	for _, field := range fields {
		if field.key != "headers" && field.nonEmpty {
			return true
		}
	}
	return false
}

func knownHTTPMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS",
		"CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func projectToolPaths(
	extracted extractedInput,
	semantics toolArgumentSemantics,
) ([]projectedToolPath, bool) {
	switch semantics.pathShape {
	case toolPathNone:
		return nil, len(extracted.paths) == 0
	case toolPathInput:
		path, ok := extracted.singlePathArgument("path", "filepath", "target", "source")
		if !ok {
			return nil, false
		}
		return []projectedToolPath{{access: semantics.pathAccess, value: path.value}}, true
	case toolPathOutput:
		path, ok := extracted.singlePathArgument("path", "filepath", "target", "destination")
		if !ok {
			return nil, false
		}
		return []projectedToolPath{{access: semantics.pathAccess, value: path.value}}, true
	case toolPathTarget:
		path, ok := extracted.singlePathArgument("path", "filepath", "target")
		if !ok {
			return nil, false
		}
		return []projectedToolPath{{access: semantics.pathAccess, value: path.value}}, true
	case toolPathCopy, toolPathMove:
		source, destination, ok := extracted.sourceDestinationArguments()
		if !ok {
			return nil, false
		}
		paths := []projectedToolPath{
			{access: PathAccessRead, value: source},
			{access: PathAccessWrite, value: destination},
		}
		if semantics.pathShape == toolPathMove {
			paths = append(paths, projectedToolPath{
				access: PathAccessDelete,
				value:  source,
			})
		}
		return paths, true
	case toolPathPatch:
		if !extracted.patchSet || len(extracted.patchChanges) == 0 ||
			len(extracted.paths) != 0 {
			return nil, false
		}
		paths := make([]projectedToolPath, 0, len(extracted.patchChanges))
		for _, change := range extracted.patchChanges {
			paths = append(paths, projectedToolPath{
				access: change.access,
				value:  change.path,
			})
		}
		return paths, true
	default:
		return nil, false
	}
}

func addToolOperations(
	command *CommandFact,
	semantics toolArgumentSemantics,
	extracted extractedInput,
	paths []projectedToolPath,
	hasURLs bool,
) {
	if semantics.pathShape == toolPathPatch {
		for _, candidate := range paths {
			switch candidate.access {
			case PathAccessWrite:
				addOperation(command, OperationWrite)
			case PathAccessDelete:
				addOperation(command, OperationDelete)
			}
		}
		if extracted.patchMove {
			addOperation(command, OperationMove)
		}
	} else if len(paths) > 0 {
		addOperation(command, semantics.pathOperation)
	}
	if hasURLs {
		addOperation(command, semantics.networkOperation)
	}
}

func validateArgv(argv []string) IssueCode {
	if len(argv) == 0 {
		return ""
	}
	if len(argv) > maxArgvItems {
		return IssueInputLimit
	}
	total := 0
	for _, arg := range argv {
		if !utf8.ValidString(arg) {
			return IssueInvalidUTF8
		}
		if len(arg) > maxScalarBytes {
			return IssueInputLimit
		}
		if strings.IndexByte(arg, 0) >= 0 {
			return IssueInvalidSyntax
		}
		total += len(arg)
		if total > maxArgvBytes {
			return IssueInputLimit
		}
	}
	if strings.TrimSpace(argv[0]) == "" || strings.TrimSpace(argv[0]) != argv[0] {
		return IssueInvalidSyntax
	}
	return ""
}

func commandMatchesArgv(
	command string,
	argv []string,
	tool string,
	hint Dialect,
) (match bool, comparable bool) {
	if len(argv) == 0 {
		return false, false
	}
	// Mixed raw grammar signals affect whether a command-only input is
	// authoritative, but they do not by themselves prove that two supplied
	// representations conflict. Use the inferred owner solely to compare the
	// raw command with the trusted argv structure.
	dialect, _ := chooseRawCommandDialect(tool, hint, command)
	nested, _, ok, unsafe := nestedCommand(
		argv,
		commandProgramForDialect(argv[0], dialect),
	)
	if unsafe {
		// An opaque wrapper cannot prove that its raw and structured sources
		// conflict. It also cannot let the structured source restore
		// authority, so keep the comparison fail-closed and incomparable.
		return false, false
	}
	if ok && nested == command {
		return true, true
	}
	parsed := parseCommandAs(command, dialect, 1, 0)
	structured := analyzeStructuredArgv(argv, 1, 0, dialect)
	classifyOutput(&parsed)
	classifyOutput(&structured)
	if parsed.status == StatusComplete &&
		structured.status == StatusComplete {
		return equivalentCommandStructure(parsed, structured), true
	}
	if !staticCommandStructureComparable(parsed) ||
		!staticCommandStructureComparable(structured) {
		return false, false
	}
	if !equivalentStaticCommandStructure(parsed, structured) {
		return false, true
	}
	// Equal static argv is insufficient to prove semantic equivalence when
	// either source used unsupported syntax. Keep the action non-authoritative
	// without incorrectly labelling the sources as conflicting.
	return false, false
}

// A partial semantic classification can still have fully static command
// structure. That structure is safe to compare even when unsupported operands
// prevent comparison of the derived path, network, or operation projections.
func staticCommandStructureComparable(out parseOutput) bool {
	switch out.status {
	case StatusComplete, StatusPartial:
	default:
		return false
	}
	if len(out.commands) == 0 {
		return false
	}
	for _, command := range out.commands {
		if (command.Kind != "" && command.Kind != CommandKindProcess) ||
			!command.ArgvComplete {
			return false
		}
	}
	return true
}

func equivalentStaticCommandStructure(left, right parseOutput) bool {
	if len(left.commands) != len(right.commands) {
		return false
	}
	for index := range left.commands {
		leftCommand := left.commands[index]
		rightCommand := right.commands[index]
		if leftCommand.ID != rightCommand.ID ||
			leftCommand.ParentCommandID != rightCommand.ParentCommandID ||
			leftCommand.PipelineID != rightCommand.PipelineID ||
			leftCommand.Kind != rightCommand.Kind ||
			leftCommand.Dialect != rightCommand.Dialect ||
			leftCommand.Effect != rightCommand.Effect ||
			!equivalentCommandExecutable(
				leftCommand.Executable,
				rightCommand.Executable,
				leftCommand.Dialect,
			) ||
			!equivalentCommandArgv(
				leftCommand.Argv,
				rightCommand.Argv,
				leftCommand.Dialect,
			) ||
			!equalComparableSlices(
				leftCommand.Redirects,
				rightCommand.Redirects,
			) ||
			len(leftCommand.Wrappers) != len(rightCommand.Wrappers) {
			return false
		}
		for wrapperIndex := range leftCommand.Wrappers {
			leftWrapper := leftCommand.Wrappers[wrapperIndex]
			rightWrapper := rightCommand.Wrappers[wrapperIndex]
			if !equivalentCommandExecutable(
				leftWrapper.Executable,
				rightWrapper.Executable,
				leftCommand.Dialect,
			) ||
				!equivalentCommandArgv(
					leftWrapper.Argv,
					rightWrapper.Argv,
					leftCommand.Dialect,
				) {
				return false
			}
		}
	}
	return true
}

func equivalentCommandExecutable(left, right string, dialect Dialect) bool {
	switch dialect {
	case DialectPowerShell, DialectCMD:
		return equivalentWindowsExecutableIdentity(left, right)
	default:
		return left == right
	}
}

func equivalentWindowsExecutableIdentity(left, right string) bool {
	if left == "" || right == "" {
		return left == right
	}
	if strings.TrimSpace(left) != left ||
		strings.TrimSpace(right) != right {
		return false
	}

	leftPath, leftIsPath := comparableWindowsExecutablePath(left)
	rightPath, rightIsPath := comparableWindowsExecutablePath(right)
	if leftIsPath || rightIsPath {
		// Full paths are comparable only inside the parser's closed trusted
		// executable roots. This permits a trusted resolved argv0 to agree
		// with its basename without equating arbitrary same-named binaries.
		if leftIsPath && !trustedExecutablePath(leftPath) ||
			rightIsPath && !trustedExecutablePath(rightPath) {
			return false
		}
		if leftIsPath && rightIsPath {
			return strings.EqualFold(leftPath, rightPath)
		}
	}

	leftBase := windowsExecutable(left)
	rightBase := windowsExecutable(right)
	return leftBase != "" && rightBase != "" &&
		strings.EqualFold(leftBase, rightBase)
}

func comparableWindowsExecutablePath(value string) (string, bool) {
	normalized := strings.ReplaceAll(value, `\`, "/")
	isPath := strings.Contains(normalized, "/") ||
		len(normalized) >= 2 &&
			isASCIILetter(normalized[0]) &&
			normalized[1] == ':'
	return normalized, isPath
}

func equivalentCommandArgv(left, right []string, dialect Dialect) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if index == 0 &&
			equivalentCommandExecutable(
				left[index],
				right[index],
				dialect,
			) {
			continue
		}
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equivalentCommandStructure(left, right parseOutput) bool {
	if len(left.commands) != len(right.commands) ||
		!equalComparableSlices(left.paths, right.paths) ||
		!equalComparableSlices(left.network, right.network) ||
		!equalComparableSlices(left.dataFlows, right.dataFlows) {
		return false
	}
	for index := range left.commands {
		if !equivalentCommandFact(left.commands[index], right.commands[index]) {
			return false
		}
	}
	return true
}

func equivalentCommandFact(left, right CommandFact) bool {
	if left.ID != right.ID ||
		left.ParentCommandID != right.ParentCommandID ||
		left.PipelineID != right.PipelineID ||
		left.Kind != right.Kind ||
		left.Dialect != right.Dialect ||
		left.Effect != right.Effect ||
		!equivalentCommandExecutable(
			left.Executable,
			right.Executable,
			left.Dialect,
		) ||
		left.Program != right.Program ||
		left.ArgvComplete != right.ArgvComplete ||
		!equivalentCommandArgv(left.Argv, right.Argv, left.Dialect) ||
		!equalComparableSlices(left.Operations, right.Operations) ||
		!equalComparableSlices(left.Redirects, right.Redirects) ||
		len(left.Arguments) != len(right.Arguments) ||
		len(left.Wrappers) != len(right.Wrappers) {
		return false
	}
	for index := range left.Arguments {
		valuesEqual := left.Arguments[index].Value ==
			right.Arguments[index].Value
		if index == 0 {
			valuesEqual = equivalentCommandExecutable(
				left.Arguments[index].Value,
				right.Arguments[index].Value,
				left.Dialect,
			)
		}
		if !valuesEqual ||
			left.Arguments[index].Expands != right.Arguments[index].Expands {
			return false
		}
	}
	for index := range left.Wrappers {
		if !equivalentCommandExecutable(
			left.Wrappers[index].Executable,
			right.Wrappers[index].Executable,
			left.Dialect,
		) ||
			!equivalentCommandArgv(
				left.Wrappers[index].Argv,
				right.Wrappers[index].Argv,
				left.Dialect,
			) {
			return false
		}
	}
	return true
}

func equalComparableSlices[T comparable](left, right []T) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func enforceAnalyzeAuthority(out *parseOutput) {
	for index := range out.commands {
		command := &out.commands[index]
		if command.ArgvComplete {
			if issue := validateArgv(command.Argv); issue != "" {
				command.ArgvComplete = false
				command.Executable = ""
				command.Program = ""
				command.Effect = EffectUncertain
				command.Operations = nil
				if issue == IssueInputLimit {
					out.markLimit(issue)
				} else {
					out.markInvalid(issue)
				}
				continue
			}
		}
		expectedProgram := commandProgramForDialect(
			command.Executable,
			command.Dialect,
		)
		if command.Executable != "" &&
			(command.Program == "" || command.Program != expectedProgram) {
			command.Program = ""
			command.Effect = EffectUncertain
			out.markPartial(IssueUnknownOperandGrammar)
		}
		if command.Effect == EffectUncertain {
			out.markPartial(IssueUnsupportedConstruct)
		}
		switch command.Program {
		case "source", ".":
			out.markPartial(IssueOpaqueArtifact)
		case "bash", "sh", "zsh", "dash", "ksh", "mksh":
			if _, commandMode, unsafe := posixShellCommandIndex(command.Argv); commandMode && !unsafe {
				continue
			} else if _, script := exactPOSIXShellScriptOperand(command.Argv); script {
				out.markPartial(IssueOpaqueArtifact)
			} else if _, script := shellScriptOperand(command.Argv); script {
				out.markPartial(IssueOpaqueArtifact)
				out.markPartial(IssueUnsupportedConstruct)
			} else if unsafe || !commandMode {
				out.markPartial(IssueUnsupportedConstruct)
			}
		case "fish":
			out.markPartial(IssueUnsupportedConstruct)
		case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe":
			if _, script := powerShellFileOperand(command.Argv); script {
				out.markPartial(IssueOpaqueArtifact)
				continue
			}
			_, _, ok, unsafe := nestedCommand(
				command.Argv,
				command.Program,
			)
			if unsafe || !ok {
				out.markPartial(IssueUnsupportedConstruct)
			}
		}
	}
}

func validDialect(dialect Dialect) bool {
	switch dialect {
	case "", DialectNone, DialectArgv, DialectPOSIX, DialectPowerShell, DialectCMD:
		return true
	default:
		return false
	}
}

func validateScalar(value string, max int) IssueCode {
	if len(value) > max {
		return IssueInputLimit
	}
	if !utf8.ValidString(value) {
		return IssueInvalidUTF8
	}
	if strings.IndexByte(value, 0) >= 0 {
		return IssueInvalidSyntax
	}
	return ""
}

func validateToolName(value string) IssueCode {
	if issue := validateScalar(value, maxScalarBytes); issue != "" {
		return issue
	}
	if value != "" && strings.TrimSpace(value) != value {
		return IssueInvalidSyntax
	}
	return ""
}

func validScalar(value string, max int) bool {
	return validateScalar(value, max) == ""
}

func validateCommandText(value string) IssueCode {
	if len(value) > maxCommandBytes {
		return IssueInputLimit
	}
	if !utf8.ValidString(value) {
		return IssueInvalidUTF8
	}
	if strings.TrimSpace(value) == "" {
		return IssueInvalidSyntax
	}
	for _, char := range value {
		if unicode.IsControl(char) && char != '\t' && char != '\n' && char != '\r' {
			return IssueInvalidSyntax
		}
	}
	return ""
}

func safeScalar(value string, max int) string {
	if !validScalar(value, max) {
		return ""
	}
	return value
}

func safeToolName(value string) string {
	if validateToolName(value) != "" {
		return ""
	}
	return value
}
