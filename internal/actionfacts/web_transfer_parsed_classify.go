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

import "strings"

type curlTransferProjection struct {
	hasTarget          bool
	upload             bool
	hasUploadTarget    bool
	hasDownloadTarget  bool
	hasUploadNetwork   bool
	hasDownloadNetwork bool
	hasUploadFile      bool
	hasUploadStdin     bool
	hasProcessUpload   bool
	hasDownloadFile    bool

	hasCookieJar bool
	cookieJar    string
	hasDump      bool
	dumpHeader   string
	hasUnix      bool
	unixSocket   string
	hasOutputDir bool
	outputDir    string
	hasCACert    bool
	cacert       string
	hasKey       bool
	key          string
}

// StaticCurlUploadPayloads returns the literal inline request-body operands
// that a complete curl command sends. File and stdin upload sources are
// deliberately excluded: their contents are not represented by argv. Multiple
// --next groups are also excluded because CommandFact does not retain the
// per-group network destination needed to prove which body reaches which peer.
func StaticCurlUploadPayloads(command CommandFact) []string {
	if !command.ArgvComplete || !isCurlProgram(command.Program) ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 {
		return nil
	}

	group := parsed.Targets[0].Group
	for _, target := range parsed.Targets[1:] {
		if target.Group != group {
			return nil
		}
	}

	var payloads []string
	for _, option := range parsed.Options {
		if option.Group != group || !option.ValuePresent {
			continue
		}
		value, literal := staticCurlUploadPayload(option)
		if !literal {
			continue
		}
		argumentIndex := option.ValueArgvIndex
		if option.ValueJoined {
			argumentIndex = option.ArgvIndex
		}
		if argumentIndex < 0 || argumentIndex >= len(command.Arguments) {
			return nil
		}
		argument := command.Arguments[argumentIndex]
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[argumentIndex] {
			return nil
		}
		payloads = append(payloads, value)
	}
	return payloads
}

func staticCurlUploadPayload(option curlOptionToken) (string, bool) {
	value := option.Value
	switch option.Canonical {
	case "--data", "--data-ascii", "--data-binary", "--json":
		if _, _, fileSource := webDataFile(value); fileSource {
			return "", false
		}
		return value, value != ""
	case "--data-urlencode":
		_, _, fileSource, valid := curlDataURLEncodeFile(value)
		return value, valid && !fileSource && value != ""
	case "--data-raw", "--form-string":
		return value, value != ""
	case "--form":
		if curlFormHasUnmodeledFileReference(value) {
			return "", false
		}
		if _, _, fileSource := webFormFile(value); fileSource {
			return "", false
		}
		return value, value != ""
	default:
		return "", false
	}
}

func classifyParsedCurlTransfer(out *parseOutput, command *CommandFact) {
	parsed := parseCurlArgv(command.Argv)
	valid := parsed.Complete && !parsed.EmptyTransferGroup &&
		parsed.hasValidOptionValues()
	if !valid {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if parsed.Preview {
		command.Effect = EffectPreview
		return
	}
	if len(parsed.Targets) == 0 {
		out.markPartial(IssueUnknownOperandGrammar)
	}

	groupCount := 1
	for _, option := range parsed.Options {
		groupCount = max(groupCount, option.Group+1)
	}
	for _, target := range parsed.Targets {
		groupCount = max(groupCount, target.Group+1)
	}
	groups := make([]curlTransferProjection, groupCount)

	for _, option := range parsed.Options {
		if !option.ValuePresent {
			continue
		}
		group := &groups[option.Group]
		value := option.Value
		switch option.Canonical {
		case "--config":
			if value != "" && value != "-" {
				appendCommandPath(out, command, PathAccessRead, value)
			}
			out.markPartial(IssueUnknownOperandGrammar)
		case "--data", "--data-ascii", "--data-binary", "--json":
			group.upload = true
			if path, stdin, ok := webDataFile(value); ok {
				if stdin {
					group.hasUploadStdin = true
				} else {
					appendCommandPath(out, command, PathAccessRead, path)
					group.hasUploadFile = true
				}
			} else {
				group.hasProcessUpload = true
			}
		case "--data-urlencode":
			group.upload = true
			path, stdin, fileForm, grammarValid :=
				curlDataURLEncodeFile(value)
			switch {
			case !grammarValid:
				out.markPartial(IssueUnknownOperandGrammar)
			case !fileForm:
				group.hasProcessUpload = true
			case stdin:
				group.hasUploadStdin = true
			default:
				appendCommandPath(out, command, PathAccessRead, path)
				group.hasUploadFile = true
			}
		case "--data-raw", "--form-string":
			group.upload = true
			group.hasProcessUpload = true
		case "--form":
			group.upload = true
			if curlFormHasUnmodeledFileReference(value) {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			if path, stdin, ok := webFormFile(value); ok {
				if stdin {
					group.hasUploadStdin = true
				} else {
					appendCommandPath(out, command, PathAccessRead, path)
					group.hasUploadFile = true
				}
			} else if value != "" {
				group.hasProcessUpload = true
			}
		case "--header":
			if !strings.HasPrefix(value, "@") {
				continue
			}
			group.upload = true
			headerFile := strings.TrimPrefix(value, "@")
			switch headerFile {
			case "":
				out.markPartial(IssueUnknownOperandGrammar)
			case "-":
				group.hasUploadStdin = true
			default:
				appendCommandPath(out, command, PathAccessRead, headerFile)
				group.hasUploadFile = true
			}
		case "--cookie-jar":
			group.hasCookieJar = true
			group.cookieJar = value
		case "--cookie":
			// Curl merges repeated cookie inputs, so every file-shaped value is
			// an effective read rather than last-value state.
			if value != "" && value != "-" && !containsCookieLiteral(value) {
				appendCommandPath(out, command, PathAccessRead, value)
			}
		case "--dump-header":
			group.hasDump = true
			group.dumpHeader = value
		case "--unix-socket":
			group.hasUnix = true
			group.unixSocket = value
		case "--output-dir":
			group.hasOutputDir = true
			group.outputDir = value
			out.markPartial(IssueUnsupportedConstruct)
		case "--cacert":
			group.hasCACert = true
			group.cacert = value
		case "--key":
			group.hasKey = true
			group.key = value
		case "--cert":
			// A certificate operand may include a password suffix. Until that
			// grammar is represented, retain it as diagnostic-only context.
			out.markPartial(IssueUnknownOperandGrammar)
		case "--connect-to", "--dns-servers", "--doh-url", "--preproxy",
			"--proxy", "--proxy1.0", "--resolve", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname":
			// These options can replace the actual peer while leaving the
			// logical URL unchanged.
			out.markPartial(IssueUnsupportedConstruct)
		}
	}

	for index := range groups {
		group := &groups[index]
		for _, input := range []struct {
			set   bool
			value string
		}{
			{set: group.hasCACert, value: group.cacert},
			{set: group.hasKey, value: group.key},
		} {
			if input.set && input.value != "" && input.value != "-" {
				appendCommandPath(out, command, PathAccessRead, input.value)
			}
		}
		if group.hasUnix {
			if !staticAbsolutePOSIXPath(group.unixSocket) {
				out.markPartial(IssueUnknownOperandGrammar)
			} else {
				addOperation(command, OperationConnect)
				appendCommandPath(out, command, PathAccessConnect, group.unixSocket)
			}
		}
		if valid && group.hasCookieJar && group.cookieJar != "" &&
			group.cookieJar != "-" {
			appendCommandPath(out, command, PathAccessWrite, group.cookieJar)
			group.hasDownloadFile = true
		}
		if valid && group.hasDump && group.dumpHeader != "" &&
			group.dumpHeader != "-" {
			appendCommandPath(out, command, PathAccessWrite, group.dumpHeader)
			group.hasDownloadFile = true
		}
	}

	for _, target := range parsed.Targets {
		group := &groups[target.Group]
		group.hasTarget = true
		// Curl expands brace/range expressions itself, independently of the
		// surrounding shell. Until facts can enumerate that grammar, a literal
		// target or transfer path would under-report the action. Output #N tokens
		// can likewise be replaced with a captured glob value.
		if curlHasUnmodeledGlob(target.Value) ||
			target.UploadSet && curlHasUnmodeledGlob(target.UploadValue) ||
			target.Output == curlOutputFile &&
				curlOutputHasUnmodeledGlobReference(target.OutputValue) {
			out.markPartial(IssueUnknownOperandGrammar)
		}
		targetUpload := group.upload || target.UploadSet
		if target.UploadSet {
			switch target.UploadValue {
			case "-", ".":
				group.hasUploadStdin = true
			case "":
				out.markPartial(IssueUnknownOperandGrammar)
			default:
				appendLiteralTransferPath(
					out,
					command,
					PathAccessRead,
					target.UploadValue,
				)
				group.hasUploadFile = true
			}
		}
		switch target.Output {
		case curlOutputStdout:
		case curlOutputFile:
			if valid {
				if group.hasOutputDir && group.outputDir != "" {
					// Relative output names are interpreted beneath --output-dir.
					out.markPartial(IssueUnsupportedConstruct)
				}
				appendCommandPath(
					out,
					command,
					PathAccessWrite,
					target.OutputValue,
				)
				group.hasDownloadFile = true
			}
		case curlOutputRemoteName, curlOutputUnknown:
			out.markPartial(IssueUnknownOperandGrammar)
		}

		action := NetworkDownload
		if targetUpload {
			action = NetworkUpload
			group.hasUploadTarget = true
		} else {
			group.hasDownloadTarget = true
		}
		fact, ok := webTargetFact(command.ID, target.Value, action)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if out.appendNetwork(fact) {
			if targetUpload {
				group.hasUploadNetwork = true
			} else {
				group.hasDownloadNetwork = true
			}
		}
	}

	for index := range groups {
		group := &groups[index]
		if !group.hasTarget {
			continue
		}
		if group.hasUploadTarget {
			addOperation(command, OperationUpload)
			if !group.hasUploadNetwork {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			addWebTransferFlows(
				out,
				command.ID,
				true,
				group.hasUploadNetwork,
				group.hasUploadFile,
				group.hasUploadStdin,
				group.hasProcessUpload,
				group.hasDownloadFile,
			)
		}
		if group.hasDownloadTarget {
			addOperation(command, OperationFetch)
			if !group.hasDownloadNetwork {
				out.markPartial(IssueUnknownOperandGrammar)
			}
			addWebTransferFlows(
				out,
				command.ID,
				false,
				group.hasDownloadNetwork,
				false,
				false,
				false,
				group.hasDownloadFile,
			)
		}
	}
}

func classifyParsedWgetTransfer(out *parseOutput, command *CommandFact) {
	parsed := parseWgetArgv(command.Argv)
	if !parsed.Complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if parsed.Preview {
		command.Effect = EffectPreview
		return
	}

	var (
		upload           bool
		hasNetwork       bool
		hasUploadFile    bool
		hasProcessUpload bool
		hasDownloadFile  bool
	)

	if parsed.ConfigIndirect {
		for _, option := range parsed.Values {
			if option.Option == "--config" && option.Value != "" && option.Value != "-" {
				appendCommandPath(out, command, PathAccessRead, option.Value)
			}
		}
		out.markPartial(IssueUnsupportedConstruct)
	}
	if parsed.Background {
		out.markPartial(IssueUnsupportedConstruct)
	}
	if parsed.InputFileSet {
		if parsed.InputFile != "" && parsed.InputFile != "-" {
			appendCommandPath(out, command, PathAccessRead, parsed.InputFile)
		}
		out.markPartial(IssueUnsupportedConstruct)
	}

	if parsed.OutputSet {
		if parsed.Complete && parsed.Output != "" && parsed.Output != "-" {
			appendCommandPath(out, command, PathAccessWrite, parsed.Output)
			hasDownloadFile = true
		}
	} else if !parsed.Spider {
		// Wget derives a file name from the response without -O.
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if parsed.Complete && parsed.LogOutputSet && parsed.LogOutput != "-" {
		access := PathAccessWrite
		if parsed.AppendLog {
			access = PathAccessAppend
		}
		appendCommandPath(out, command, access, parsed.LogOutput)
		hasDownloadFile = true
	}

	if !parsed.Spider {
		if parsed.PostDataSet || parsed.BodyDataSet {
			upload = true
			hasProcessUpload = true
		}
		for _, candidate := range []struct {
			set   bool
			value string
		}{
			{set: parsed.PostFileSet, value: parsed.PostFile},
			{set: parsed.BodyFileSet, value: parsed.BodyFile},
		} {
			if !candidate.set || candidate.value == "" {
				continue
			}
			upload = true
			hasUploadFile = true
			appendLiteralTransferPath(
				out,
				command,
				PathAccessRead,
				candidate.value,
			)
		}
	}

	action := NetworkDownload
	if upload {
		action = NetworkUpload
		addOperation(command, OperationUpload)
	} else {
		addOperation(command, OperationFetch)
	}
	for _, target := range parsed.Targets {
		fact, ok := webTargetFact(command.ID, target, action)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if out.appendNetwork(fact) {
			hasNetwork = true
		}
	}
	if !hasNetwork {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	addWebTransferFlows(
		out,
		command.ID,
		upload,
		hasNetwork,
		hasUploadFile,
		false,
		hasProcessUpload,
		hasDownloadFile,
	)
}

func appendLiteralTransferPath(
	out *parseOutput,
	command *CommandFact,
	access PathAccess,
	value string,
) {
	if value == "" {
		return
	}
	if value == "-" {
		out.appendPath(PathFact{
			CommandID: command.ID,
			Access:    access,
			Flavor:    PathFlavorUnknown,
			Value:     value,
		})
		return
	}
	appendCommandPath(out, command, access, value)
}

func containsCookieLiteral(value string) bool {
	for _, character := range value {
		if character == '=' {
			return true
		}
	}
	return false
}

func curlDataURLEncodeFile(
	value string,
) (path string, stdin bool, fileForm bool, valid bool) {
	candidate := ""
	switch {
	case strings.HasPrefix(value, "@"):
		candidate = strings.TrimPrefix(value, "@")
		fileForm = true
	case strings.Contains(value, "@"):
		name, file, _ := strings.Cut(value, "@")
		if name != "" && !strings.Contains(name, "=") {
			candidate = file
			fileForm = true
		}
	}
	if !fileForm {
		return "", false, false, true
	}
	if candidate == "" {
		return "", false, true, false
	}
	if candidate == "-" {
		return "", true, true, true
	}
	return candidate, false, true, true
}

func curlFormHasUnmodeledFileReference(value string) bool {
	for _, parameter := range strings.Split(value, ";")[1:] {
		parameter = strings.TrimLeft(parameter, " \t")
		if strings.HasPrefix(strings.ToLower(parameter), "headers=") {
			// Curl applies its own quoted header-source grammar after shell quote
			// removal and permits whitespace before the parameter. Keep every
			// headers= form partial until that grammar is projected, rather than
			// silently omitting an @file read.
			return true
		}
	}
	_, payload, hasName := strings.Cut(value, "=")
	if !hasName {
		payload = value
	}
	if payload == "" || payload[0] != '@' && payload[0] != '<' {
		return false
	}
	fileSpec := payload[1:]
	if separator := strings.Index(fileSpec, ";"); separator >= 0 {
		fileSpec = fileSpec[:separator]
	}
	// Commas select multiple files, while quotes introduce curl's form-specific
	// escaping. An unquoted backslash remains valid in a Windows path, so it is
	// not ambiguous by itself. webFormFile handles only the single literal path
	// subset.
	return strings.ContainsAny(fileSpec, ",\"'")
}

func curlHasUnmodeledGlob(value string) bool {
	// Curl consumes backslash escapes around glob metacharacters even when they
	// suppress expansion, so the literal argv value is still not the effective
	// path or URL. Treat both opening and closing delimiters conservatively.
	return strings.ContainsAny(value, "{}[]")
}

func curlOutputHasUnmodeledGlobReference(value string) bool {
	for index := 0; index+1 < len(value); index++ {
		if value[index] == '#' && value[index+1] >= '1' && value[index+1] <= '9' {
			return true
		}
	}
	return false
}
