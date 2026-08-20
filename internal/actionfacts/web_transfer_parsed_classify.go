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
	"net/url"
	"strings"
)

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

// CurlTransmittedMetadata keeps HTTP headers, HTTP internal-auth operands,
// FTP origin credentials, and exact-target request bytes distinct so callers
// can bind each kind to only the URL schemes where curl transmits it.
type CurlTransmittedMetadata struct {
	Headers               []string
	HTTPOriginCredentials []string
	FTPOriginCredentials  []string
	HTTPBearerTokens      []string
	HTTPRequestComponents []TransmittedRequestComponent
}

// TransmittedRequestComponent binds literal request bytes to the exact parser-owned
// request target that transmits it. Callers must pair all three destination
// fields with a same-command network fact before treating Value as egress.
type TransmittedRequestComponent struct {
	Value  string
	Scheme string
	Host   string
	Port   int64
}

// StaticCurlTransmittedMetadata returns literal request-metadata operands that
// a complete curl command uses for origin-bound transmission. Only
// parser-owned custom headers, origin credentials, bounded URL components,
// and literal cookies are exposed. Header files, peer-changing controls, and
// multiple --next groups are deliberately excluded because the argv alone
// cannot bind their effective bytes to one network peer. As elsewhere in the
// POSIX web-transfer parser, this proof uses the package's standard argv-only
// assumption for ambient curl configuration.
func StaticCurlTransmittedMetadata(command CommandFact) CurlTransmittedMetadata {
	if !command.ArgvComplete || !isCurlProgram(command.Program) ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return CurlTransmittedMetadata{}
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 {
		return CurlTransmittedMetadata{}
	}

	group := parsed.Targets[0].Group
	for _, target := range parsed.Targets[1:] {
		if target.Group != group {
			return CurlTransmittedMetadata{}
		}
	}
	for _, target := range parsed.Targets {
		if !webMetadataTargetSchemeSupported(target.Value) ||
			!validLiteralRequestTarget(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) {
			return CurlTransmittedMetadata{}
		}
	}

	lastUser := -1
	lastBearer := -1
	lastRequestTarget := -1
	for index, option := range parsed.Options {
		if option.Group != group || option.Role == curlOptionConfig ||
			option.Role == curlOptionNetworkOverride {
			return CurlTransmittedMetadata{}
		}
		if option.Canonical == "--user" && option.ValuePresent {
			lastUser = index
		}
		if option.Canonical == "--oauth2-bearer" && option.ValuePresent {
			lastBearer = index
		}
		if option.Canonical == "--request-target" && option.ValuePresent {
			lastRequestTarget = index
		}
	}
	requestTargetValue := ""
	if lastRequestTarget >= 0 {
		requestTarget := parsed.Options[lastRequestTarget]
		if !staticCurlOptionValue(command, requestTarget) ||
			requestTarget.Value == "" || !visibleASCII(requestTarget.Value) {
			return CurlTransmittedMetadata{}
		}
		requestTargetValue = requestTarget.Value
	}

	metadata := CurlTransmittedMetadata{}
	httpAuthorizationOverridden := false
	httpCookieOverridden := false
	finalUser := ""
	finalBearer := ""
	var literalCookies []string
	for index, option := range parsed.Options {
		if !option.ValuePresent ||
			(option.Canonical != "--header" &&
				option.Canonical != "--cookie" &&
				(option.Canonical != "--user" || index != lastUser) &&
				(option.Canonical != "--oauth2-bearer" || index != lastBearer)) {
			continue
		}
		argumentIndex := option.ValueArgvIndex
		if option.ValueJoined {
			argumentIndex = option.ArgvIndex
		}
		if argumentIndex < 0 || argumentIndex >= len(command.Arguments) {
			return CurlTransmittedMetadata{}
		}
		argument := command.Arguments[argumentIndex]
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[argumentIndex] {
			return CurlTransmittedMetadata{}
		}
		switch option.Canonical {
		case "--header":
			if strings.HasPrefix(option.Value, "@") {
				httpAuthorizationOverridden = true
				httpCookieOverridden = true
				continue
			}
			if curlHeaderOverridesHTTPAuthorization(option.Value) {
				httpAuthorizationOverridden = true
			}
			if curlHeaderOverridesHTTPCookie(option.Value) {
				httpCookieOverridden = true
			}
			if !curlStaticHTTPHeaderIsTransmitted(option.Value) {
				continue
			}
			metadata.Headers = append(metadata.Headers, option.Value)
		case "--cookie":
			if curlCookieBytesPreserved(option.Value) {
				literalCookies = append(literalCookies, option.Value)
			}
		case "--user":
			finalUser = option.Value
		case "--oauth2-bearer":
			finalBearer = option.Value
		}
	}
	if finalUser != "" {
		metadata.FTPOriginCredentials = []string{finalUser}
	}
	if !httpAuthorizationOverridden {
		if finalBearer != "" {
			metadata.HTTPBearerTokens = []string{finalBearer}
		} else if finalUser != "" {
			metadata.HTTPOriginCredentials = []string{finalUser}
		}
	}
	for _, target := range parsed.Targets {
		network, ok := webTargetFact(
			command.ID,
			target.Value,
			NetworkDownload,
		)
		if !ok || network.Scheme != "http" && network.Scheme != "https" {
			continue
		}
		component := func(value string) TransmittedRequestComponent {
			return TransmittedRequestComponent{
				Value:  value,
				Scheme: network.Scheme,
				Host:   network.Host,
				Port:   network.Port,
			}
		}
		if !httpCookieOverridden {
			for _, cookie := range literalCookies {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(cookie),
				)
			}
		}
		if lastRequestTarget >= 0 {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(requestTargetValue),
			)
			continue
		}
		if path := rawHTTPURLPath(target.Value); curlURLPathBytesPreserved(path) {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(path),
			)
		}
		query := rawURLQuery(target.Value)
		if query != "" && visibleASCII(query) {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(query),
			)
		}
	}
	return metadata
}

func staticCommandArgumentAt(command CommandFact, index int) bool {
	if index < 0 || index >= len(command.Arguments) ||
		index >= len(command.Argv) {
		return false
	}
	argument := command.Arguments[index]
	return !argument.Expands && argument.Quote != QuoteMixed &&
		argument.Value == command.Argv[index]
}

func staticCurlOptionValue(command CommandFact, option curlOptionToken) bool {
	argumentIndex := option.ValueArgvIndex
	if option.ValueJoined {
		argumentIndex = option.ArgvIndex
	}
	return option.ValuePresent && staticCommandArgumentAt(command, argumentIndex)
}

func validLiteralRequestTarget(value string) bool {
	for index := range len(value) {
		if value[index] <= 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func webMetadataTargetSchemeSupported(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasPrefix(lower, "ftp://") ||
		strings.HasPrefix(lower, "ftps://")
}

func rawURLQuery(value string) string {
	requestTarget, _, _ := strings.Cut(value, "#")
	_, query, found := strings.Cut(requestTarget, "?")
	if !found {
		return ""
	}
	return query
}

func rawHTTPURLPath(value string) string {
	_, remainder, found := strings.Cut(value, "://")
	if !found {
		return ""
	}
	delimiter := strings.IndexAny(remainder, "/?#")
	if delimiter < 0 || remainder[delimiter] != '/' {
		return "/"
	}
	path := remainder[delimiter:]
	if end := strings.IndexAny(path, "?#"); end >= 0 {
		path = path[:end]
	}
	if path == "" {
		return "/"
	}
	return path
}

func visibleASCII(value string) bool {
	for index := range len(value) {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func curlURLPathBytesPreserved(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("/-._~", rune(character)) {
			continue
		}
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func curlCookieBytesPreserved(value string) bool {
	if strings.IndexByte(value, '=') <= 0 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("-._~=", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func curlStaticHTTPHeaderIsTransmitted(value string) bool {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	// Curl drops bare -H values and colon forms without a field name or a
	// nonblank value. Without a colon, only the first semicolon terminating the
	// operand causes curl to send an empty-valued header.
	if separator := strings.IndexByte(value, ':'); separator >= 0 {
		return separator > 0 && strings.ContainsFunc(
			value[separator+1:],
			func(character rune) bool {
				return character != ' ' && character != '\t' &&
					character != '\r' && character != '\n' &&
					character != '\v' && character != '\f'
			},
		)
	}
	return len(value) > 1 && strings.IndexByte(value, ';') == len(value)-1
}

func curlHeaderOverridesHTTPAuthorization(value string) bool {
	separator := strings.IndexAny(value, ":;")
	return separator >= 0 && strings.EqualFold(value[:separator], "authorization")
}

func curlHeaderOverridesHTTPCookie(value string) bool {
	separator := strings.IndexAny(value, ":;")
	return separator >= 0 && strings.EqualFold(value[:separator], "cookie")
}

// WgetTransmittedMetadata keeps protocol-specific metadata lanes separate so
// callers cannot pair an HTTP-only header with an FTP target. Generic Wget
// origin credentials are returned only when the closed argv state proves
// their effective values.
type WgetTransmittedMetadata struct {
	HTTPHeaders           []string
	HTTPOriginCredentials []string
	FTPOriginCredentials  []string
	HTTPRequestComponents []TransmittedRequestComponent
}

// StaticWgetTransmittedMetadata returns effective literal custom headers and
// generic origin credentials owned by the closed Wget parser. Repeated header
// names replace case-insensitively, and an empty --header clears all earlier
// custom headers. Generic credentials require --no-config because protocol-
// specific values from ambient wgetrc files otherwise have higher priority.
func StaticWgetTransmittedMetadata(command CommandFact) WgetTransmittedMetadata {
	if !command.ArgvComplete || !isWgetProgram(command.Program) ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return WgetTransmittedMetadata{}
	}
	parsed := parseWgetArgv(command.Argv)
	if !parsed.Complete || parsed.Preview || parsed.Background ||
		parsed.ConfigIndirect || parsed.InputFileSet ||
		len(parsed.Targets) == 0 {
		return WgetTransmittedMetadata{}
	}
	if len(parsed.TargetValues) != len(parsed.Targets) {
		return WgetTransmittedMetadata{}
	}
	for _, target := range parsed.TargetValues {
		if !webMetadataTargetSchemeSupported(target.Value) ||
			!validLiteralRequestTarget(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) {
			return WgetTransmittedMetadata{}
		}
	}

	lastHeaders := make(map[string]int)
	lastUser := -1
	lastPassword := -1
	for index, value := range parsed.Values {
		switch value.Option {
		case "--header":
			if !staticWgetValueArgument(command, value) {
				return WgetTransmittedMetadata{}
			}
			if value.Value == "" {
				clear(lastHeaders)
				continue
			}
			name, _, found := strings.Cut(value.Value, ":")
			if !found || !validWgetHeader(value.Value) {
				return WgetTransmittedMetadata{}
			}
			lastHeaders[strings.ToLower(name)] = index
		case "--user":
			lastUser = index
		case "--password":
			lastPassword = index
		}
	}

	metadata := WgetTransmittedMetadata{}
	httpAuthorizationOverridden := false
	for index, value := range parsed.Values {
		if value.Option != "--header" || value.Value == "" {
			continue
		}
		name, _, _ := strings.Cut(value.Value, ":")
		lastIndex, active := lastHeaders[strings.ToLower(name)]
		if !active || lastIndex != index {
			continue
		}
		if strings.EqualFold(name, "proxy-authorization") {
			continue
		}
		metadata.HTTPHeaders = append(
			metadata.HTTPHeaders,
			wgetWireHeader(value.Value),
		)
		if strings.EqualFold(name, "authorization") {
			httpAuthorizationOverridden = true
		}
	}
	for _, target := range parsed.TargetValues {
		network, ok := webTargetFact(
			command.ID,
			target.Value,
			NetworkDownload,
		)
		if !ok || network.Scheme != "http" && network.Scheme != "https" {
			continue
		}
		component := func(value string) TransmittedRequestComponent {
			return TransmittedRequestComponent{
				Value:  value,
				Scheme: network.Scheme,
				Host:   network.Host,
				Port:   network.Port,
			}
		}
		if path := rawHTTPURLPath(target.Value); wgetURLPathBytesPreserved(path) {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(path),
			)
		}
		query := rawURLQuery(target.Value)
		if query == "" || !wgetQueryBytesPreserved(query) {
			continue
		}
		metadata.HTTPRequestComponents = append(
			metadata.HTTPRequestComponents,
			component(query),
		)
	}

	if !parsed.ConfigDisabled || len(parsed.Targets) != 1 ||
		wgetTargetHasUserinfo(parsed.Targets[0]) {
		return metadata
	}
	if lastUser < 0 && lastPassword < 0 {
		return metadata
	}

	user := ""
	password := ""
	if lastUser >= 0 {
		value := parsed.Values[lastUser]
		if !staticWgetValueArgument(command, value) {
			return metadata
		}
		user = value.Value
	}
	if lastPassword >= 0 {
		value := parsed.Values[lastPassword]
		if !staticWgetValueArgument(command, value) {
			return metadata
		}
		password = value.Value
	}

	if user != "" {
		metadata.FTPOriginCredentials = append(
			metadata.FTPOriginCredentials,
			user,
		)
	}
	if password != "" && lastUser >= 0 {
		metadata.FTPOriginCredentials = append(
			metadata.FTPOriginCredentials,
			password,
		)
	}
	if lastUser >= 0 && lastPassword >= 0 &&
		!httpAuthorizationOverridden {
		if user != "" {
			metadata.HTTPOriginCredentials = append(
				metadata.HTTPOriginCredentials,
				user,
			)
		}
		if password != "" {
			metadata.HTTPOriginCredentials = append(
				metadata.HTTPOriginCredentials,
				password,
			)
		}
	}
	return metadata
}

func staticWgetValueArgument(command CommandFact, value wgetArgvValue) bool {
	return value.ValueIndex >= 0 && staticCommandArgumentAt(
		command,
		value.ValueIndex,
	)
}

func wgetWireHeader(value string) string {
	name, headerValue, _ := strings.Cut(value, ":")
	headerValue = strings.TrimLeftFunc(headerValue, func(character rune) bool {
		return character <= 0x7f && isWgetASCIIWhitespace(byte(character))
	})
	return name + ": " + headerValue
}

func wgetQueryBytesPreserved(value string) bool {
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("-._~=&", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func wgetURLPathBytesPreserved(value string) bool {
	return !strings.Contains(value, "//") && curlURLPathBytesPreserved(value)
}

func wgetTargetHasUserinfo(value string) bool {
	parsed, err := url.Parse(value)
	return err != nil || parsed.User != nil
}

// StaticWgetUploadPayloads returns the final literal inline request body that
// a complete wget command sends. File-backed bodies and control modes are
// deliberately excluded because their contents or execution are not proved by
// the argv value itself.
func StaticWgetUploadPayloads(command CommandFact) []string {
	if !command.ArgvComplete || !isWgetProgram(command.Program) ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	parsed := parseWgetArgv(command.Argv)
	if !parsed.Complete || !parsed.RequestBodyValid || parsed.Preview ||
		parsed.Background || parsed.ConfigIndirect || parsed.InputFileSet ||
		parsed.Spider || len(parsed.Targets) == 0 {
		return nil
	}

	optionName := ""
	payload := ""
	switch {
	case parsed.PostDataSet:
		optionName = "--post-data"
		payload = parsed.PostData
	case parsed.BodyDataSet:
		optionName = "--body-data"
		payload = parsed.BodyData
	default:
		return nil
	}
	if payload == "" {
		return nil
	}

	for index := len(parsed.Values) - 1; index >= 0; index-- {
		value := parsed.Values[index]
		if value.Option != optionName {
			continue
		}
		if value.Value != payload || value.ValueIndex < 0 ||
			value.ValueIndex >= len(command.Arguments) {
			return nil
		}
		argument := command.Arguments[value.ValueIndex]
		if argument.Expands || argument.Quote == QuoteMixed ||
			argument.Value != command.Argv[value.ValueIndex] {
			return nil
		}
		return []string{payload}
	}
	return nil
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
