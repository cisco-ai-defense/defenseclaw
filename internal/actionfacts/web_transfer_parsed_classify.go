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
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
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

// StaticCurlStdinUploadTargets returns the exact parser-owned destination that
// receives stdin from one literal --data-binary @- or --upload-file - operand.
// The proof is intentionally an exact minimal invocation: another option or
// target can consume stdin or route bytes independently of an unrelated
// NetworkUpload fact on the same command.
func StaticCurlStdinUploadTargets(command CommandFact) []NetworkFact {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		!command.ArgvComplete || command.ParentCommandID != 0 ||
		len(command.Wrappers) != 0 || command.Program != "curl" ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return nil
		}
	}

	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) {
		return nil
	}

	if len(parsed.Options) != 1 || len(parsed.Targets) != 1 {
		return nil
	}
	option := parsed.Options[0]
	if option.Group != parsed.Targets[0].Group || !option.ValuePresent ||
		!staticCurlOptionValue(command, option) {
		return nil
	}
	stdinBody := option.Canonical == "--data-binary" && option.Value == "@-"
	stdinUpload := option.Canonical == "--upload-file" && option.Value == "-"
	if !stdinBody && !stdinUpload {
		return nil
	}

	target := parsed.Targets[0]
	if !staticCommandArgumentAt(command, target.ArgvIndex) ||
		!webMetadataTargetSchemeSupported(target.Value) ||
		!validLiteralRequestTarget(target.Value) ||
		curlTargetHasInvalidUserinfo(target.Value) ||
		curlHasUnmodeledGlob(target.Value) {
		return nil
	}
	network, ok := webTargetFact(command.ID, target.Value, NetworkUpload)
	if !ok ||
		(stdinBody && network.Scheme != "http" && network.Scheme != "https") ||
		(stdinUpload && network.Scheme != "http" && network.Scheme != "https" &&
			network.Scheme != "ftp" && network.Scheme != "ftps") {
		return nil
	}
	return []NetworkFact{network}
}

// StaticCurlUploadPayloads returns the literal inline request-body operands
// that a complete curl command sends. File and stdin upload sources are
// deliberately excluded: their contents are not represented by argv. Multiple
// --next groups are also excluded because CommandFact does not retain the
// per-group network destination needed to prove which body reaches which peer.
func StaticCurlUploadPayloads(command CommandFact) []string {
	if !command.ArgvComplete || !isCurlProgram(command.Program) ||
		len(command.Argv) == 0 || !staticCurlArgvIdentity(command) ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) {
		return nil
	}

	group := parsed.Targets[0].Group
	for _, target := range parsed.Targets[1:] {
		if target.Group != group {
			return nil
		}
	}
	hasHTTPTarget := false
	for _, target := range parsed.Targets {
		network, ok := webTargetFact(command.ID, target.Value, NetworkUpload)
		if !ok || !webMetadataTargetSchemeSupported(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			!validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) {
			return nil
		}
		switch network.Scheme {
		case "http", "https":
			hasHTTPTarget = true
		case "ftp", "ftps":
		default:
			return nil
		}
	}
	if !hasHTTPTarget {
		return nil
	}
	if _, valid := staticCurlHTTPRequestComponentProjection(
		command,
		parsed,
		group,
	); !valid {
		return nil
	}
	if !curlOriginRequestBuildAllowsPayload(command, parsed, group) {
		return nil
	}
	if !curlStaticFormSequenceValid(command, parsed, group) {
		return nil
	}
	postData, hasPostData, postDataValid := staticCurlPostDataBytes(
		command,
		parsed,
		group,
	)
	if !postDataValid {
		return nil
	}

	getQueryData := false
	requestTargetSet := false
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical == "--get" {
			getQueryData = option.Name != "--no-get"
		}
		requestTargetSet = requestTargetSet ||
			option.Canonical == "--request-target" && option.ValuePresent
	}
	if getQueryData && requestTargetSet {
		if hasPostData {
			if _, valid := curlGETPostDataQueryBytes(postData); !valid ||
				!curlGETPostDataURLLengthsValid(parsed.Targets, postData) {
				return nil
			}
		}
		return nil
	}
	if getQueryData && hasPostData {
		fullPostData := postData
		var valid bool
		postData, valid = curlGETPostDataQueryBytes(fullPostData)
		if !valid ||
			!curlGETPostDataURLLengthsValid(parsed.Targets, fullPostData) {
			return nil
		}
	}

	var payloads []string
	for _, option := range parsed.Options {
		if option.Group != group || !option.ValuePresent ||
			!curlUploadPayloadOption(option.Canonical) {
			continue
		}
		if curlOptionProvidesGETQueryData(option.Canonical) {
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
		if curlUploadPayloadSourceUncertain(option) {
			return nil
		}
		values, literal, transmissionStops := staticCurlUploadPayloads(option)
		if !literal {
			continue
		}
		payloads = append(payloads, values...)
		if transmissionStops {
			break
		}
	}
	if hasPostData && postData != "" {
		payloads = append(payloads, postData)
	}
	return payloads
}

func curlUploadPayloadOption(canonical string) bool {
	switch canonical {
	case "--data", "--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--json", "--form", "--form-string":
		return true
	default:
		return false
	}
}

func staticCurlPostDataBytes(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) (string, bool, bool) {
	var postData strings.Builder
	hasPostData := false
	for _, option := range parsed.Options {
		if option.Group != group ||
			!curlOptionProvidesGETQueryData(option.Canonical) {
			continue
		}
		hasPostData = true
		if !option.ValuePresent || !staticCurlOptionValue(command, option) {
			return "", true, false
		}
		value := ""
		if curlUploadPayloadSourceUncertain(option) {
			var nullSource bool
			value, nullSource = curlPOSIXNullPostDataValue(command, option)
			if !nullSource {
				return "", true, false
			}
		} else {
			values, literal, _ := staticCurlUploadPayloads(option)
			if !literal || len(values) > 1 {
				return "", true, false
			}
			if len(values) == 1 {
				value = values[0]
			}
		}
		separatorLength := 0
		if postData.Len() > 0 && option.Canonical != "--json" {
			separatorLength = 1
		}
		const maximumFileToMemory = 1 << 30
		if len(value) >= maximumFileToMemory-postData.Len()-separatorLength {
			return "", true, false
		}
		if separatorLength != 0 {
			postData.WriteByte('&')
		}
		postData.WriteString(value)
	}
	return postData.String(), hasPostData, true
}

func curlPOSIXNullPostDataValue(
	command CommandFact,
	option curlOptionToken,
) (string, bool) {
	if command.Dialect != DialectPOSIX {
		return "", false
	}
	switch option.Canonical {
	case "--data", "--data-ascii", "--data-binary", "--json":
		return "", option.Value == "@/dev/null"
	case "--data-urlencode":
		path, stdin, fileSource, valid := curlDataURLEncodeFile(option.Value)
		if !valid || !fileSource || stdin || path != "/dev/null" {
			return "", false
		}
		name, _, _ := strings.Cut(option.Value, "@")
		if name == "" {
			return "", true
		}
		return name + "=", true
	default:
		return "", false
	}
}

func curlGETPostDataQueryBytes(value string) (string, bool) {
	if !curlURLQueryWireBytesValid(value) {
		return "", false
	}
	value = curlCanonicalURLQueryPercentHex(value)
	prefix, _, _ := strings.Cut(value, "#")
	return prefix, true
}

func curlGETPostDataURLLengthsValid(
	targets []curlTransferTarget,
	postData string,
) bool {
	for _, target := range targets {
		beforeFragment, _, _ := strings.Cut(target.Value, "#")
		separatorLength := 1
		if queryStart := strings.IndexByte(beforeFragment, '?'); queryStart >= 0 {
			query := beforeFragment[queryStart+1:]
			if query == "" || strings.HasSuffix(query, "&") {
				separatorLength = 0
			}
		}
		if len(postData) >= 8_000_000-len(target.Value)-separatorLength {
			return false
		}
	}
	return true
}

func staticCurlGETPostDataValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	_, valid := staticCurlGETPostDataProjection(command, parsed, group)
	return valid
}

func staticCurlGETPostDataProjection(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) (string, bool) {
	httpGetSet := false
	for _, option := range parsed.Options {
		if option.Group == group && option.Canonical == "--get" {
			httpGetSet = option.Name != "--no-get"
		}
	}
	if !httpGetSet {
		return "", true
	}
	postData, hasPostData, valid := staticCurlPostDataBytes(command, parsed, group)
	if !valid || !hasPostData {
		return "", valid
	}
	query, valid := curlGETPostDataQueryBytes(postData)
	var targets []curlTransferTarget
	for _, target := range parsed.Targets {
		if target.Group == group {
			targets = append(targets, target)
		}
	}
	if !valid || !curlGETPostDataURLLengthsValid(targets, postData) {
		return "", false
	}
	return query, true
}

func curlUploadPayloadSourceUncertain(option curlOptionToken) bool {
	switch option.Canonical {
	case "--data", "--data-ascii", "--data-binary", "--json":
		if strings.HasPrefix(option.Value, "@") {
			return true
		}
		_, _, fileSource := webDataFile(option.Value)
		return fileSource
	case "--data-urlencode":
		_, _, fileSource, valid := curlDataURLEncodeFile(option.Value)
		if !valid || fileSource {
			return true
		}
		_, valid = curlDataURLEncodeBytes(option.Value)
		return !valid
	case "--form", "--form-string":
		_, valid, _ := curlStaticFormPayloads(option)
		return !valid
	default:
		return false
	}
}

func curlFormUsesPOSIXNullDevice(value string) bool {
	_, specification, found := strings.Cut(value, "=")
	if !found {
		return false
	}
	if strings.HasPrefix(specification, "@") {
		fileEntries, valid := curlMIMEFormFileEntries(specification[1:])
		if valid && len(fileEntries) > 1 {
			for _, fileEntry := range fileEntries {
				if curlFormUsesPOSIXNullDevice("=@" + fileEntry) {
					return true
				}
			}
			return false
		}
	}
	position := 0
	if strings.HasPrefix(specification, "@") ||
		strings.HasPrefix(specification, "<") {
		position = curlSkipFormSpace(specification, 1)
		source, next := curlFormParameterWord(specification, position)
		if source == "/dev/null" {
			return true
		}
		position = next
	} else {
		position = curlSkipFormSpace(specification, 0)
		_, position = curlFormParameterWord(specification, position)
	}
	for position < len(specification) {
		if specification[position] != ';' {
			return false
		}
		position = curlSkipFormSpace(specification, position+1)
		if !curlFormHasFoldedPrefix(specification, position, "headers=") {
			_, position = curlFormParameterWord(specification, position)
			continue
		}
		position += len("headers=")
		if position >= len(specification) ||
			(specification[position] != '@' && specification[position] != '<') {
			_, position = curlFormParameterWord(specification, position)
			continue
		}
		position = curlSkipFormSpace(specification, position+1)
		source, next := curlFormParameterWord(specification, position)
		if source == "/dev/null" {
			return true
		}
		position = next
	}
	return false
}

func curlPOSIXNullDeviceAvailable(command CommandFact) bool {
	return command.Dialect == DialectPOSIX
}

// CurlTransmittedMetadata keeps HTTP headers, HTTP internal-auth operands,
// FTP origin credentials, and exact-target request bytes distinct so callers
// can bind each kind to only the URL schemes where curl transmits it.
type CurlTransmittedMetadata struct {
	Headers                        []string
	HTTPOriginCredentials          []string
	FTPOriginCredentials           []string
	HTTPBearerTokens               []string
	HTTPRequestComponents          []TransmittedRequestComponent
	FTPRequestComponents           []TransmittedRequestComponent
	HTTPOriginCredentialComponents []TransmittedRequestComponent
	FTPOriginCredentialComponents  []TransmittedRequestComponent
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

// TransmittedFileSource binds one exact parser-owned filesystem input to the
// transfer target whose request can consume it. Path describes the source
// identity, not a byte-for-byte payload guarantee: cookie files, for example,
// contribute only the entries curl selects for that target.
type TransmittedFileSource struct {
	Path   string
	Scheme string
	Host   string
	Port   int64
}

// StaticCurlUploadFileSources returns exact target-bound file inputs that curl
// can transmit as a request body or request metadata. TLS/config/support files
// and stdin pseudo-sources are deliberately excluded. Callers must pair each
// result with an exact same-command network fact before granting authority.
func StaticCurlUploadFileSources(command CommandFact) []TransmittedFileSource {
	if command.Effect != EffectExecute || !command.ArgvComplete ||
		!isCurlProgram(command.Program) || len(command.Argv) == 0 ||
		!staticCurlArgvIdentity(command) ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return nil
		}
	}

	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) || !curlStaticFormEagerSyntaxValid(parsed) {
		return nil
	}

	grouped := make(map[int][]string)
	for _, option := range parsed.Options {
		if !option.ValuePresent {
			continue
		}
		if !staticCurlOptionValue(command, option) {
			return nil
		}
		path := ""
		switch option.Canonical {
		case "--data", "--data-ascii", "--data-binary", "--json":
			var stdin, fileSource bool
			path, stdin, fileSource = webDataFile(option.Value)
			if !fileSource || stdin {
				continue
			}
		case "--data-urlencode":
			var stdin, fileSource, valid bool
			path, stdin, fileSource, valid = curlDataURLEncodeFile(option.Value)
			if !valid {
				return nil
			}
			if !fileSource || stdin {
				continue
			}
		case "--form":
			if curlFormHasUnmodeledFileReference(option.Value) {
				return nil
			}
			var stdin, fileSource bool
			path, stdin, fileSource = webFormFile(option.Value)
			if !fileSource || stdin {
				continue
			}
		case "--header":
			if !strings.HasPrefix(option.Value, "@") {
				continue
			}
			path = strings.TrimPrefix(option.Value, "@")
			if path == "" {
				return nil
			}
			if path == "-" {
				continue
			}
		case "--cookie":
			if option.Value == "" || option.Value == "-" ||
				containsCookieLiteral(option.Value) {
				continue
			}
			path = option.Value
		default:
			continue
		}
		path, valid := curlStaticFileSourcePath(command, path)
		if !valid {
			return nil
		}
		grouped[option.Group] = append(grouped[option.Group], path)
	}

	seen := make(map[string]struct{})
	var sources []TransmittedFileSource
	appendSource := func(path string, network NetworkFact) {
		key := path + "\x00" + strings.ToLower(network.Scheme) + "\x00" +
			network.Host + "\x00" + strconv.FormatInt(network.Port, 10)
		if _, duplicate := seen[key]; duplicate {
			return
		}
		seen[key] = struct{}{}
		sources = append(sources, TransmittedFileSource{
			Path: path, Scheme: network.Scheme,
			Host: network.Host, Port: network.Port,
		})
	}
	for _, target := range parsed.Targets {
		if !staticCommandArgumentAt(command, target.ArgvIndex) ||
			!validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) {
			return nil
		}
		network, valid := webTargetFact(
			command.ID,
			target.Value,
			NetworkUpload,
		)
		if !valid {
			network, valid = curlSMTPTargetFact(
				command.ID,
				target.Value,
				NetworkUpload,
			)
		}
		if !valid {
			return nil
		}
		switch network.Scheme {
		case "http", "https", "ftp", "ftps", "smtp", "smtps":
		default:
			continue
		}
		if target.UploadSet && target.UploadValue != "" &&
			target.UploadValue != "-" && target.UploadValue != "." {
			path, sourceValid := curlStaticFileSourcePath(
				command,
				target.UploadValue,
			)
			if !sourceValid {
				return nil
			}
			appendSource(path, network)
		}
		if network.Scheme != "http" && network.Scheme != "https" {
			continue
		}
		for _, source := range grouped[target.Group] {
			appendSource(source, network)
		}
	}
	return sources
}

func curlStaticFileSourcePath(command CommandFact, value string) (string, bool) {
	if value == "" || value == "-" {
		return "", false
	}
	if command.Dialect != DialectCMD && command.Dialect != DialectPowerShell {
		return value, true
	}
	return windowsCanonicalPathFactValue(value)
}

// StaticCurlSMTPRequestComponents returns literal SMTP request operands that
// a closed curl invocation sends to one exact SMTP(S) peer. An upload emits
// the final MAIL FROM value and every appended RCPT TO value. Without an
// upload, curl's default SMTP command sends only the first recipient as VRFY;
// --mail-from is ignored in that mode.
//
// The upload lane accepts only stdin and, for POSIX commands, /dev/null sources
// whose availability cannot fail before the envelope is sent. Other files,
// MIME bodies, custom SMTP commands, peer overrides, and multiple transfer
// groups remain outside this bounded proof.
func StaticCurlSMTPRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	if (command.Dialect != DialectPOSIX && command.Dialect != DialectArgv) ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 ||
		command.Program != "curl" || len(command.Argv) == 0 ||
		command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") ||
		len(command.Arguments) != len(command.Argv) {
		return nil
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return nil
		}
	}

	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) != 1 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) {
		return nil
	}
	target := parsed.Targets[0]
	if target.Group != 0 || !staticCommandArgumentAt(command, target.ArgvIndex) ||
		!validLiteralRequestTarget(target.Value) ||
		curlHasUnmodeledGlob(target.Value) || webTargetHasUserinfo(target.Value) {
		return nil
	}
	parsedTarget, err := url.Parse(target.Value)
	if err != nil || parsedTarget.Opaque != "" || parsedTarget.User != nil ||
		parsedTarget.Host == "" || parsedTarget.RawPath != "" ||
		(parsedTarget.Path != "" && parsedTarget.Path != "/") ||
		parsedTarget.RawQuery != "" || parsedTarget.ForceQuery ||
		parsedTarget.Fragment != "" || parsedTarget.RawFragment != "" {
		return nil
	}
	network, ok := curlSMTPTargetFact(command.ID, target.Value, NetworkDownload)
	if !ok || network.Scheme != "smtp" && network.Scheme != "smtps" {
		return nil
	}

	mailFrom := ""
	mailFromSet := false
	var recipients []string
	uploads := 0
	for _, option := range parsed.Options {
		if option.Group != target.Group || !option.Known {
			return nil
		}
		switch option.Canonical {
		case "--mail-from":
			wireValue, valid := curlSMTPAddressBytes(option.Value)
			if !staticCurlOptionValue(command, option) || !valid {
				return nil
			}
			mailFrom = wireValue
			mailFromSet = true
		case "--mail-rcpt":
			if !staticCurlOptionValue(command, option) {
				return nil
			}
			if option.Value == "" {
				recipients = append(recipients, "")
				continue
			}
			wireValue, valid := curlSMTPAddressBytes(option.Value)
			if !valid {
				return nil
			}
			recipients = append(recipients, wireValue)
		case "--mail-auth":
			// AUTH is server/authentication-state dependent, so it is not a
			// candidate. A static value cannot suppress the independently
			// proven MAIL FROM or RCPT TO commands.
			if !staticCurlOptionValue(command, option) || option.Value == "" {
				return nil
			}
		case "--upload-file":
			uploads++
			if !staticCurlOptionValue(command, option) ||
				!curlSMTPUploadSourceAvailable(command, option.Value) {
				return nil
			}
		case "--url", "--":
			// These options do not change the SMTP request bytes or peer.
		default:
			if !curlSMTPInertFlag(option) {
				return nil
			}
		}
	}
	if len(recipients) == 0 || uploads > 1 ||
		uploads == 1 && (!target.UploadSet ||
			!curlSMTPUploadSourceAvailable(command, target.UploadValue)) ||
		uploads == 0 && target.UploadSet {
		return nil
	}
	component := func(value string) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value:  value,
			Scheme: network.Scheme,
			Host:   network.Host,
			Port:   network.Port,
		}
	}
	if uploads == 0 {
		if recipients[0] == "" {
			return nil
		}
		return []TransmittedRequestComponent{component(recipients[0])}
	}

	components := make([]TransmittedRequestComponent, 0, len(recipients)+1)
	if mailFromSet && mailFrom != "" {
		components = append(components, component(mailFrom))
	}
	for _, recipient := range recipients {
		if recipient == "" {
			continue
		}
		components = append(components, component(recipient))
	}
	return components
}

func curlSMTPAddressBytes(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	value = strings.TrimPrefix(value, "<")
	value = strings.TrimSuffix(value, ">")
	if value == "" {
		return "", true
	}
	for index := range len(value) {
		if value[index] == 0 {
			return "", false
		}
	}
	local, host, hasHost := strings.Cut(value, "@")
	if hasHost {
		for index := range len(host) {
			if host[index] >= 0x80 {
				// Curl may IDN-convert the host, but it preserves the local
				// bytes before the first '@'. Keep that exact prefix. Curl
				// ignores the conversion result, so this address cannot erase
				// independently projected later recipients.
				return local, true
			}
		}
	}
	return value, true
}

func curlSMTPUploadSourceAvailable(command CommandFact, value string) bool {
	switch value {
	case "/dev/null":
		return curlPOSIXNullDeviceAvailable(command)
	case "-", ".":
		return true
	default:
		return false
	}
}

func curlSMTPInertFlag(option curlOptionToken) bool {
	if option.TakesValue || option.ValuePresent || option.Role != curlOptionNeutral {
		return false
	}
	switch option.Canonical {
	case "--append", "--compressed", "--disable", "--globoff", "--http1.0",
		"--include", "--insecure", "--ipv4", "--ipv6",
		"--junk-session-cookies", "--list-only", "--location", "--no-buffer",
		"--no-progress-meter", "--parallel", "--progress-bar", "--remote-time",
		"--show-error", "--silent", "--sslv2", "--sslv3", "--tlsv1",
		"--use-ascii", "--verbose", "--mail-rcpt-allowfails":
		return true
	default:
		return false
	}
}

// StaticCurlTelnetOptionRequestComponents returns exact Telnet negotiation
// fields from a closed curl 8.7.1 invocation, bound to one literal Telnet
// origin. TTYPE and XDISPLOC are final-value settings. NEW_ENV is additive and
// replaces its first comma with the Telnet VAR/VALUE marker on the wire.
// Transmission remains conditional on the peer requesting the corresponding
// negotiation, just as FTP account commands are conditional on peer replies.
func StaticCurlTelnetOptionRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	parsed := parseCurlArgv(command.Argv)
	network, values, valid := staticCurlTelnetOptionProjection(command, parsed)
	if !valid {
		return nil
	}
	components := make([]TransmittedRequestComponent, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		components = append(components, TransmittedRequestComponent{
			Value: value, Scheme: network.Scheme,
			Host: network.Host, Port: network.Port,
		})
	}
	return components
}

// StaticCurlTelnetOptionRequestComponentsForFacts admits a curl child beneath
// exact env/command/exec wrappers. POSIX stdin, stdout, and stderr redirects
// to /dev/null are erased as deterministic I/O sinks; every other ancestor
// redirect or pipeline keeps the proof closed.
func StaticCurlTelnetOptionRequestComponentsForFacts(
	facts Facts,
	commandID int64,
) []TransmittedRequestComponent {
	if commandID == 0 || !facts.Authoritative() || !facts.EnforcementEligible() {
		return nil
	}
	command, valid := staticCurlTelnetCommandForCommands(
		facts.Commands,
		commandID,
	)
	if !valid {
		return nil
	}
	return StaticCurlTelnetOptionRequestComponents(command)
}

func staticCurlTelnetOptionProjection(
	command CommandFact,
	parsed curlArgvParse,
) (NetworkFact, []string, bool) {
	if (command.Dialect != DialectPOSIX && command.Dialect != DialectArgv) ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		len(command.Wrappers) != 0 ||
		!curlTelnetOutputRedirectsSafe(command) || command.Program != "curl" ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") ||
		len(command.Arguments) != len(command.Argv) {
		return NetworkFact{}, nil, false
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return NetworkFact{}, nil, false
		}
	}

	nullConfigOnly := staticCurlPOSIXNullConfigOnly(command, parsed)
	if (!parsed.Complete && !nullConfigOnly) ||
		parsed.ConfigOpaque && !nullConfigOnly || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) != 1 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) ||
		!staticCurlFTPEagerOptionConflictsValid(parsed) {
		return NetworkFact{}, nil, false
	}
	target := parsed.Targets[0]
	outputSafe := target.Output == curlOutputStdout ||
		target.Output == curlOutputFile && target.OutputValue == "/dev/null" &&
			curlPOSIXNullDeviceAvailable(command)
	uploadSafe := !target.UploadSet || target.UploadValue == "" ||
		target.UploadValue == "/dev/null" && curlPOSIXNullDeviceAvailable(command)
	if target.Group != 0 || !outputSafe ||
		!uploadSafe || !staticCommandArgumentAt(command, target.ArgvIndex) ||
		!validLiteralRequestTarget(target.Value) ||
		curlHasUnmodeledGlob(target.Value) {
		return NetworkFact{}, nil, false
	}
	telnetTarget, valid := curlTelnetEffectiveTarget(command, parsed, target)
	if !valid {
		return NetworkFact{}, nil, false
	}
	network, valid := curlTelnetTargetFact(
		command.ID,
		telnetTarget,
		NetworkDownload,
	)
	if !valid {
		return NetworkFact{}, nil, false
	}
	if !staticCurlTelnetNetrcSetupValid(command, parsed, target.Group) {
		return NetworkFact{}, nil, false
	}

	lastMainProxy := -1
	lastPreproxy := -1
	lastNoProxy := -1
	for index, option := range parsed.Options {
		if option.Group != target.Group {
			continue
		}
		switch {
		case curlMainProxyOption(option.Canonical):
			lastMainProxy = index
		case option.Canonical == "--preproxy":
			lastPreproxy = index
		case option.Canonical == "--noproxy":
			lastNoProxy = index
		}
	}
	mainProxyDisabled := false
	mainProxyActive := false
	if lastMainProxy >= 0 {
		option := parsed.Options[lastMainProxy]
		if !staticCurlOptionValue(command, option) {
			return NetworkFact{}, nil, false
		}
		mainProxyDisabled = option.Canonical == "--proxy" && option.Value == "" ||
			curlProxyDecodedControlUserinfoDisables(
				command.ID,
				option.Canonical,
				option.Value,
			)
		mainProxyActive = !mainProxyDisabled
	}
	noProxyBypassesPeer := false
	if lastNoProxy >= 0 {
		option := parsed.Options[lastNoProxy]
		if !staticCurlOptionValue(command, option) {
			return NetworkFact{}, nil, false
		}
		noProxyBypassesPeer, valid = curlNoProxyMatches(option.Value, network.Host)
		if !valid {
			return NetworkFact{}, nil, false
		}
	}
	if !noProxyBypassesPeer && (lastPreproxy >= 0 || mainProxyActive ||
		lastNoProxy >= 0 && !mainProxyDisabled) {
		return NetworkFact{}, nil, false
	}
	ipv4Only, _ := curlEffectiveIPv4Only(parsed, target.Group)
	if !curlPeerMatchesAddressOptions(network.Host, ipv4Only, false) {
		return NetworkFact{}, nil, false
	}
	telnetUser, telnetUserSet, valid := curlTelnetEffectiveUser(
		command,
		parsed,
		target,
		telnetTarget,
	)
	if !valid {
		return NetworkFact{}, nil, false
	}
	if !staticCurlTelnetTransferSetupValid(
		command,
		parsed,
		target,
		telnetTarget,
	) {
		return NetworkFact{}, nil, false
	}

	var telnetOptions []string
	for _, option := range parsed.Options {
		if option.Group != target.Group || !option.Known {
			return NetworkFact{}, nil, false
		}
		switch option.Canonical {
		case "--telnet-option":
			if !staticCurlOptionValue(command, option) {
				return NetworkFact{}, nil, false
			}
			telnetOptions = append(telnetOptions, option.Value)
		case "--", "--url":
		case "--output":
			if !staticCurlOptionValue(command, option) ||
				option.Value != "-" &&
					(option.Value != "/dev/null" ||
						!curlPOSIXNullDeviceAvailable(command)) {
				return NetworkFact{}, nil, false
			}
		case "--cacert", "--cert", "--key":
			// Telnet never initializes TLS, so these support-file settings are
			// not opened and cannot preempt option negotiation.
			if !staticCurlOptionValue(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--user":
			// Only the final value is effective. Its prompt safety, username
			// bytes, and USER/NEW_ENV buffer occupancy were validated above.
			if !staticCurlOptionValue(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--config":
			if !staticCurlOptionValue(command, option) ||
				option.Value != "/dev/null" ||
				!curlPOSIXNullDeviceAvailable(command) {
				return NetworkFact{}, nil, false
			}
		case "--upload-file":
			if !staticCurlOptionValue(command, option) ||
				option.Value != "" &&
					(option.Value != "/dev/null" ||
						!curlPOSIXNullDeviceAvailable(command)) {
				return NetworkFact{}, nil, false
			}
		case "--write-out":
			if !staticCurlOptionValue(command, option) ||
				strings.HasPrefix(option.Value, "@") &&
					(option.Value != "@/dev/null" ||
						!curlPOSIXNullDeviceAvailable(command)) {
				return NetworkFact{}, nil, false
			}
		case "--connect-timeout", "--max-time", "--retry", "--retry-delay",
			"--retry-max-time", "--speed-limit", "--speed-time":
			if !staticCurlOptionValue(command, option) ||
				!curlTelnetNumericValueIsZero(option.Canonical, option.Value) {
				return NetworkFact{}, nil, false
			}
		case "--aws-sigv4", "--capath", "--cert-type", "--ciphers", "--crlfile",
			"--curves", "--egd-file", "--ftp-account", "--ftp-alternative-to-user",
			"--ftp-method", "--ftp-port", "--ftp-ssl-ccc-mode", "--mail-from",
			"--mail-rcpt", "--netrc-file", "--oauth2-bearer", "--random-file",
			"--referer", "--request", "--request-target", "--user-agent",
			"--haproxy-clientip", "--hostpubsha256", "--ipfs-gateway", "--key-type",
			"--login-options", "--pass", "--pinnedpubkey", "--proxy-cacert",
			"--proxy-capath", "--proxy-cert", "--proxy-cert-type", "--proxy-ciphers",
			"--proxy-crlfile", "--proxy-key", "--proxy-key-type", "--proxy-pass",
			"--proxy-pinnedpubkey", "--proxy-service-name",
			"--proxy-tls13-ciphers", "--pubkey", "--service-name", "--tls13-ciphers":
			// These values are either unused by Telnet or were reduced to a
			// preconnect-safe final state above. random-file is a documented
			// compatibility no-op in curl 8.7.1.
			if !staticCurlOptionValue(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--header", "--proxy-header":
			if !staticCurlHeaderSetupValid(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--cookie":
			if !staticCurlOptionValue(command, option) ||
				!containsCookieLiteral(option.Value) {
				return NetworkFact{}, nil, false
			}
		case "--cookie-jar", "--continue-at", "--data", "--data-ascii",
			"--data-binary", "--data-raw", "--data-urlencode", "--doh-url",
			"--dump-header", "--form", "--form-string", "--json", "--output-dir",
			"--proxy-user", "--quote", "--range", "--time-cond", "--url-query":
			// Aggregate and final-state semantics were validated together above.
			if !staticCurlOptionValue(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--create-file-mode", "--delegation", "--expect100-timeout",
			"--happy-eyeballs-timeout-ms", "--hostpubmd5", "--keepalive-time",
			"--limit-rate", "--local-port", "--max-filesize", "--max-redirs",
			"--parallel-max", "--proto", "--proto-redir", "--rate",
			"--tftp-blksize", "--tls-max", "--trace-config", "--variable":
			if !staticCurlOptionValue(command, option) ||
				!curlTelnetBoundedValueValid(option) {
				return NetworkFact{}, nil, false
			}
		case "--etag-compare", "--etag-save", "--trace", "--trace-ascii":
			if !staticCurlOptionValue(command, option) ||
				!curlTelnetNullSinkValueValid(command, option) {
				return NetworkFact{}, nil, false
			}
		case "--proto-default":
			if !staticCurlOptionValue(command, option) ||
				!curlTelnetProtoDefaultValueValid(option.Value) {
				return NetworkFact{}, nil, false
			}
		case "--stderr":
			if !staticCurlOptionValue(command, option) ||
				option.Value != "-" &&
					(option.Value != "/dev/null" ||
						!curlPOSIXNullDeviceAvailable(command)) {
				return NetworkFact{}, nil, false
			}
		case "--proxy", "--proxy1.0", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname", "--preproxy", "--noproxy":
			// Final direct-route state was validated above. Earlier settings
			// are overwritten; a final --proxy '' disables the main proxy and
			// a final --noproxy '*' bypasses an otherwise active main proxy.
		case "--disallow-username-in-url", "--remote-header-name":
			// Conditional final flag state was validated above.
			if !curlTelnetInertFlag(option) {
				return NetworkFact{}, nil, false
			}
		default:
			if !curlTelnetInertFlag(option) {
				return NetworkFact{}, nil, false
			}
		}
	}
	values, valid := curlTelnetOptionWireValues(
		telnetOptions,
		telnetUser,
		telnetUserSet,
	)
	if !valid {
		return NetworkFact{}, nil, false
	}
	return network, values, true
}

func staticCurlTelnetTransferSetupValid(
	command CommandFact,
	parsed curlArgvParse,
	target curlTransferTarget,
	telnetTarget string,
) bool {
	group := target.Group
	explicitTelnet := curlTargetHasExplicitTelnetScheme(target.Value)
	hasPostData := false
	hasURLQuery := false
	finalGet := false
	showHeaders := false
	contentDisposition := false
	haproxyProtocol := false
	disallowURLUser := false
	continueSet := false
	continueCurrent := false
	continueOffset := int64(0)
	dohURLSet := false
	dohURL := ""
	dumpHeaderSet := false
	dumpHeader := ""
	proxyUserSet := false
	proxyUser := ""
	outputDirSet := false
	finalHappyEyeballs := ""
	finalKeepaliveTime := ""
	finalLimitRate := ""
	finalLocalPort := ""
	finalMaxFilesize := ""

	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.ValuePresent && !staticCurlOptionValue(command, option) {
			return false
		}
		switch option.Canonical {
		case "--get":
			finalGet = curlTelnetBooleanOptionEnabled(option)
		case "--include":
			showHeaders = curlTelnetBooleanOptionEnabled(option)
		case "--head":
			showHeaders = curlTelnetBooleanOptionEnabled(option)
		case "--no-head":
			showHeaders = false
		case "--remote-header-name":
			contentDisposition = curlTelnetBooleanOptionEnabled(option)
		case "--haproxy-protocol":
			haproxyProtocol = curlTelnetBooleanOptionEnabled(option)
		case "--disallow-username-in-url":
			disallowURLUser = curlTelnetBooleanOptionEnabled(option)
		case "--data", "--data-ascii", "--data-binary", "--json":
			hasPostData = true
			if strings.HasPrefix(option.Value, "@") {
				return false
			}
		case "--data-raw":
			hasPostData = true
		case "--data-urlencode":
			hasPostData = true
			if !curlTelnetDataURLEncodeIsInline(option.Value) {
				return false
			}
		case "--form", "--form-string":
			if !curlTelnetLiteralFormValid(option) {
				return false
			}
		case "--url-query":
			hasURLQuery = true
			if !curlTelnetURLQueryIsInline(option.Value) {
				return false
			}
		case "--continue-at":
			continueSet = true
			var valid bool
			continueOffset, continueCurrent, valid =
				curlTelnetContinueAtValue(option.Value)
			if !valid {
				return false
			}
		case "--doh-url":
			dohURLSet = true
			dohURL = option.Value
		case "--dump-header":
			dumpHeaderSet = true
			dumpHeader = option.Value
		case "--proxy-user":
			proxyUserSet = true
			proxyUser = option.Value
		case "--output-dir":
			outputDirSet = true
		case "--time-cond":
			if !curlTelnetKnownTimeCondition(option.Value) {
				return false
			}
		case "--happy-eyeballs-timeout-ms":
			finalHappyEyeballs = option.Value
		case "--keepalive-time":
			finalKeepaliveTime = option.Value
		case "--limit-rate":
			finalLimitRate = option.Value
		case "--local-port":
			finalLocalPort = option.Value
		case "--max-filesize":
			finalMaxFilesize = option.Value
		}
	}

	_, _, postDataValid := staticCurlPostDataBytes(command, parsed, group)
	if !postDataValid || !curlStaticFormSequenceValid(command, parsed, group) {
		return false
	}
	if hasPostData && finalGet &&
		(!explicitTelnet || !staticCurlGETPostDataValid(command, parsed, group)) {
		return false
	}
	if hasURLQuery &&
		(!explicitTelnet ||
			!staticCurlFTPURLQueryOptionsValid(command, parsed, group)) {
		return false
	}
	if continueSet && (continueCurrent || continueOffset != 0) {
		return false
	}
	if dohURLSet && dohURL != "" {
		return false
	}
	if dumpHeaderSet && dumpHeader != "-" &&
		(dumpHeader != "/dev/null" || !curlPOSIXNullDeviceAvailable(command)) {
		return false
	}
	if proxyUserSet {
		if !curlTelnetUserAvoidsPrompt(proxyUser, false) {
			return false
		}
		if _, _, valid := curlDecodedProxyCredentials(proxyUser); !valid {
			return false
		}
	}
	if outputDirSet && target.Output != curlOutputStdout {
		return false
	}
	if contentDisposition && (showHeaders || continueCurrent) || haproxyProtocol {
		return false
	}
	if disallowURLUser {
		_, _, userPresent, _, _, valid := curlTelnetURLParts(telnetTarget)
		if !valid || userPresent {
			return false
		}
	}
	if finalHappyEyeballs != "" {
		value, valid := curlUnsignedLong(finalHappyEyeballs)
		if !valid || value != 200 {
			return false
		}
	}
	if finalKeepaliveTime != "" {
		value, valid := curlUnsignedLong(finalKeepaliveTime)
		if !valid || value != 0 {
			return false
		}
	}
	if finalLimitRate != "" {
		value, valid := curlTelnetSizeValue(finalLimitRate)
		if !valid || value != 0 {
			return false
		}
	}
	if finalLocalPort != "" {
		start, _, hasRange, valid := curlTelnetLocalPortValue(finalLocalPort)
		if !valid || start != 0 || hasRange {
			return false
		}
	}
	if finalMaxFilesize != "" {
		value, valid := curlTelnetSizeValue(finalMaxFilesize)
		if !valid || value != 0 {
			return false
		}
	}
	return true
}

func curlTargetHasExplicitTelnetScheme(value string) bool {
	delimiter := strings.IndexByte(value, ':')
	return delimiter > 0 && curlASCIIEqualFold(value[:delimiter], "telnet")
}

func curlTelnetBooleanOptionEnabled(option curlOptionToken) bool {
	return !strings.HasPrefix(option.Name, "--no-")
}

func curlTelnetDataURLEncodeIsInline(value string) bool {
	return strings.Contains(value, "=") || !strings.Contains(value, "@")
}

func curlTelnetURLQueryIsInline(value string) bool {
	return strings.HasPrefix(value, "+") ||
		curlTelnetDataURLEncodeIsInline(value)
}

func curlTelnetContinueAtValue(value string) (int64, bool, bool) {
	if value == "-" {
		return 0, true, true
	}
	offset, valid := curlTelnetNonnegativeOffT(value)
	return offset, false, valid
}

func curlTelnetNonnegativeOffT(value string) (int64, bool) {
	// curlx_strtoofft skips SP/HTAB rather than the full C whitespace set.
	// Its positive-only mode accepts an optional plus but rejects every minus,
	// including -0. Keep this portable across curl's off_t/long build split.
	value = strings.TrimLeft(value, " \t")
	if value == "" {
		return 0, false
	}
	if value[0] == '+' {
		value = value[1:]
	}
	if value == "" {
		return 0, false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 63)
	return int64(parsed), err == nil
}

func curlTelnetSignedDecimal(value string) (int64, bool) {
	value = strings.TrimLeftFunc(value, curlCWhitespace)
	if value == "" {
		return 0, false
	}
	index := 0
	if value[index] == '+' || value[index] == '-' {
		index++
	}
	if index == len(value) {
		return 0, false
	}
	for ; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	return parsed, err == nil
}

func curlTelnetKnownTimeCondition(value string) bool {
	if value != "" && (value[0] == '+' || value[0] == '-' || value[0] == '=') {
		value = value[1:]
	}
	_, err := time.Parse(time.RFC1123, value)
	return err == nil
}

func curlTelnetLiteralFormValid(option curlOptionToken) bool {
	if _, valid, _ := curlStaticFormPayloads(option); !valid {
		return false
	}
	if option.Canonical == "--form-string" {
		return true
	}
	if option.Canonical != "--form" {
		return false
	}
	_, specification, found := strings.Cut(option.Value, "=")
	if !found || strings.HasPrefix(specification, "@") ||
		strings.HasPrefix(specification, "<") {
		return false
	}
	position := curlSkipFormSpace(specification, 0)
	_, position = curlFormParameterWord(specification, position)
	typeActive := false
	for position < len(specification) {
		if specification[position] != ';' {
			return false
		}
		position = curlSkipFormSpace(specification, position+1)
		switch {
		case !typeActive && curlFormHasFoldedPrefix(specification, position, "type="):
			position = curlSkipFormSpace(specification, position+len("type="))
			var valid bool
			position, valid = curlFormTypePrefix(specification, position)
			if !valid {
				return false
			}
			for position < len(specification) && specification[position] != ';' {
				position++
			}
			typeActive = true
		case curlFormHasFoldedPrefix(specification, position, "filename="):
			typeActive = false
			position = curlSkipFormSpace(specification, position+len("filename="))
			_, position = curlFormParameterWord(specification, position)
		case curlFormHasFoldedPrefix(specification, position, "headers="):
			typeActive = false
			position += len("headers=")
			if position < len(specification) &&
				(specification[position] == '@' || specification[position] == '<') {
				return false
			}
			position = curlSkipFormSpace(specification, position)
			_, position = curlFormParameterWord(specification, position)
		case curlFormHasFoldedPrefix(specification, position, "encoder="):
			typeActive = false
			position = curlSkipFormSpace(specification, position+len("encoder="))
			_, position = curlFormParameterWord(specification, position)
		case typeActive:
			for position < len(specification) && specification[position] != ';' {
				position++
			}
		default:
			_, position = curlFormParameterWord(specification, position)
		}
	}
	return true
}

func curlTelnetBoundedValueValid(option curlOptionToken) bool {
	switch option.Canonical {
	case "--create-file-mode":
		value, valid := curlTelnetOctalLong(option.Value)
		return valid && value <= 0o777
	case "--delegation":
		return curlASCIIEqualFold(option.Value, "none")
	case "--expect100-timeout":
		_, valid := curlSecondsMilliseconds(option.Value)
		return valid
	case "--happy-eyeballs-timeout-ms", "--keepalive-time", "--parallel-max",
		"--tftp-blksize":
		_, valid := curlUnsignedLong(option.Value)
		return valid
	case "--hostpubmd5":
		return len(option.Value) == 32
	case "--limit-rate", "--max-filesize":
		_, valid := curlTelnetSizeValue(option.Value)
		return valid
	case "--local-port":
		_, _, _, valid := curlTelnetLocalPortValue(option.Value)
		return valid
	case "--max-redirs":
		value, valid := curlTelnetSignedLong(option.Value)
		return valid && value >= -1
	case "--proto", "--proto-redir":
		value := option.Value
		if value != "" && (value[0] == '+' || value[0] == '=') {
			value = value[1:]
		}
		return curlASCIIEqualFold(value, "telnet")
	case "--rate":
		return curlTelnetRateValid(option.Value)
	case "--tls-max":
		switch option.Value {
		case "default", "1.0", "1.1", "1.2", "1.3":
			return true
		default:
			return false
		}
	case "--trace-config":
		return curlTelnetTraceConfigValid(option.Value)
	case "--variable":
		return curlTelnetLiteralVariableValid(option.Value)
	default:
		return false
	}
}

func curlTelnetOctalLong(value string) (uint64, bool) {
	value = strings.TrimLeftFunc(value, curlCWhitespace)
	if value == "" {
		return 0, false
	}
	negative := false
	if value[0] == '+' || value[0] == '-' {
		negative = value[0] == '-'
		value = value[1:]
	}
	if value == "" {
		return 0, false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '7' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(value, 8, 64)
	if err != nil || parsed > curlPortableLongMaximum() || negative && parsed != 0 {
		return 0, false
	}
	return parsed, true
}

func curlTelnetSignedLong(value string) (int64, bool) {
	parsed, valid := curlTelnetSignedDecimal(value)
	if !valid || parsed < -int64(curlPortableLongMaximum())-1 ||
		parsed > int64(curlPortableLongMaximum()) {
		return 0, false
	}
	return parsed, true
}

func curlTelnetSizeValue(value string) (int64, bool) {
	value = strings.TrimLeft(value, " \t")
	if value == "" {
		return 0, false
	}
	multiplier := int64(1)
	last := value[len(value)-1]
	switch last {
	case 'b', 'B':
		value = value[:len(value)-1]
	case 'k', 'K':
		value = value[:len(value)-1]
		multiplier = 1024
	case 'm', 'M':
		value = value[:len(value)-1]
		multiplier = 1024 * 1024
	case 'g', 'G':
		value = value[:len(value)-1]
		multiplier = 1024 * 1024 * 1024
	}
	parsed, valid := curlTelnetNonnegativeOffT(value)
	if !valid || parsed > int64(^uint64(0)>>1)/multiplier {
		return 0, false
	}
	return parsed * multiplier, true
}

func curlTelnetLocalPortValue(value string) (
	start uint64,
	end uint64,
	hasRange bool,
	valid bool,
) {
	index := 0
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	if index == 0 {
		return 0, 0, false, false
	}
	parsedStart, err := strconv.ParseUint(value[:index], 10, 64)
	if err != nil || parsedStart > 65535 {
		return 0, 0, false, false
	}
	if index == len(value) {
		return parsedStart, parsedStart, false, true
	}
	for index < len(value) && (value[index] == ' ' || value[index] == '\t') {
		index++
	}
	if index >= len(value) || value[index] != '-' {
		return 0, 0, false, false
	}
	index++
	for index < len(value) && (value[index] == ' ' || value[index] == '\t') {
		index++
	}
	endStart := index
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		index++
	}
	if endStart == index || index != len(value) || index-endStart > 6 {
		return 0, 0, false, false
	}
	parsedEnd, err := strconv.ParseUint(value[endStart:index], 10, 64)
	if err != nil || parsedEnd > 65535 || parsedEnd < parsedStart {
		return 0, 0, false, false
	}
	return parsedStart, parsedEnd, true, true
}

func curlTelnetRateValid(value string) bool {
	unit := byte('h')
	number := value
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		if slash+1 >= len(value) {
			return false
		}
		number = value[:slash]
		unit = value[slash+1]
	}
	if len(number) > 25 {
		return false
	}
	denominator, valid := curlUnsignedLong(number)
	if !valid || denominator == 0 {
		return false
	}
	numerator := uint64(60 * 60 * 1000)
	switch unit {
	case 's':
		numerator = 1000
	case 'm':
		numerator = 60 * 1000
	case 'h':
	case 'd':
		numerator = 24 * 60 * 60 * 1000
	default:
		return false
	}
	return denominator <= numerator
}

func curlTelnetTraceConfigValid(value string) bool {
	start := 0
	for start < len(value) {
		for start < len(value) && (value[start] == ',' || value[start] == ' ') {
			start++
		}
		if start == len(value) {
			return true
		}
		end := start
		for end < len(value) && value[end] != ',' && value[end] != ' ' {
			end++
		}
		token := value[start:end]
		if token != "" && (token[0] == '+' || token[0] == '-') {
			token = token[1:]
		}
		if !curlASCIIEqualFold(token, "ids") &&
			!curlASCIIEqualFold(token, "time") {
			return false
		}
		start = end
	}
	return true
}

func curlTelnetLiteralVariableValid(value string) bool {
	name, _, found := strings.Cut(value, "=")
	if !found || len(name) == 0 || len(name) >= 128 {
		return false
	}
	for index := range len(name) {
		character := name[index]
		if character != '_' &&
			(character < '0' || character > '9') &&
			(character < 'A' || character > 'Z') &&
			(character < 'a' || character > 'z') {
			return false
		}
	}
	return true
}

func curlTelnetNullSinkValueValid(
	command CommandFact,
	option curlOptionToken,
) bool {
	if (option.Canonical == "--trace" || option.Canonical == "--trace-ascii") &&
		option.Value == "-" {
		return true
	}
	return option.Value == "/dev/null" && curlPOSIXNullDeviceAvailable(command)
}

func curlTelnetEffectiveUser(
	command CommandFact,
	parsed curlArgvParse,
	target curlTransferTarget,
	telnetTarget string,
) (string, bool, bool) {
	if option, present := curlFinalGroupOption(parsed, target.Group, "--user"); present {
		bearer, bearerPresent := curlFinalGroupOption(
			parsed, target.Group, "--oauth2-bearer",
		)
		if !staticCurlOptionValue(command, option) ||
			!curlTelnetUserAvoidsPrompt(
				option.Value,
				bearerPresent && bearer.Value != "",
			) {
			return "", false, false
		}
		user, _, _ := strings.Cut(option.Value, ":")
		if curlTelnetValueHasHighByte(user) {
			return "", false, false
		}
		return user, true, true
	}

	_, user, userSet, _, _, valid := curlTelnetURLParts(telnetTarget)
	if !valid {
		return "", false, false
	}
	if !userSet {
		return "", false, true
	}
	if curlTelnetValueHasHighByte(user) {
		return "", false, false
	}
	return user, true, true
}

func curlTelnetEffectiveTarget(
	command CommandFact,
	parsed curlArgvParse,
	target curlTransferTarget,
) (string, bool) {
	protoDefault := ""
	if option, present := curlFinalGroupOption(
		parsed, target.Group, "--proto-default",
	); present {
		if !staticCurlOptionValue(command, option) ||
			!curlTelnetProtoDefaultValueValid(option.Value) {
			return "", false
		}
		protoDefault = option.Value
	}
	if delimiter := strings.IndexByte(target.Value, ':'); delimiter > 0 &&
		curlASCIIEqualFold(target.Value[:delimiter], "telnet") {
		return curlCanonicalTelnetURL(target.Value)
	}
	if strings.Contains(target.Value, "://") {
		return "", false
	}
	if !curlASCIIEqualFold(protoDefault, "telnet") ||
		strings.HasPrefix(target.Value, "//") {
		return "", false
	}
	return "telnet://" + target.Value, true
}

func curlTargetSelectsTelnet(parsed curlArgvParse, target curlTransferTarget) bool {
	if delimiter := strings.IndexByte(target.Value, ':'); delimiter > 0 {
		return curlASCIIEqualFold(target.Value[:delimiter], "telnet")
	}
	option, present := curlFinalGroupOption(
		parsed, target.Group, "--proto-default",
	)
	return present && curlASCIIEqualFold(option.Value, "telnet")
}

func curlCanonicalTelnetURL(value string) (string, bool) {
	delimiter := strings.IndexByte(value, ':')
	if delimiter <= 0 || !curlASCIIEqualFold(value[:delimiter], "telnet") {
		return "", false
	}
	remainder := value[delimiter+1:]
	slashes := 0
	for slashes < len(remainder) && remainder[slashes] == '/' {
		slashes++
	}
	if slashes < 1 || slashes > 3 || slashes == len(remainder) {
		return "", false
	}
	return "telnet://" + remainder[slashes:], true
}

func curlTelnetNumericValueIsZero(canonical string, value string) bool {
	switch canonical {
	case "--connect-timeout", "--max-time":
		milliseconds, valid := curlSecondsMilliseconds(value)
		return valid && milliseconds == 0
	case "--retry", "--retry-delay", "--retry-max-time", "--speed-limit",
		"--speed-time":
		parsed, valid := curlUnsignedLong(value)
		return valid && parsed == 0
	default:
		return false
	}
}

func curlTelnetProtoDefaultValueValid(value string) bool {
	// Curl validates every occurrence against the protocols compiled into the
	// selected binary. ActionFacts does not identify that binary or expose its
	// runtime protocol manifest, so a non-Telnet value is capability-dependent
	// even when a later occurrence overwrites it. The lane already requires
	// Telnet itself; keep only that build-independent premise authoritative.
	return curlASCIIEqualFold(value, "telnet")
}

func staticCurlHeaderSetupValid(
	command CommandFact,
	option curlOptionToken,
) bool {
	if !staticCurlOptionValue(command, option) {
		return false
	}
	if !strings.HasPrefix(option.Value, "@") {
		return true
	}
	return option.Value == "@/dev/null" &&
		curlPOSIXNullDeviceAvailable(command)
}

func curlTelnetUserAvoidsPrompt(value string, bearerSet bool) bool {
	return strings.IndexByte(value, 0) < 0 &&
		(strings.Contains(value, ":") || strings.HasPrefix(value, ";") ||
			bearerSet)
}

func curlTelnetInertFlag(option curlOptionToken) bool {
	if option.TakesValue || option.ValuePresent {
		return false
	}
	if curlTelnetFeatureDependentPositiveFlag(option) {
		return false
	}
	switch option.Role {
	case curlOptionNeutral, curlOptionHead, curlOptionNoHead,
		curlOptionNoRemoteName, curlOptionNoRemoteNameAll,
		curlOptionTelnetProof:
		return true
	default:
		return false
	}
}

func curlTelnetFeatureDependentPositiveFlag(option curlOptionToken) bool {
	switch option.Canonical {
	case "--metalink", "--proxy-http2", "--proxy-negotiate", "--proxy-ntlm",
		"--tcp-fastopen", "--wdebug":
		// Both spellings are closed: curl 8.7.1 either capability-checks the
		// negative form too, always errors, or ignores the toggle and enables
		// platform-sensitive TCP Fast Open.
		return true
	}
	if strings.HasPrefix(option.Name, "--no-") {
		return false
	}
	switch option.Canonical {
	case "--compressed", "--ftp-ssl-control", "--http2",
		"--http2-prior-knowledge", "--http3", "--http3-only", "--negotiate",
		"--ntlm", "--ntlm-wb", "--ssl", "--ssl-reqd":
		return true
	default:
		return false
	}
}

func curlTelnetOutputRedirectsSafe(command CommandFact) bool {
	if len(command.Redirects) == 0 {
		return true
	}
	if command.Dialect != DialectPOSIX {
		return false
	}
	for _, redirect := range command.Redirects {
		if redirect.Expands || redirect.Target != "/dev/null" {
			return false
		}
		readNull := redirect.FD == 0 && redirect.Access == PathAccessRead
		writeNull := (redirect.FD == -1 || redirect.FD == 1 || redirect.FD == 2) &&
			(redirect.Access == PathAccessWrite ||
				redirect.Access == PathAccessAppend)
		if !readNull && !writeNull {
			return false
		}
	}
	return true
}

func curlTelnetOptionWireValues(
	options []string,
	user string,
	userSet bool,
) ([]string, bool) {
	ttype := ""
	ttypeSet := false
	xDisplay := ""
	xDisplaySet := false
	environmentLength := 4
	var environment []string
	if userSet {
		// check_telnet_options prepends USER through a 256-byte snprintf
		// buffer. "USER," occupies five bytes, leaving at most 250 username
		// bytes plus the NUL terminator. The resulting entry is then inserted
		// before every explicit NEW_ENV option.
		if len(user) > 250 {
			user = user[:250]
		}
		environmentLength += 6 + len(user)
		environment = append(environment, "USER")
		if user != "" {
			environment = append(environment, user)
		}
	}
	for _, option := range options {
		name, value, present := strings.Cut(option, "=")
		if !present || strings.IndexByte(value, 0) >= 0 {
			return nil, false
		}
		if curlTelnetValueHasHighByte(value) {
			// Curl silently ignores a non-ASCII value before it validates the
			// option name. An earlier valid setting therefore remains active.
			continue
		}
		switch {
		case curlASCIIEqualFold(name, "TTYPE"):
			if len(value) >= 32 {
				return nil, false
			}
			ttype = value
			ttypeSet = true
		case curlASCIIEqualFold(name, "XDISPLOC"):
			if len(value) >= 128 {
				return nil, false
			}
			xDisplay = value
			xDisplaySet = true
		case curlASCIIEqualFold(name, "NEW_ENV"):
			// libcurl uses a fixed 2048-byte negotiation buffer. Each entry
			// replaces at most its first comma with a one-byte VALUE marker,
			// so the encoded entry occupies len(value)+1 bytes. Entries that do
			// not fit are skipped without preventing later short entries.
			entryLength := len(value) + 1
			if environmentLength+entryLength >= 2048-6 {
				continue
			}
			environmentLength += entryLength
			variable, environmentValue, hasValue := strings.Cut(value, ",")
			if variable != "" {
				environment = append(environment, variable)
			}
			if hasValue && environmentValue != "" {
				environment = append(environment, environmentValue)
			}
		case curlASCIIEqualFold(name, "WS"):
			if !curlTelnetWindowSizeValid(value) {
				return nil, false
			}
		case curlASCIIEqualFold(name, "BINARY"):
			// Curl uses atoi: exactly 1 enables binary negotiation and every
			// other 7-bit spelling disables it. Neither form carries candidate
			// bytes in the modeled peer-controlled subnegotiations.
		default:
			return nil, false
		}
	}
	values := make([]string, 0, 2+len(environment))
	if ttypeSet && ttype != "" {
		values = append(values, ttype)
	}
	if xDisplaySet && xDisplay != "" {
		values = append(values, xDisplay)
	}
	return append(values, environment...), true
}

func curlTelnetValueHasHighByte(value string) bool {
	for index := range len(value) {
		if value[index] >= 0x80 {
			return true
		}
	}
	return false
}

func curlTelnetWindowSizeValid(value string) bool {
	width, delimiter, valid := curlTelnetStrtoulPrefix(value)
	if !valid || delimiter >= len(value) ||
		value[delimiter] != 'x' && value[delimiter] != 'X' {
		return false
	}
	height, _, valid := curlTelnetStrtoulPrefix(value[delimiter+1:])
	return valid && width != 0 && height != 0
}

func curlTelnetStrtoulPrefix(value string) (uint64, int, bool) {
	index := 0
	for index < len(value) {
		switch value[index] {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			index++
		default:
			goto sign
		}
	}
sign:
	negative := false
	if index < len(value) && value[index] == '+' {
		index++
	} else if index < len(value) && value[index] == '-' {
		negative = true
		index++
	}
	start := index
	var parsed uint64
	unsignedLongMax := uint64(^uint32(0))
	if runtime.GOOS != "windows" && strconv.IntSize == 64 {
		unsignedLongMax = ^uint64(0)
	}
	overflow := false
	for index < len(value) && value[index] >= '0' && value[index] <= '9' {
		digit := uint64(value[index] - '0')
		if !overflow {
			if parsed > (unsignedLongMax-digit)/10 {
				overflow = true
			} else {
				parsed = parsed*10 + digit
			}
		}
		index++
	}
	if index == start || overflow {
		return 0, index, false
	}
	if negative {
		if unsignedLongMax == uint64(^uint32(0)) {
			parsed = uint64(-uint32(parsed))
		} else {
			parsed = -parsed
		}
	}
	return parsed, index, parsed <= 65535
}

// CurlProxyTransmittedMetadata keeps proxy-bound request bytes separate from
// origin-bound curl metadata. Each component is paired only with the explicit
// proxy destination that receives it.
type CurlProxyTransmittedMetadata struct {
	ProxyRequestComponents []TransmittedRequestComponent
}

// StaticCurlProxyUploadPayloads returns exact inline body bytes that curl sends
// in plaintext to an explicit HTTP(S) proxy. Only HTTP origin targets use the
// forward-proxy request form; HTTPS origin bodies travel inside the CONNECT
// tunnel and therefore are not proxy-visible plaintext candidates.
func StaticCurlProxyUploadPayloads(
	command CommandFact,
) []TransmittedRequestComponent {
	proxy, parsed, ok := staticCurlProxyDestination(command)
	if !ok || proxy.Scheme != "http" && proxy.Scheme != "https" {
		return nil
	}
	hasHTTPOrigin := false
	httpGet := false
	for _, option := range parsed.Options {
		if option.Canonical == "--get" {
			httpGet = option.Name != "--no-get"
		}
	}
	if httpGet {
		// Curl moves data options into the URL query under --get; they are
		// not request-body bytes in the forward-proxy request.
		return nil
	}
	for _, target := range parsed.Targets {
		targetFact, valid := webTargetFact(
			command.ID,
			target.Value,
			NetworkUpload,
		)
		if !valid {
			return nil
		}
		hasHTTPOrigin = hasHTTPOrigin || targetFact.Scheme == "http"
	}
	if !hasHTTPOrigin {
		return nil
	}

	payloads := StaticCurlUploadPayloads(command)
	if len(payloads) == 0 {
		return nil
	}
	components := make([]TransmittedRequestComponent, 0, len(payloads))
	for _, payload := range payloads {
		components = append(components, TransmittedRequestComponent{
			Value:  payload,
			Scheme: proxy.Scheme,
			Host:   proxy.Host,
			Port:   proxy.Port,
		})
	}
	return components
}

// StaticCurlProxyTransmittedMetadata returns literal credentials and custom
// headers that a closed curl invocation can transmit to one explicit HTTP(S)
// proxy. This uses the same argv-only/no-ambient-defaults assumption as the
// origin metadata proof: absent --noproxy means there is no argv proxy bypass,
// while a final explicit nonempty --noproxy closes this lane.
func staticCurlHTTPProxyTransmittedMetadata(
	command CommandFact,
) CurlProxyTransmittedMetadata {
	proxy, parsed, ok := staticCurlProxyDestination(command)
	if !ok || proxy.Scheme != "http" && proxy.Scheme != "https" {
		return CurlProxyTransmittedMetadata{}
	}
	component := func(value string) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value:  value,
			Scheme: proxy.Scheme,
			Host:   proxy.Host,
			Port:   proxy.Port,
		}
	}

	lastProxy := -1
	lastProxyUser := -1
	proxyAuthorizationOverridden := false
	ordinaryProxyAuthorizationOverridden := false
	metadata := CurlProxyTransmittedMetadata{}
	proxyTunnel := curlProxyTunnelEnabled(parsed, parsed.Targets[0].Group)
	formBody := false
	separateProxyHeaders := false
	for _, option := range parsed.Options {
		formBody = formBody || option.Canonical == "--form" ||
			option.Canonical == "--form-string"
		separateProxyHeaders = separateProxyHeaders ||
			option.Canonical == "--proxy-header"
	}
	ordinaryHeaderTargets := parsed.Targets
	if separateProxyHeaders {
		ordinaryHeaderTargets = nil
		if !proxyTunnel {
			for _, target := range parsed.Targets {
				if strings.HasPrefix(strings.ToLower(target.Value), "http://") {
					ordinaryHeaderTargets = append(ordinaryHeaderTargets, target)
				}
			}
		}
	}
	for index, option := range parsed.Options {
		switch option.Canonical {
		case "--proxy", "--proxy1.0", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname":
			if option.ValuePresent {
				lastProxy = index
			}
		case "--proxy-user":
			if option.ValuePresent {
				lastProxyUser = index
			}
		case "--proxy-header":
			if !option.ValuePresent || !staticCurlOptionValue(command, option) ||
				strings.HasPrefix(option.Value, "@") {
				return CurlProxyTransmittedMetadata{}
			}
			if curlHeaderOverridesHTTPField(
				option.Value,
				"proxy-authorization",
			) {
				proxyAuthorizationOverridden = true
			}
			if curlProxyHeaderCandidateIsTransmitted(
				option.Value,
				parsed.Targets,
				proxy.Scheme,
				proxyTunnel,
				formBody,
			) {
				metadata.ProxyRequestComponents = append(
					metadata.ProxyRequestComponents,
					component(option.Value),
				)
			}
		case "--header":
			if curlProxyHeaderCandidateIsTransmitted(
				option.Value,
				ordinaryHeaderTargets,
				proxy.Scheme,
				proxyTunnel && !separateProxyHeaders,
				formBody,
			) {
				metadata.ProxyRequestComponents = append(
					metadata.ProxyRequestComponents,
					component(option.Value),
				)
			}
			if !separateProxyHeaders &&
				curlHeaderOverridesHTTPField(
					option.Value,
					"proxy-authorization",
				) {
				ordinaryProxyAuthorizationOverridden = true
			}
		}
	}
	credentials := ""
	candidate := false
	if lastProxyUser >= 0 {
		proxyUser := parsed.Options[lastProxyUser]
		if !staticCurlOptionValue(command, proxyUser) {
			return CurlProxyTransmittedMetadata{}
		}
		var valid bool
		credentials, candidate, valid =
			curlDecodedProxyCredentials(proxyUser.Value)
		if !valid {
			return CurlProxyTransmittedMetadata{}
		}
	}
	if lastProxy < 0 {
		return CurlProxyTransmittedMetadata{}
	}
	proxyOption := parsed.Options[lastProxy]
	_, urlCredentials, present, valid := staticCurlHTTPProxyFact(
		command.ID,
		proxyOption.Canonical,
		proxyOption.Value,
	)
	if !valid {
		return CurlProxyTransmittedMetadata{}
	}
	if present {
		credentials = urlCredentials
		candidate = true
	}
	if candidate && !proxyAuthorizationOverridden &&
		!ordinaryProxyAuthorizationOverridden {
		metadata.ProxyRequestComponents = append(
			metadata.ProxyRequestComponents,
			component(credentials),
		)
	}
	// This HTTP-only caller rejected a SOCKS destination above. An explicit
	// http(s):// scheme overrides a SOCKS-named option alias, so every remaining
	// validated non-tunnel destination uses HTTP forward request form.
	if proxyTunnel {
		return metadata
	}
	requestProjection, valid := staticCurlHTTPRequestComponentProjection(
		command,
		parsed,
		parsed.Targets[0].Group,
	)
	if !valid {
		return CurlProxyTransmittedMetadata{}
	}
	getPostData, valid := staticCurlGETPostDataProjection(
		command,
		parsed,
		parsed.Targets[0].Group,
	)
	if !valid {
		return CurlProxyTransmittedMetadata{}
	}
	for _, target := range parsed.Targets {
		if !strings.HasPrefix(strings.ToLower(target.Value), "http://") {
			continue
		}
		if requestProjection.requestTargetSet {
			if requestProjection.requestTarget != "" {
				metadata.ProxyRequestComponents = append(
					metadata.ProxyRequestComponents,
					component(requestProjection.requestTarget),
				)
			}
			continue
		}
		if path := rawHTTPURLPath(target.Value); path != "/" &&
			curlURLPathBytesPreserved(path) {
			metadata.ProxyRequestComponents = append(
				metadata.ProxyRequestComponents,
				component(path),
			)
		}
		if query := rawURLQuery(target.Value); query != "" && visibleASCII(query) {
			metadata.ProxyRequestComponents = append(
				metadata.ProxyRequestComponents,
				component(query),
			)
		}
		for _, query := range requestProjection.urlQueries {
			metadata.ProxyRequestComponents = append(
				metadata.ProxyRequestComponents,
				component(query),
			)
		}
		if getPostData != "" {
			metadata.ProxyRequestComponents = append(
				metadata.ProxyRequestComponents,
				component(getPostData),
			)
		}
	}
	return metadata
}

// StaticCurlProxyTransmittedMetadata returns literal bytes that a closed curl
// invocation can expose to an exact explicit proxy. HTTP proxy metadata and
// FTP control-channel metadata use separate protocol proofs, then share the
// same proxy-bound request-component representation.
func StaticCurlProxyTransmittedMetadata(
	command CommandFact,
) CurlProxyTransmittedMetadata {
	metadata := staticCurlHTTPProxyTransmittedMetadata(command)
	metadata.ProxyRequestComponents = append(
		metadata.ProxyRequestComponents,
		StaticCurlSOCKSProxyCredentialComponents(command)...,
	)
	metadata.ProxyRequestComponents = append(
		metadata.ProxyRequestComponents,
		staticCurlFTPProxyRequestComponents(command)...,
	)
	return metadata
}

// StaticCurlSOCKSProxyCredentialComponents returns the final static username
// and password fields that a closed curl 8.7.1 command can expose to one
// explicit SOCKS peer. SOCKS4 transmits only the username. SOCKS5 transmits
// the two fields separately and only when username/password authentication is
// enabled and selected by the server.
//
// The shared destination proof owns direct HTTP(S)/FTP(S) routes and a sole
// SOCKS preproxy. A separately closed FTP route owns the two-hop
// SOCKS-preproxy + HTTP-main case: --proxy-user belongs to the main HTTP proxy,
// while only URL credentials belong to that SOCKS preproxy.
func StaticCurlSOCKSProxyCredentialComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	proxy, parsed, ok := staticCurlProxyDestination(command)
	chainProxyIndex := -1
	chainProxyCanonical := ""
	chainGroup := 0
	if !ok {
		proxy, parsed, chainGroup, chainProxyIndex, chainProxyCanonical, ok =
			staticCurlFTPSOCKSPreproxyCredentialRoute(command)
	}
	if !ok || proxy.Scheme != "tcp" || len(command.Redirects) != 0 ||
		command.PipelineID != 0 || len(parsed.Targets) == 0 {
		return nil
	}
	target := parsed.Targets[0]
	if target.Group != 0 || chainProxyIndex >= 0 && target.Group != chainGroup {
		return nil
	}

	lastProxy := -1
	lastPreproxy := -1
	lastProxyUser := -1
	for index, option := range parsed.Options {
		if option.Group != target.Group || !option.Known {
			return nil
		}
		switch option.Canonical {
		case "--proxy", "--proxy1.0", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname":
			lastProxy = index
		case "--preproxy":
			lastPreproxy = index
		case "--proxy-user":
			lastProxyUser = index
		}
	}
	disabledMainCanonical := ""
	if chainProxyIndex < 0 && lastProxy >= 0 {
		option := parsed.Options[lastProxy]
		if option.Canonical == "--proxy" && option.Value == "" {
			lastProxy = -1
		} else if curlProxyDecodedControlUserinfoDisables(
			command.ID,
			option.Canonical,
			option.Value,
		) {
			disabledMainCanonical = option.Canonical
			lastProxy = -1
		}
	}
	if chainProxyIndex < 0 && lastProxy < 0 && lastPreproxy < 0 {
		return nil
	}
	proxyIndex := chainProxyIndex
	proxyCanonical := chainProxyCanonical
	if proxyIndex < 0 {
		proxyIndex = lastProxy
	}
	if proxyIndex < 0 {
		proxyIndex = lastPreproxy
		var canonicalValid bool
		proxyCanonical, canonicalValid = curlStandalonePreproxyCanonical(
			parsed.Options[proxyIndex].Value,
			disabledMainCanonical,
		)
		if !canonicalValid {
			return nil
		}
	}
	proxyOption := parsed.Options[proxyIndex]
	if proxyCanonical == "" {
		proxyCanonical = proxyOption.Canonical
	}
	_, _, _, socks, valid := staticCurlProxyFact(
		command.ID,
		proxyCanonical,
		proxyOption.Value,
	)
	if !valid || !socks {
		return nil
	}

	username := ""
	password := ""
	candidate := false
	if chainProxyIndex < 0 && lastProxyUser >= 0 {
		var fieldsValid bool
		username, password, candidate, fieldsValid =
			curlDecodedProxyCredentialFields(parsed.Options[lastProxyUser].Value)
		if !fieldsValid {
			return nil
		}
	}
	urlUser, urlPassword, urlCredentials, fieldsValid :=
		curlProxyURLCredentialFields(proxyOption.Value)
	if !fieldsValid {
		return nil
	}
	if urlCredentials {
		username = urlUser
		password = urlPassword
		candidate = true
	}
	if !candidate || len(username) > 255 {
		return nil
	}

	socks4 := curlProxyUsesSOCKS4(
		proxyCanonical,
		proxyOption.Value,
	)
	if !socks4 && !curlSOCKS5BasicAuthenticationEnabled(parsed, target.Group) {
		return nil
	}
	component := func(value string) TransmittedRequestComponent {
		return TransmittedRequestComponent{
			Value: value, Scheme: proxy.Scheme, Host: proxy.Host, Port: proxy.Port,
		}
	}
	if socks4 {
		if username == "" {
			return nil
		}
		return []TransmittedRequestComponent{component(username)}
	}
	if len(password) > 255 {
		return nil
	}
	components := make([]TransmittedRequestComponent, 0, 2)
	if username != "" {
		components = append(components, component(username))
	}
	if password != "" {
		components = append(components, component(password))
	}
	return components
}

func staticCurlFTPSOCKSPreproxyCredentialRoute(
	command CommandFact,
) (NetworkFact, curlArgvParse, int, int, string, bool) {
	empty := func() (NetworkFact, curlArgvParse, int, int, string, bool) {
		return NetworkFact{}, curlArgvParse{}, 0, -1, "", false
	}
	if (command.Dialect != DialectPOSIX && command.Dialect != DialectArgv) ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 ||
		command.Program != "curl" || len(command.Argv) == 0 ||
		command.Executable != command.Argv[0] ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") ||
		len(command.Arguments) != len(command.Argv) {
		return empty()
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return empty()
		}
	}

	parsed := parseCurlArgv(command.Argv)
	nullConfigOnly := staticCurlPOSIXNullConfigOnly(command, parsed)
	if (!parsed.Complete && !nullConfigOnly) || parsed.ConfigOpaque ||
		parsed.Preview || parsed.EmptyTransferGroup ||
		!parsed.hasValidOptionValues() || len(parsed.Targets) == 0 ||
		!curlRangeOptionsValid(parsed) ||
		!staticCurlFTPEagerPreparseValid(command, parsed) ||
		!staticCurlFTPParallelSetupValid(command, parsed) {
		return empty()
	}
	group := parsed.Targets[0].Group
	if group != 0 || !curlGroupTargetsAreFTPFamily(parsed, group) ||
		!staticCurlFTPGroupSetupValid(command, parsed, group) ||
		!staticCurlGETPostDataValid(command, parsed, group) ||
		!staticCurlFTPURLQueryOptionsValid(command, parsed, group) ||
		!curlStaticFormSequenceValid(command, parsed, group) ||
		!curlOriginRequestBuildAllowsPayload(command, parsed, group) {
		return empty()
	}
	for _, target := range parsed.Targets {
		if target.Group != group ||
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			!validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) {
			return empty()
		}
	}

	route, valid := staticCurlFTPProxyRoute(command, parsed, group)
	if !valid || route.Disabled || len(route.Networks) != 2 ||
		route.Networks[0].Scheme != "tcp" ||
		(route.Networks[1].Scheme != "http" &&
			route.Networks[1].Scheme != "https") {
		return empty()
	}
	lastPreproxy := -1
	for index, option := range parsed.Options {
		if option.Group == group && option.Canonical == "--preproxy" {
			lastPreproxy = index
		}
	}
	if lastPreproxy < 0 ||
		!curlExplicitSOCKSProxyURL(parsed.Options[lastPreproxy].Value) {
		return empty()
	}
	return route.Networks[0], parsed, group, lastPreproxy, "--proxy", true
}

// StaticCurlSOCKSProxyCredentialComponentsForFacts admits an exactly isolated
// curl child beneath transparent env/command/exec launchers. Ancestor
// redirects and pipelines remain outside this proof because they can prevent
// the SOCKS handshake from starting.
func StaticCurlSOCKSProxyCredentialComponentsForFacts(
	facts Facts,
	commandID int64,
) []TransmittedRequestComponent {
	command, valid := staticCurlCommandForFacts(facts, commandID)
	if !valid {
		return nil
	}
	return StaticCurlSOCKSProxyCredentialComponents(command)
}

func curlSOCKSCredentialInertFlag(option curlOptionToken) bool {
	if option.TakesValue || option.ValuePresent || option.Role != curlOptionNeutral {
		return false
	}
	switch option.Canonical {
	case "--disable", "--globoff", "--no-buffer", "--no-progress-meter",
		"--progress-bar", "--show-error", "--silent", "--verbose":
		return true
	default:
		return false
	}
}

func curlSOCKS5BasicAuthenticationEnabled(
	parsed curlArgvParse,
	group int,
) bool {
	const (
		basic = 1 << iota
		gssapi
	)
	authentication := 0
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--socks5-basic":
			if option.Name == "--no-socks5-basic" {
				authentication &^= basic
			} else {
				authentication |= basic
			}
		case "--socks5-gssapi":
			if option.Name == "--no-socks5-gssapi" {
				authentication &^= gssapi
			} else {
				authentication |= gssapi
			}
		}
	}
	// Curl leaves CURLOPT_SOCKS5_AUTH at libcurl's default when the CLI
	// bitmask is zero. That default includes username/password auth.
	return authentication == 0 || authentication&basic != 0
}

func staticCurlProxyDestination(
	command CommandFact,
) (NetworkFact, curlArgvParse, bool) {
	if command.Effect != EffectExecute || !command.ArgvComplete ||
		command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
		command.Program != "curl" || len(command.Argv) == 0 ||
		!staticCurlArgvIdentity(command) ||
		!staticCurlProgramIdentity(command) ||
		len(command.Arguments) != len(command.Argv) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	for index := range command.Argv {
		if !staticCommandArgumentAt(command, index) {
			return NetworkFact{}, curlArgvParse{}, false
		}
	}

	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	group := parsed.Targets[0].Group
	if !staticCurlNetrcSetupValid(command, parsed, group) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	if !staticCurlGETPostDataValid(command, parsed, group) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	if _, valid := staticCurlHTTPRequestComponentProjection(
		command,
		parsed,
		group,
	); !valid {
		return NetworkFact{}, curlArgvParse{}, false
	}
	if !curlStaticFormSequenceValid(command, parsed, group) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	lastProxy := -1
	lastPreproxy := -1
	lastNoProxy := -1
	lastProxyUser := -1
	fail := false
	failWithBody := false
	for index, option := range parsed.Options {
		if option.Group != group || option.Canonical == "--next" ||
			option.Role == curlOptionConfig {
			return NetworkFact{}, curlArgvParse{}, false
		}
		if !curlProxyOptionPreservesDestination(command, option) {
			return NetworkFact{}, curlArgvParse{}, false
		}
		if option.Role == curlOptionNetworkOverride {
			switch {
			case curlMainProxyOption(option.Canonical):
				lastProxy = index
			case option.Canonical == "--preproxy":
				lastPreproxy = index
			case option.Canonical == "--noproxy":
				lastNoProxy = index
			default:
				return NetworkFact{}, curlArgvParse{}, false
			}
		}
		if option.Canonical == "--proxy-user" && option.ValuePresent {
			lastProxyUser = index
		}
		if option.Canonical == "--fail" {
			fail = option.Name != "--no-fail"
		}
		if option.Canonical == "--fail-with-body" {
			failWithBody = option.Name != "--no-fail-with-body"
		}
	}
	disabledMainCanonical := ""
	if lastProxy >= 0 {
		option := parsed.Options[lastProxy]
		if option.Canonical == "--proxy" && option.Value == "" {
			lastProxy = -1
		} else if curlProxyDecodedControlUserinfoDisables(
			command.ID,
			option.Canonical,
			option.Value,
		) {
			disabledMainCanonical = option.Canonical
			lastProxy = -1
		}
	}
	if lastProxy < 0 && lastPreproxy < 0 ||
		lastProxy >= 0 && lastPreproxy >= 0 || fail && failWithBody {
		return NetworkFact{}, curlArgvParse{}, false
	}
	if lastNoProxy >= 0 {
		noProxy := parsed.Options[lastNoProxy]
		if !staticCurlOptionValue(command, noProxy) {
			return NetworkFact{}, curlArgvParse{}, false
		}
	}
	if lastProxyUser >= 0 {
		proxyUser := parsed.Options[lastProxyUser]
		if !staticCurlOptionValue(command, proxyUser) {
			return NetworkFact{}, curlArgvParse{}, false
		}
		_, _, valid := curlDecodedProxyCredentials(proxyUser.Value)
		if !valid {
			return NetworkFact{}, curlArgvParse{}, false
		}
	}

	hasFTPTarget := false
	for _, target := range parsed.Targets {
		lowerTarget := strings.ToLower(target.Value)
		if target.Group != group ||
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			!validLiteralRequestTarget(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			!strings.HasPrefix(lowerTarget, "http://") &&
				!strings.HasPrefix(lowerTarget, "https://") &&
				!strings.HasPrefix(lowerTarget, "ftp://") &&
				!strings.HasPrefix(lowerTarget, "ftps://") {
			return NetworkFact{}, curlArgvParse{}, false
		}
		targetFact, ok := webTargetFact(
			command.ID,
			target.Value,
			NetworkDownload,
		)
		if !ok || targetFact.Scheme != "http" && targetFact.Scheme != "https" &&
			targetFact.Scheme != "ftp" && targetFact.Scheme != "ftps" {
			return NetworkFact{}, curlArgvParse{}, false
		}
		hasFTPTarget = hasFTPTarget || targetFact.Scheme == "ftp" ||
			targetFact.Scheme == "ftps"
	}
	if lastNoProxy >= 0 && parsed.Options[lastNoProxy].Value != "" {
		noProxy := parsed.Options[lastNoProxy].Value
		proxyContact := false
		for _, target := range parsed.Targets {
			host, valid := curlNoProxyTargetHost(target.Value)
			if !valid {
				return NetworkFact{}, curlArgvParse{}, false
			}
			bypassed, valid := curlNoProxyMatches(noProxy, host)
			if !valid {
				return NetworkFact{}, curlArgvParse{}, false
			}
			proxyContact = proxyContact || !bypassed
		}
		if !proxyContact {
			return NetworkFact{}, curlArgvParse{}, false
		}
	}

	proxyIndex := lastProxy
	proxyCanonical := ""
	if proxyIndex < 0 {
		proxyIndex = lastPreproxy
		var canonicalValid bool
		proxyCanonical, canonicalValid = curlStandalonePreproxyCanonical(
			parsed.Options[proxyIndex].Value,
			disabledMainCanonical,
		)
		if !canonicalValid {
			return NetworkFact{}, curlArgvParse{}, false
		}
	}
	proxyOption := parsed.Options[proxyIndex]
	if proxyCanonical == "" {
		proxyCanonical = proxyOption.Canonical
	}
	if !staticCurlOptionValue(command, proxyOption) {
		return NetworkFact{}, curlArgvParse{}, false
	}
	proxy := NetworkFact{}
	ok := false
	if lastProxy >= 0 {
		proxy, _, _, ok = staticCurlHTTPProxyFact(
			command.ID,
			proxyCanonical,
			proxyOption.Value,
		)
	}
	if !ok {
		var socks bool
		proxy, socks, ok = staticCurlFTPProxyFact(
			command.ID,
			proxyCanonical,
			proxyOption.Value,
		)
		ok = ok && socks
		if ok {
			proxyUser := ""
			if lastProxyUser >= 0 {
				proxyUser = parsed.Options[lastProxyUser].Value
			}
			ok = curlSOCKS4UserWithinBounds(
				proxyCanonical,
				proxyOption.Value,
				proxyUser,
				true,
			)
			if ok && curlProxyUsesSOCKS4(
				proxyCanonical,
				proxyOption.Value,
			) && !curlProxyUsesSOCKS4A(
				proxyCanonical,
				proxyOption.Value,
			) {
				ok = curlSOCKS4TargetsEncodable(parsed, group)
			}
		}
	}
	if ok && !curlProxyPeerMatchesIPVersion(proxy, parsed, group) {
		ok = false
	}
	if ok && hasFTPTarget && proxy.Scheme != "tcp" {
		// Plain FTP through an HTTP proxy has forward-proxy semantics that the
		// dedicated FTP route owns. This shared extension is only for SOCKS
		// authentication, which is protocol-agnostic.
		ok = false
	}
	return proxy, parsed, ok
}

func staticCurlProgramIdentity(command CommandFact) bool {
	switch command.Dialect {
	case DialectPOSIX, DialectArgv:
		return exactCaseSensitivePOSIXProgram(&command, "curl")
	case DialectCMD:
		return command.Executable == "curl" || command.Executable == "curl.exe"
	case DialectPowerShell:
		// Unqualified curl is a PowerShell alias. Only the explicit native
		// executable can inherit curl's option and proxy grammar.
		return command.Executable == "curl.exe"
	default:
		return false
	}
}

func staticCurlArgvIdentity(command CommandFact) bool {
	if len(command.Argv) == 0 {
		return false
	}
	if command.Executable == command.Argv[0] {
		return true
	}
	return (command.Dialect == DialectCMD || command.Dialect == DialectPowerShell) &&
		windowsExactNativeExecutableIdentity(command.Argv[0], command.Executable)
}

func curlProxyPeerMatchesIPVersion(
	proxy NetworkFact,
	parsed curlArgvParse,
	group int,
) bool {
	ipv4Only, _ := curlEffectiveIPv4Only(parsed, group)
	return curlPeerMatchesAddressOptions(proxy.Host, ipv4Only, false)
}

func curlProxyOptionPreservesDestination(
	command CommandFact,
	option curlOptionToken,
) bool {
	if !option.Known || option.Role == curlOptionConfig ||
		option.Role == curlOptionPreview {
		return false
	}
	if option.Canonical == "--proto-default" {
		// The shared HTTP/FTP proxy proof interprets schemeless targets with
		// its own fallback. Keep protocol-default rewriting in the dedicated
		// Telnet projector so those targets cannot be misclassified as HTTP.
		return false
	}
	if option.Role == curlOptionNetworkOverride {
		return curlMainProxyOption(option.Canonical) ||
			option.Canonical == "--preproxy" || option.Canonical == "--noproxy"
	}
	if option.TakesValue && !staticCurlOptionValue(command, option) {
		return false
	}
	if option.Role == curlOptionUpload || option.Role == curlOptionRemoteName ||
		option.Role == curlOptionRemoteNameAll {
		// Upload-file sources can fail or drain stdin before a request is sent;
		// remote-name can fail before connect when a URL has no filename. This
		// body-proof lane models only deterministic inline request data and
		// output modes that cannot preempt the first request.
		return false
	}
	if curlUploadPayloadOption(option.Canonical) {
		return curlProxyInlinePayloadOptionValid(command, option)
	}
	if !curlProxyNumericOptionWithinPortableBounds(option) {
		return false
	}
	switch option.Canonical {
	case "--header", "--proxy-header", "--write-out":
		return !strings.HasPrefix(option.Value, "@")
	case "--stderr":
		return option.Value == "-" || option.Value == "/dev/null" &&
			curlPOSIXNullDeviceAvailable(command)
	case "--url-query":
		return true
	case "--cacert", "--cert", "--key", "--continue-at", "--dump-header":
		// These operands can deterministically abort before the first request;
		// their file/resume/output validity is not represented by ActionFacts.
		return false
	default:
		return true
	}
}

func curlProxyURLQueryOptionsValid(parsed curlArgvParse) bool {
	httpGetSet := false
	getQueryDataSet := false
	for _, option := range parsed.Options {
		if option.Canonical == "--get" {
			httpGetSet = option.Name != "--no-get"
		}
		getQueryDataSet = getQueryDataSet ||
			curlOptionProvidesGETQueryData(option.Canonical)
	}
	replaced := httpGetSet && getQueryDataSet
	var outputLengths []int
	for _, option := range parsed.Options {
		if option.Canonical != "--url-query" {
			continue
		}
		wireValue := ""
		valid := false
		if replaced {
			wireValue, valid = curlURLQueryConfigBytes(option.Value)
		} else {
			wireValue, valid = curlURLQueryOptionBytes(option.Value)
		}
		if !valid {
			return false
		}
		outputLengths = append(outputLengths, len(wireValue))
	}
	if replaced {
		return curlURLQueryConfigLengthsValid(outputLengths)
	}
	return curlURLQueryLengthsValid(parsed.Targets, outputLengths)
}

type curlHTTPRequestComponentProjection struct {
	requestTargetSet bool
	requestTarget    string
	urlQueries       []string
}

func staticCurlHTTPRequestComponentProjection(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) (curlHTTPRequestComponentProjection, bool) {
	projection := curlHTTPRequestComponentProjection{}
	lastRequestTarget := -1
	httpGetSet := false
	getQueryDataSet := false
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical == "--request-target" && option.ValuePresent {
			lastRequestTarget = index
		}
		if option.Canonical == "--get" {
			httpGetSet = option.Name != "--no-get"
		}
		getQueryDataSet = getQueryDataSet ||
			curlOptionProvidesGETQueryData(option.Canonical)
	}
	replaced := httpGetSet && getQueryDataSet
	fragmentSeen := false
	var outputLengths []int
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical != "--url-query" {
			continue
		}
		if !staticCurlOptionValue(command, option) {
			return curlHTTPRequestComponentProjection{}, false
		}
		wireValue := ""
		valid := false
		if replaced {
			wireValue, valid = curlURLQueryConfigBytes(option.Value)
		} else {
			wireValue, valid = curlURLQueryOptionBytes(option.Value)
		}
		if !valid {
			return curlHTTPRequestComponentProjection{}, false
		}
		// The full transformed value participates in curl's applicable bounds,
		// even though a raw '#' moves its suffix and all later values into the
		// client-side fragment rather than the HTTP request query.
		outputLengths = append(outputLengths, len(wireValue))
		if replaced {
			continue
		}
		prefix, _, fragment := strings.Cut(wireValue, "#")
		if !fragmentSeen && prefix != "" {
			projection.urlQueries = append(projection.urlQueries, prefix)
		}
		fragmentSeen = fragmentSeen || fragment
	}
	if replaced {
		// In curl 8.7.1, -G with a data option replaces --url-query as the
		// appended query source instead of combining the two. The CLI has already
		// produced config->query and applied its repeated-value builder cap, but
		// httpgetfields bypasses that value at the later URL API phase. Retain the
		// config lengths even though none remain request components or participate
		// in the final target-plus-query allocation.
		projection.urlQueries = nil
	}
	lengthsValid := curlURLQueryLengthsValid(parsed.Targets, outputLengths)
	if replaced {
		lengthsValid = curlURLQueryConfigLengthsValid(outputLengths)
	}
	if !lengthsValid {
		return curlHTTPRequestComponentProjection{}, false
	}
	projection.requestTargetSet = lastRequestTarget >= 0
	if lastRequestTarget >= 0 {
		requestTarget := parsed.Options[lastRequestTarget]
		if staticCurlOptionValue(command, requestTarget) &&
			curlHTTPRequestLineBytesPreserved(requestTarget.Value) {
			projection.requestTarget = requestTarget.Value
		}
	}
	return projection, true
}

func curlProxyNumericOptionWithinPortableBounds(option curlOptionToken) bool {
	switch option.Canonical {
	case "--retry", "--speed-limit", "--speed-time":
		_, valid := curlUnsignedLong(option.Value)
		return valid
	case "--retry-delay", "--retry-max-time":
		value, valid := curlUnsignedLong(option.Value)
		return valid && value <= curlPortableLongMaximum()/1000
	case "--connect-timeout", "--expect100-timeout", "--max-time":
		_, valid := curlSecondsMilliseconds(option.Value)
		return valid
	default:
		return true
	}
}

func curlProxyInlinePayloadOptionValid(
	command CommandFact,
	option curlOptionToken,
) bool {
	if !curlUploadPayloadOption(option.Canonical) ||
		!staticCurlOptionValue(command, option) ||
		curlUploadPayloadSourceUncertain(option) {
		return false
	}
	if _, literal, _ := staticCurlUploadPayloads(option); literal {
		return true
	}
	if option.Value != "" {
		return false
	}
	// These options accept an empty inline value and still issue the request.
	// Multipart options reject an empty operand in hasValidOptionValues.
	switch option.Canonical {
	case "--data", "--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--json":
		return true
	default:
		return false
	}
}

func staticCurlHTTPProxyFact(
	commandID int64,
	canonical string,
	value string,
) (NetworkFact, string, bool, bool) {
	if !validLiteralRequestTarget(value) {
		return NetworkFact{}, "", false, false
	}
	lower := strings.ToLower(value)
	scheme := ""
	switch {
	case strings.HasPrefix(lower, "http://"):
		scheme = "http"
	case strings.HasPrefix(lower, "https://"):
		scheme = "https"
	default:
		return NetworkFact{}, "", false, false
	}
	if !curlMainProxyOptionUsesHTTP(canonical, scheme) {
		return NetworkFact{}, "", false, false
	}
	defaultPort := int64(1080)
	if scheme == "https" {
		defaultPort = 443
	}
	return staticCurlProxyAuthorityFact(
		commandID, value, scheme, scheme, defaultPort,
	)
}

func staticCurlProxyAuthorityFact(
	commandID int64,
	value string,
	inputScheme string,
	factScheme string,
	defaultPort int64,
) (NetworkFact, string, bool, bool) {
	remainder := value
	if inputScheme != "" {
		remainder = value[len(inputScheme)+3:]
	} else if strings.HasPrefix(remainder, "//") {
		// Curl 8.7.1 accepts a bare host[:port] proxy but rejects URL
		// scheme-relative spelling as an unsupported proxy syntax.
		return NetworkFact{}, "", false, false
	}
	authorityEnd := strings.IndexAny(remainder, "/?#")
	if authorityEnd < 0 {
		authorityEnd = len(remainder)
	}
	authority := remainder[:authorityEnd]
	rawUserinfo, hostPort, hasUserinfo := strings.Cut(authority, "@")
	if !hasUserinfo {
		hostPort = authority
	}
	if hostPort == "" || !visibleASCII(hostPort) || strings.Contains(hostPort, "@") {
		return NetworkFact{}, "", false, false
	}
	if inputScheme == "" && strings.HasSuffix(hostPort, ":") {
		// Curl accepts an empty port after an explicit proxy scheme as the
		// default, but rejects the same spelling in a bare host:port value.
		return NetworkFact{}, "", hasUserinfo, false
	}

	credentials := ""
	if hasUserinfo {
		var valid bool
		credentials, valid = curlDecodedProxyURLCredentials(rawUserinfo)
		if !valid {
			return NetworkFact{}, "", true, false
		}
	}
	peerURL := factScheme + "://" + hostPort
	parsed, err := url.Parse(peerURL)
	if err != nil || parsed.Opaque != "" || parsed.User != nil ||
		parsed.Host == "" || parsed.Path != "" || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawFragment != "" {
		return NetworkFact{}, "", hasUserinfo, false
	}
	rawPort := parsed.Port()
	if rawPort != "" {
		port, valid := parseNetworkPort(rawPort)
		if !valid || port == 0 {
			return NetworkFact{}, "", hasUserinfo, false
		}
	}
	proxy, ok := networkURLFact(commandID, peerURL, NetworkConnect)
	if ok && rawPort == "" {
		proxy.Port = defaultPort
	}
	return proxy, credentials, hasUserinfo, ok
}

func curlDecodedProxyURLCredentials(raw string) (string, bool) {
	user, password, valid := curlDecodedProxyURLCredentialFields(raw)
	if !valid {
		return "", false
	}
	return user + ":" + password, true
}

func curlDecodedProxyURLCredentialFields(
	raw string,
) (string, string, bool) {
	user, password, hasPassword := strings.Cut(raw, ":")
	if !hasPassword {
		password = ""
	}
	user, valid := curlDecodePercentBytes(user, true)
	if !valid {
		return "", "", false
	}
	password, valid = curlDecodePercentBytes(password, true)
	if !valid {
		return "", "", false
	}
	return user, password, true
}

func curlDecodedProxyCredentials(
	value string,
) (decoded string, candidate bool, valid bool) {
	user, password, candidate, valid := curlDecodedProxyCredentialFields(value)
	if !valid {
		return "", false, false
	}
	return user + ":" + password, candidate, true
}

func curlDecodedProxyCredentialFields(
	value string,
) (user string, password string, candidate bool, valid bool) {
	user, password, present := strings.Cut(value, ":")
	if !present && !strings.HasPrefix(value, ";") {
		return "", "", false, false
	}
	if !present {
		user = value
		password = ""
	}
	user, valid = curlDecodePercentBytes(user, false)
	if !valid {
		return "", "", false, false
	}
	password, valid = curlDecodePercentBytes(password, false)
	if !valid {
		return "", "", false, false
	}
	return user, password, true, true
}

func curlProxyURLCredentialFields(
	value string,
) (user string, password string, present bool, valid bool) {
	remainder := value
	if delimiter := strings.Index(strings.ToLower(value), "://"); delimiter >= 0 {
		remainder = value[delimiter+3:]
	} else if strings.HasPrefix(remainder, "//") {
		remainder = remainder[2:]
	}
	if end := strings.IndexAny(remainder, "/?#"); end >= 0 {
		remainder = remainder[:end]
	}
	rawUserinfo, host, present := strings.Cut(remainder, "@")
	if !present {
		return "", "", false, true
	}
	if host == "" || strings.Contains(host, "@") {
		return "", "", true, false
	}
	user, password, valid = curlDecodedProxyURLCredentialFields(rawUserinfo)
	return user, password, true, valid
}

func curlDecodePercentBytes(value string, rejectControls bool) (string, bool) {
	var output strings.Builder
	output.Grow(len(value))
	for index := 0; index < len(value); index++ {
		decoded := value[index]
		if decoded == '%' && index+2 < len(value) &&
			isASCIIHexByte(value[index+1]) &&
			isASCIIHexByte(value[index+2]) {
			parsed, err := strconv.ParseUint(value[index+1:index+3], 16, 8)
			if err != nil {
				return "", false
			}
			decoded = byte(parsed)
			index += 2
		}
		if decoded == 0 || rejectControls && decoded < 0x20 {
			return "", false
		}
		output.WriteByte(decoded)
	}
	return output.String(), true
}

func curlMainProxyOption(canonical string) bool {
	switch canonical {
	case "--proxy", "--proxy1.0", "--socks4", "--socks4a",
		"--socks5", "--socks5-hostname":
		return true
	default:
		return false
	}
}

func curlProxyTunnelEnabled(parsed curlArgvParse, group int) bool {
	enabled := false
	for _, option := range parsed.Options {
		if option.Group != group || option.Canonical != "--proxytunnel" {
			continue
		}
		enabled = option.Name != "--no-proxytunnel"
	}
	return enabled
}

func curlMainProxyOptionUsesHTTP(canonical string, scheme string) bool {
	if scheme == "https" {
		return curlMainProxyOption(canonical)
	}
	return scheme == "http" &&
		(canonical == "--proxy" || canonical == "--proxy1.0")
}

func curlProxyInertFlag(option curlOptionToken) bool {
	if !option.Known || option.ValuePresent || option.TakesValue {
		return false
	}
	switch option.Role {
	case curlOptionNeutral, curlOptionHead, curlOptionNoHead,
		curlOptionNoRemoteName, curlOptionNoRemoteNameAll:
		return true
	default:
		return false
	}
}

func curlProxyHeaderCandidateIsTransmitted(
	value string,
	targets []curlTransferTarget,
	proxyScheme string,
	proxyTunnel bool,
	formBody bool,
) bool {
	if len(targets) == 0 {
		return false
	}
	if proxyScheme == "https" {
		for _, name := range []string{
			"host", "upgrade", "connection", "keep-alive",
			"proxy-connection", "transfer-encoding",
		} {
			if curlHeaderOverridesHTTPField(value, name) {
				return false
			}
		}
	}
	// Curl's generated multipart Content-Type wins over a same-request custom
	// proxy header in forward-proxy mode. Conservatively omit this field for
	// every form request rather than claiming mode-dependent bytes.
	if formBody && curlHeaderOverridesHTTPField(value, "content-type") {
		return false
	}
	// Curl's generated Host wins on an HTTP forward-proxy request, while the
	// custom Host is sent on an HTTPS CONNECT.
	if curlHeaderOverridesHTTPField(value, "host") {
		for _, target := range targets {
			if proxyTunnel ||
				strings.HasPrefix(strings.ToLower(target.Value), "https://") {
				return curlStaticHTTPHeaderIsTransmitted(value)
			}
		}
		return false
	}
	return curlStaticHTTPHeaderIsTransmitted(value)
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
		len(command.Argv) == 0 || !staticCurlArgvIdentity(command) ||
		len(command.Arguments) != len(command.Argv) {
		return CurlTransmittedMetadata{}
	}
	parsed := parseCurlArgv(command.Argv)
	if !parsed.Complete || parsed.ConfigOpaque || parsed.Preview ||
		parsed.EmptyTransferGroup || !parsed.hasValidOptionValues() ||
		len(parsed.Targets) == 0 || !curlRequestModeValid(parsed) ||
		!curlRangeOptionsValid(parsed) {
		return CurlTransmittedMetadata{}
	}

	group := parsed.Targets[0].Group
	for _, target := range parsed.Targets[1:] {
		if target.Group != group {
			return CurlTransmittedMetadata{}
		}
	}
	if !staticCurlGETPostDataValid(command, parsed, group) {
		return CurlTransmittedMetadata{}
	}
	if !curlStaticFormSequenceValid(command, parsed, group) {
		return CurlTransmittedMetadata{}
	}
	if !curlOriginRequestBuildAllowsPayload(command, parsed, group) {
		return CurlTransmittedMetadata{}
	}
	for _, target := range parsed.Targets {
		if !webMetadataTargetSchemeSupported(target.Value) ||
			!validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) {
			return CurlTransmittedMetadata{}
		}
	}
	requestProjection, valid := staticCurlHTTPRequestComponentProjection(
		command,
		parsed,
		group,
	)
	if !valid {
		return CurlTransmittedMetadata{}
	}
	explicitProxy, _, explicitProxyValid := staticCurlProxyDestination(command)
	allTargetsTunnelled := false
	if explicitProxyValid {
		proxyTunnel := curlProxyTunnelEnabled(parsed, group)
		allTargetsTunnelled = explicitProxy.Scheme == "tcp"
		if !allTargetsTunnelled {
			allTargetsTunnelled = true
			for _, target := range parsed.Targets {
				if !proxyTunnel &&
					!strings.HasPrefix(strings.ToLower(target.Value), "https://") {
					allTargetsTunnelled = false
					break
				}
			}
		}
		if !allTargetsTunnelled {
			return curlProxiedOriginRequestMetadata(
				command,
				parsed,
				requestProjection,
				proxyTunnel,
			)
		}
	}

	lastUser := -1
	lastBearer := -1
	lastUserAgent := -1
	lastReferer := -1
	lastRange := -1
	lastRequestMethod := -1
	rangeWireUncertain := false
	netrcSet := false
	var ftpQuoteValues []string
	for index, option := range parsed.Options {
		if option.Group != group || option.Role == curlOptionConfig {
			return CurlTransmittedMetadata{}
		}
		if option.Role == curlOptionNetworkOverride &&
			(!explicitProxyValid || !allTargetsTunnelled ||
				!curlMainProxyOption(option.Canonical) &&
					option.Canonical != "--noproxy") {
			return CurlTransmittedMetadata{}
		}
		if option.Canonical == "--user" && option.ValuePresent {
			lastUser = index
		}
		if option.Canonical == "--oauth2-bearer" && option.ValuePresent {
			lastBearer = index
		}
		if option.Canonical == "--user-agent" && option.ValuePresent {
			lastUserAgent = index
		}
		if option.Canonical == "--referer" && option.ValuePresent {
			lastReferer = index
		}
		if option.Canonical == "--range" && option.ValuePresent {
			lastRange = index
		}
		if option.Canonical == "--request" && option.ValuePresent {
			lastRequestMethod = index
		}
		if option.Canonical == "--netrc" {
			netrcSet = true
		}
		if option.Canonical == "--quote" {
			wireValue, preserved := curlFTPQuoteBytes(option.Value)
			if staticCurlOptionValue(command, option) && preserved {
				ftpQuoteValues = append(ftpQuoteValues, wireValue)
			}
		}
		if curlOptionMakesRangeWireUncertain(option.Canonical) {
			rangeWireUncertain = true
		}
	}
	metadata := CurlTransmittedMetadata{}
	httpAuthorizationOverridden := false
	httpCookieOverridden := false
	httpHeaderFileOpaque := false
	httpUserAgentOverridden := false
	httpRefererOverridden := false
	httpRangeOverridden := false
	finalUser := ""
	finalBearer := ""
	finalUserAgent := ""
	finalReferer := ""
	finalRange := ""
	finalRequestMethod := ""
	finalFTPRequestCommand := ""
	var literalCookies []string
	for index, option := range parsed.Options {
		if !option.ValuePresent ||
			(option.Canonical != "--header" &&
				option.Canonical != "--cookie" &&
				(option.Canonical != "--user" || index != lastUser) &&
				(option.Canonical != "--oauth2-bearer" || index != lastBearer) &&
				(option.Canonical != "--user-agent" || index != lastUserAgent) &&
				(option.Canonical != "--referer" || index != lastReferer) &&
				(option.Canonical != "--range" || index != lastRange) &&
				(option.Canonical != "--request" || index != lastRequestMethod)) {
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
				httpHeaderFileOpaque = true
				continue
			}
			if curlHeaderOverridesHTTPAuthorization(option.Value) {
				httpAuthorizationOverridden = true
			}
			if curlHeaderOverridesHTTPCookie(option.Value) {
				httpCookieOverridden = true
			}
			if curlHeaderOverridesHTTPField(option.Value, "user-agent") {
				httpUserAgentOverridden = true
			}
			if curlHeaderOverridesHTTPField(option.Value, "referer") {
				httpRefererOverridden = true
			}
			if curlHeaderOverridesHTTPField(option.Value, "range") {
				httpRangeOverridden = true
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
		case "--user-agent":
			if curlHTTPOWSBoundedHeaderBytesPreserved(option.Value) {
				finalUserAgent = option.Value
			}
		case "--referer":
			wireValue, _, _ := strings.Cut(option.Value, ";auto")
			if curlHTTPOWSBoundedHeaderBytesPreserved(wireValue) {
				finalReferer = wireValue
			}
		case "--range":
			if !rangeWireUncertain && curlRangeBytesPreserved(option.Value) {
				finalRange = option.Value
			}
		case "--request":
			if curlHTTPRequestMethodBytesPreserved(option.Value) {
				finalRequestMethod = option.Value
			}
			if printableASCII(option.Value) {
				finalFTPRequestCommand = option.Value
			}
		}
	}
	// --time-cond converts a date or file mtime into a generated HTTP date and
	// is not a literal-header candidate. Range proof is limited to the closed
	// default-GET state; body, method-control, and resume options can instead
	// generate Content-Range or otherwise change precedence. ETag file options
	// are outside the closed parser, so they make this helper return no metadata.
	originAuthTargetBound := lastUser >= 0 || finalBearer != ""
	if !originAuthTargetBound {
		originAuthTargetBound = true
		for _, target := range parsed.Targets {
			if webTargetHasUserinfo(target.Value) {
				originAuthTargetBound = false
				break
			}
		}
	}
	if originAuthTargetBound {
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
	}
	for _, target := range parsed.Targets {
		network, ok := webTargetFact(
			command.ID,
			target.Value,
			NetworkDownload,
		)
		if !ok {
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
		if lastUser < 0 && !netrcSet {
			user, userPresent, password, passwordPresent :=
				webTargetUserinfo(target.Value)
			userinfoBytesProved :=
				(!userPresent || printableASCII(user)) &&
					(!passwordPresent || printableASCII(password))
			switch network.Scheme {
			case "http", "https":
				if userinfoBytesProved && !httpAuthorizationOverridden && finalBearer == "" {
					if userPresent {
						metadata.HTTPOriginCredentialComponents = append(
							metadata.HTTPOriginCredentialComponents,
							component(user),
						)
					}
					if passwordPresent {
						metadata.HTTPOriginCredentialComponents = append(
							metadata.HTTPOriginCredentialComponents,
							component(password),
						)
					}
				}
			case "ftp", "ftps":
				if userinfoBytesProved && userPresent {
					metadata.FTPOriginCredentialComponents = append(
						metadata.FTPOriginCredentialComponents,
						component(user),
					)
				}
				if userinfoBytesProved && passwordPresent {
					metadata.FTPOriginCredentialComponents = append(
						metadata.FTPOriginCredentialComponents,
						component(password),
					)
				}
			}
		}
		if network.Scheme == "ftp" || network.Scheme == "ftps" {
			path := rawHTTPURLPath(target.Value)
			pathIsDirectory := path == "/" || strings.HasSuffix(path, "/")
			requestModeProved := curlFTPURLPathModeProved(path) &&
				!(target.UploadSet && pathIsDirectory)
			if requestModeProved {
				for _, quote := range ftpQuoteValues {
					metadata.FTPRequestComponents = append(
						metadata.FTPRequestComponents,
						component(quote),
					)
				}
			}
			if requestModeProved && finalFTPRequestCommand != "" &&
				!target.Head && !target.UploadSet && pathIsDirectory {
				metadata.FTPRequestComponents = append(
					metadata.FTPRequestComponents,
					component(finalFTPRequestCommand),
				)
			}
			// Leading +/- quote phases vary with transfer success and target
			// mode, so they remain detection-only until those phases are
			// represented by the closed parser.
			continue
		}
		if network.Scheme != "http" && network.Scheme != "https" {
			continue
		}
		if !httpCookieOverridden {
			for _, cookie := range literalCookies {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(cookie),
				)
			}
		}
		if !httpHeaderFileOpaque {
			if finalUserAgent != "" && !httpUserAgentOverridden {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(finalUserAgent),
				)
			}
			if finalReferer != "" && !httpRefererOverridden {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(finalReferer),
				)
			}
			if finalRange != "" && !httpRangeOverridden {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(finalRange),
				)
			}
		}
		if finalRequestMethod != "" {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(finalRequestMethod),
			)
		}
		if requestProjection.requestTargetSet {
			if requestProjection.requestTarget != "" {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(requestProjection.requestTarget),
				)
			}
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
		for _, query := range requestProjection.urlQueries {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(query),
			)
		}
	}
	return metadata
}

func curlProxiedOriginRequestMetadata(
	command CommandFact,
	parsed curlArgvParse,
	projection curlHTTPRequestComponentProjection,
	proxyTunnel bool,
) CurlTransmittedMetadata {
	metadata := CurlTransmittedMetadata{}
	for _, target := range parsed.Targets {
		network, ok := webTargetFact(command.ID, target.Value, NetworkDownload)
		if !ok || !proxyTunnel && network.Scheme != "https" {
			continue
		}
		component := func(value string) TransmittedRequestComponent {
			return TransmittedRequestComponent{
				Value: value, Scheme: network.Scheme,
				Host: network.Host, Port: network.Port,
			}
		}
		if projection.requestTargetSet {
			if projection.requestTarget != "" {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(projection.requestTarget),
				)
			}
			continue
		}
		if path := rawHTTPURLPath(target.Value); curlURLPathBytesPreserved(path) {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(path),
			)
		}
		if query := rawURLQuery(target.Value); query != "" && visibleASCII(query) {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(query),
			)
		}
		for _, query := range projection.urlQueries {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(query),
			)
		}
	}
	return metadata
}

func curlProxiedFTPControlMetadata(
	command CommandFact,
	parsed curlArgvParse,
	values []string,
	mode curlFTPProxyTunnelMode,
) CurlTransmittedMetadata {
	metadata := CurlTransmittedMetadata{}
	if len(values) == 0 || mode == curlFTPProxyTunnelNone {
		return metadata
	}
	for _, target := range parsed.Targets {
		network, ok := webTargetFact(command.ID, target.Value, NetworkDownload)
		if !ok || network.Scheme != "ftp" && network.Scheme != "ftps" ||
			mode == curlFTPProxyTunnelFTPS && network.Scheme != "ftps" {
			continue
		}
		for _, value := range values {
			metadata.FTPRequestComponents = append(
				metadata.FTPRequestComponents,
				TransmittedRequestComponent{
					Value: value, Scheme: network.Scheme,
					Host: network.Host, Port: network.Port,
				},
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

func staticCurlPOSIXNullConfigOnly(
	command CommandFact,
	parsed curlArgvParse,
) bool {
	if command.Dialect != DialectPOSIX || !parsed.ConfigOpaque ||
		len(parsed.Unresolved) == 0 {
		return false
	}
	for _, option := range parsed.Options {
		if option.Role == curlOptionConfig &&
			(option.Value != "/dev/null" || !staticCurlOptionValue(command, option)) {
			return false
		}
	}
	for _, unresolved := range parsed.Unresolved {
		matched := false
		for _, option := range parsed.Options {
			if option.Role == curlOptionConfig &&
				option.ArgvIndex == unresolved.ArgvIndex &&
				option.Value == "/dev/null" &&
				staticCurlOptionValue(command, option) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
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

func printableASCII(value string) bool {
	if value == "" || strings.Trim(value, " ") == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < 0x20 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func curlFTPQuoteBytes(value string) (string, bool) {
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") {
		return "", false
	}
	value = strings.TrimPrefix(value, "*")
	return value, printableASCII(value)
}

type curlFTPProxyTunnelMode uint8

const (
	curlFTPProxyTunnelNone curlFTPProxyTunnelMode = iota
	curlFTPProxyTunnelFTPS
	curlFTPProxyTunnelAll
)

type curlFTPProxyRouting struct {
	Networks   []NetworkFact
	Observers  []NetworkFact
	Explicit   bool
	Disabled   bool
	TunnelMode curlFTPProxyTunnelMode
	NoProxy    string
}

// staticCurlFTPProxyRoute proves the final explicit proxy state for an
// FTP(S)-only transfer group. HTTP proxies forward plain FTP as HTTP unless
// -p is set, while FTPS implicitly uses CONNECT. SOCKS proxies always carry
// the FTP control protocol, including the login exchange.
func staticCurlFTPProxyRoute(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) (curlFTPProxyRouting, bool) {
	proxyTunnel := curlProxyTunnelEnabled(parsed, group)
	lastProxy := -1
	lastPreproxy := -1
	lastNoProxy := -1
	lastProxyUser := -1
	lastInterface := -1
	hasPlainFTP := false
	hasFTPS := false
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		lowerTarget := strings.ToLower(target.Value)
		switch {
		case strings.HasPrefix(lowerTarget, "ftp://"):
			hasPlainFTP = true
		case strings.HasPrefix(lowerTarget, "ftps://"):
			hasFTPS = true
		default:
			// Other targets in the same operation do not alter curl's final
			// FTP proxy state. Their own classifier lanes decide whether the
			// complete command remains authoritative.
			continue
		}
	}
	if !hasPlainFTP && !hasFTPS {
		return curlFTPProxyRouting{}, false
	}
	if !staticCurlNetrcSetupValid(command, parsed, group) {
		return curlFTPProxyRouting{}, false
	}
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if !staticCommandArgumentAt(command, option.ArgvIndex) ||
			option.TakesValue && !staticCurlOptionValue(command, option) {
			return curlFTPProxyRouting{}, false
		}
		if option.Role != curlOptionNetworkOverride {
			if option.Canonical == "--proxy-user" && option.ValuePresent {
				lastProxyUser = index
			}
			continue
		}
		switch {
		case curlMainProxyOption(option.Canonical):
			lastProxy = index
		case option.Canonical == "--preproxy":
			lastPreproxy = index
		case option.Canonical == "--noproxy":
			lastNoProxy = index
		case option.Canonical == "--interface":
			lastInterface = index
		default:
			return curlFTPProxyRouting{}, false
		}
	}
	if lastProxyUser >= 0 {
		_, _, valid := curlDecodedProxyCredentials(
			parsed.Options[lastProxyUser].Value,
		)
		if !valid {
			return curlFTPProxyRouting{}, false
		}
	}
	mainDisabled := false
	disabledMainCanonical := ""
	if lastProxy >= 0 {
		proxyOption := parsed.Options[lastProxy]
		switch {
		case proxyOption.Value == "":
			if proxyOption.Canonical != "--proxy" {
				return curlFTPProxyRouting{}, false
			}
			mainDisabled = true
			lastProxy = -1
		case curlProxyDecodedControlUserinfoDisables(
			command.ID,
			proxyOption.Canonical,
			proxyOption.Value,
		):
			mainDisabled = true
			disabledMainCanonical = proxyOption.Canonical
			lastProxy = -1
		}
	}
	if lastPreproxy >= 0 && curlProxyDecodedControlUserinfoDisables(
		command.ID,
		"--proxy",
		parsed.Options[lastPreproxy].Value,
	) {
		lastPreproxy = -1
	}
	if lastProxy < 0 && lastPreproxy < 0 {
		route := curlFTPProxyRouting{Disabled: mainDisabled}
		if !curlFTPRoutePeerOptionsValid(
			parsed, group, route, lastInterface,
		) {
			return curlFTPProxyRouting{}, false
		}
		return route, true
	}
	proxy := NetworkFact{}
	socks := false
	networks := []NetworkFact(nil)
	observers := []NetworkFact(nil)
	if lastProxy < 0 {
		preproxyOption := parsed.Options[lastPreproxy]
		preproxyCanonical, canonicalValid :=
			curlStandalonePreproxyCanonical(
				preproxyOption.Value,
				disabledMainCanonical,
			)
		if !canonicalValid {
			return curlFTPProxyRouting{}, false
		}
		var valid bool
		proxy, socks, valid = staticCurlFTPProxyFact(
			command.ID, preproxyCanonical, preproxyOption.Value,
		)
		if !valid || !socks {
			return curlFTPProxyRouting{}, false
		}
		proxyUser := ""
		if lastProxyUser >= 0 {
			proxyUser = parsed.Options[lastProxyUser].Value
		}
		if !curlSOCKS4UserWithinBounds(
			preproxyCanonical, preproxyOption.Value, proxyUser, true,
		) {
			return curlFTPProxyRouting{}, false
		}
		networks = []NetworkFact{proxy}
		observers = []NetworkFact{proxy}
		lastPreproxy = -1
	} else {
		proxyOption := parsed.Options[lastProxy]
		var valid bool
		proxy, socks, valid = staticCurlFTPProxyFact(
			command.ID,
			proxyOption.Canonical,
			proxyOption.Value,
		)
		if !valid {
			return curlFTPProxyRouting{}, false
		}
		proxyUser := ""
		if lastProxyUser >= 0 {
			proxyUser = parsed.Options[lastProxyUser].Value
		}
		if !curlSOCKS4UserWithinBounds(
			proxyOption.Canonical, proxyOption.Value, proxyUser, true,
		) {
			return curlFTPProxyRouting{}, false
		}
		networks = []NetworkFact{proxy}
		observers = []NetworkFact{proxy}
	}
	if lastPreproxy >= 0 {
		if socks {
			return curlFTPProxyRouting{}, false
		}
		preproxyOption := parsed.Options[lastPreproxy]
		preproxyScheme := ""
		if delimiter := strings.Index(
			strings.ToLower(preproxyOption.Value),
			"://",
		); delimiter >= 0 {
			preproxyScheme = strings.ToLower(preproxyOption.Value[:delimiter])
		}
		switch preproxyScheme {
		case "socks", "socks4", "socks4a", "socks5", "socks5h":
		default:
			return curlFTPProxyRouting{}, false
		}
		preproxy, preproxySOCKS, preproxyValid := staticCurlFTPProxyFact(
			command.ID, "--proxy", preproxyOption.Value,
		)
		if !preproxyValid || !preproxySOCKS {
			return curlFTPProxyRouting{}, false
		}
		if !curlSOCKS4UserWithinBounds(
			"--proxy", preproxyOption.Value, "", false,
		) {
			return curlFTPProxyRouting{}, false
		}
		if curlProxyUsesSOCKS4("--proxy", preproxyOption.Value) &&
			!curlProxyUsesSOCKS4A("--proxy", preproxyOption.Value) {
			address, addressError := netip.ParseAddr(proxy.Host)
			if addressError == nil && address.Is6() {
				return curlFTPProxyRouting{}, false
			}
		}
		networks = []NetworkFact{preproxy, proxy}
		observers = []NetworkFact{proxy}
		if proxy.Scheme == "http" {
			observers = append([]NetworkFact{preproxy}, observers...)
		}
	}
	mode := curlFTPProxyTunnelFTPS
	if socks || proxyTunnel {
		mode = curlFTPProxyTunnelAll
	}
	noProxy := ""
	if lastNoProxy >= 0 {
		noProxy = parsed.Options[lastNoProxy].Value
	}
	if noProxy != "" {
		if noProxy == "*" {
			route := curlFTPProxyRouting{
				Disabled: true, TunnelMode: curlFTPProxyTunnelAll,
				NoProxy: noProxy,
			}
			if !curlFTPRoutePeerOptionsValid(
				parsed, group, route, lastInterface,
			) {
				return curlFTPProxyRouting{}, false
			}
			return route, true
		}
		if _, valid := curlNoProxyMatches(noProxy, "validation.invalid"); !valid {
			return curlFTPProxyRouting{}, false
		}
		proxyContact := false
		for _, target := range parsed.Targets {
			if target.Group != group {
				continue
			}
			targetFact, valid := webTargetFact(
				command.ID,
				target.Value,
				NetworkDownload,
			)
			if !valid || targetFact.Scheme != "ftp" && targetFact.Scheme != "ftps" {
				continue
			}
			noProxyHost, valid := curlNoProxyTargetHost(target.Value)
			if !valid {
				return curlFTPProxyRouting{}, false
			}
			bypassed, valid := curlNoProxyMatches(noProxy, noProxyHost)
			if !valid {
				return curlFTPProxyRouting{}, false
			}
			proxyContact = proxyContact || !bypassed
		}
		if !proxyContact {
			networks = nil
		}
	}
	route := curlFTPProxyRouting{
		Networks: networks, Observers: observers,
		Explicit: true, TunnelMode: mode, NoProxy: noProxy,
	}
	if !curlFTPRoutePeerOptionsValid(parsed, group, route, lastInterface) {
		return curlFTPProxyRouting{}, false
	}
	return route, true
}

func curlFTPRoutePeerOptionsValid(
	parsed curlArgvParse,
	group int,
	route curlFTPProxyRouting,
	lastInterface int,
) bool {
	ipv4Only, _ := curlEffectiveIPv4Only(parsed, group)
	if !ipv4Only && lastInterface < 0 {
		return true
	}
	if lastInterface >= 0 && parsed.Options[lastInterface].Value != "0.0.0.0" {
		return false
	}
	proxied := false
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		lower := strings.ToLower(target.Value)
		if !strings.HasPrefix(lower, "ftp://") &&
			!strings.HasPrefix(lower, "ftps://") {
			continue
		}
		bypassed := !route.Explicit || route.Disabled
		if route.NoProxy != "" {
			host, hostValid := curlNoProxyTargetHost(target.Value)
			if !hostValid {
				return false
			}
			var matchValid bool
			bypassed, matchValid = curlNoProxyMatches(route.NoProxy, host)
			if !matchValid {
				return false
			}
		}
		if !bypassed {
			proxied = true
			continue
		}
		parsedTarget, err := url.Parse(target.Value)
		if err != nil || !curlPeerMatchesAddressOptions(
			parsedTarget.Hostname(), ipv4Only, lastInterface >= 0,
		) {
			return false
		}
	}
	if !proxied {
		return true
	}
	if len(route.Networks) == 0 {
		return false
	}
	for _, network := range route.Networks {
		if !curlPeerMatchesAddressOptions(
			network.Host, ipv4Only, lastInterface >= 0,
		) {
			return false
		}
	}
	return true
}

func curlPeerMatchesAddressOptions(
	host string,
	ipv4Only bool,
	wildcardIPv4Interface bool,
) bool {
	address, addressError := netip.ParseAddr(host)
	if ipv4Only && addressError == nil && address.Is6() {
		return false
	}
	return !wildcardIPv4Interface || addressError == nil && address.Is4()
}

func curlEffectiveIPv4Only(parsed curlArgvParse, group int) (bool, int) {
	ipv4Only := false
	last := -1
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--ipv4":
			ipv4Only = true
			last = index
		case "--ipv6":
			ipv4Only = false
			last = index
		}
	}
	return ipv4Only, last
}

func curlNoProxyMatches(value string, host string) (bool, bool) {
	if value == "" {
		return false, true
	}
	if value == "*" {
		return true, true
	}
	host = strings.TrimSuffix(host, ".")
	hostIP, hostIsIP := netip.ParseAddr(host)
	tokens := strings.FieldsFunc(value, func(character rune) bool {
		return character == ',' || character == ' ' || character == '\t'
	})
	for _, rawToken := range tokens {
		if rawToken == "" || rawToken == "*" {
			continue
		}
		if rawAddress, rawBits, cidr := strings.Cut(rawToken, "/"); cidr {
			address, addressError := netip.ParseAddr(rawAddress)
			if addressError != nil || hostIsIP != nil {
				continue
			}
			if address.Is6() {
				// Curl 8.7.1 classifies bracket-stripped IPv6 URL hosts as
				// hostnames in its no-proxy caller and also has nonstandard
				// partial-bit CIDR behavior. Keep that lossy boundary closed.
				return false, false
			}
			bits, bitsValid := curlNoProxyIPv4CIDRBits(rawBits)
			if !bitsValid {
				return false, false
			}
			if bits == 0 {
				if address == hostIP {
					return true, true
				}
				continue
			}
			if bits <= 32 && netip.PrefixFrom(address, bits).Contains(hostIP) {
				return true, true
			}
			continue
		}
		if tokenIP, err := netip.ParseAddr(rawToken); err == nil {
			if hostIsIP == nil && tokenIP == hostIP {
				return true, true
			}
			continue
		}
		// Non-IP CIDR-shaped and wildcard-bearing tokens are ordinary
		// nonmatches in curl 8.7.1, not option-parse failures.
		if strings.ContainsAny(rawToken, "/*") || hostIsIP == nil {
			continue
		}
		token := strings.TrimPrefix(rawToken, ".")
		token = strings.TrimSuffix(token, ".")
		if token == "" {
			continue
		}
		lowerHost := strings.ToLower(host)
		lowerToken := strings.ToLower(token)
		if lowerHost == lowerToken || strings.HasSuffix(lowerHost, "."+lowerToken) {
			return true, true
		}
	}
	return false, true
}

func curlNoProxyTargetHost(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" {
		return "", false
	}
	host := parsed.Hostname()
	if _, addressError := netip.ParseAddr(host); addressError != nil &&
		strings.IndexFunc(host, func(character rune) bool {
			return character != '.' && character != 'x' && character != 'X' &&
				(character < '0' || character > '9') &&
				(character < 'a' || character > 'f') &&
				(character < 'A' || character > 'F')
		}) < 0 {
		// Curl's URL API expands legacy numeric IPv4 spellings (for example,
		// 127.1) before no-proxy matching. net/url preserves them, so keep
		// this lossy spelling class outside the exact routing lane.
		return "", false
	}
	return host, true
}

func curlNoProxyIPv4CIDRBits(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return 0, false
		}
	}
	// Curl 8.7.1 uses C atoi and assigns the result to an unsigned integer.
	// Only the portable nonnegative int32 subset has platform-independent
	// semantics; larger and signed spellings keep proxy routing unproved.
	bits, err := strconv.ParseUint(value, 10, 31)
	return int(bits), err == nil
}

func curlProxyDecodedControlUserinfoDisables(
	commandID int64,
	canonical string,
	value string,
) bool {
	if !validLiteralRequestTarget(value) {
		return false
	}
	remainder := value
	if delimiter := strings.Index(strings.ToLower(value), "://"); delimiter >= 0 {
		scheme := strings.ToLower(value[:delimiter])
		switch scheme {
		case "http", "https", "socks", "socks4", "socks4a", "socks5", "socks5h":
		default:
			return false
		}
		remainder = value[delimiter+3:]
	} else if strings.HasPrefix(remainder, "//") {
		remainder = remainder[2:]
	}
	if end := strings.IndexAny(remainder, "/?#"); end >= 0 {
		remainder = remainder[:end]
	}
	rawUserinfo, rawHost, present := strings.Cut(remainder, "@")
	if !present || rawHost == "" || strings.Contains(rawHost, "@") {
		return false
	}
	_, valid := curlDecodedProxyURLCredentials(rawUserinfo)
	if valid {
		return false
	}

	// Curl 8.7.1 silently disables a proxy when decoding control bytes in
	// proxy userinfo, but only after the rest of the proxy URL has parsed. Prove
	// that authority independently with harmless credentials so malformed hosts
	// and ports cannot be mistaken for the silent-disable path.
	authorityStart := strings.Index(value, remainder)
	if authorityStart < 0 {
		return false
	}
	authorityEnd := authorityStart + len(remainder)
	if suffix := strings.IndexAny(remainder, "/?#"); suffix >= 0 {
		authorityEnd = authorityStart + suffix
	}
	sanitized := value[:authorityStart] + "u:p@" + rawHost + value[authorityEnd:]
	_, _, parsed := staticCurlFTPProxyFact(commandID, canonical, sanitized)
	return parsed
}

// staticCurlFTPProxyFact resolves the finite proxy URL grammar relevant to
// FTP control-channel routing. Curl's final proxy setter supplies the default
// type, then an explicit https:// or socks*:// scheme overrides it. An
// explicit http:// scheme deliberately does not override a SOCKS-named setter.
func staticCurlFTPProxyFact(
	commandID int64,
	canonical string,
	value string,
) (NetworkFact, bool, bool) {
	proxy, _, _, socks, valid := staticCurlProxyFact(
		commandID,
		canonical,
		value,
	)
	return proxy, socks, valid
}

// staticCurlProxyFact retains decoded URL credentials alongside the exact
// explicit proxy peer. HTTP callers can ignore the SOCKS bit; SOCKS credential
// callers use it to avoid treating an HTTP proxy's authentication fields as a
// SOCKS handshake.
func staticCurlProxyFact(
	commandID int64,
	canonical string,
	value string,
) (NetworkFact, string, bool, bool, bool) {
	if !validLiteralRequestTarget(value) {
		return NetworkFact{}, "", false, false, false
	}
	socks := canonical == "--socks4" || canonical == "--socks4a" ||
		canonical == "--socks5" || canonical == "--socks5-hostname"
	lower := strings.ToLower(value)
	explicitScheme := ""
	if delimiter := strings.Index(lower, "://"); delimiter >= 0 {
		explicitScheme = lower[:delimiter]
		switch explicitScheme {
		case "https":
			socks = false
		case "socks", "socks4", "socks4a", "socks5", "socks5h":
			socks = true
		case "http":
		default:
			return NetworkFact{}, "", false, false, false
		}
	}
	scheme := "http"
	if socks {
		scheme = "tcp"
	} else if explicitScheme == "https" {
		scheme = "https"
	}
	defaultPort := int64(1080)
	if scheme == "https" {
		defaultPort = 443
	}
	proxy, credentials, credentialsPresent, valid := staticCurlProxyAuthorityFact(
		commandID, value, explicitScheme, scheme, defaultPort,
	)
	if valid && socks && strings.EqualFold(proxy.Host, "localhost") {
		remainder := value
		if explicitScheme != "" {
			remainder = value[len(explicitScheme)+3:]
		} else if strings.HasPrefix(remainder, "//") {
			remainder = remainder[2:]
		}
		if suffix := strings.IndexAny(remainder, "/?#"); suffix >= 0 &&
			strings.HasPrefix(remainder[suffix:], "/") {
			path := remainder[suffix:]
			if end := strings.IndexAny(path, "?#"); end >= 0 {
				path = path[:end]
			}
			if path != "/" {
				return NetworkFact{}, "", false, false, false
			}
		}
	}
	return proxy, credentials, credentialsPresent, socks, valid
}

func curlSOCKS4UserWithinBounds(
	canonical string,
	value string,
	fallbackProxyUser string,
	allowFallback bool,
) bool {
	if !curlProxyUsesSOCKS4(canonical, value) {
		return true
	}
	remainder := value
	if delimiter := strings.Index(strings.ToLower(value), "://"); delimiter >= 0 {
		remainder = value[delimiter+3:]
	} else if strings.HasPrefix(remainder, "//") {
		remainder = remainder[2:]
	}
	if end := strings.IndexAny(remainder, "/?#"); end >= 0 {
		remainder = remainder[:end]
	}
	if rawUserinfo, _, present := strings.Cut(remainder, "@"); present {
		rawUser, _, _ := strings.Cut(rawUserinfo, ":")
		user, valid := curlDecodePercentBytes(rawUser, true)
		if !valid {
			return false
		}
		return len(user) <= 255
	}
	if !allowFallback || fallbackProxyUser == "" {
		return true
	}
	rawUser, _, _ := strings.Cut(fallbackProxyUser, ":")
	user, valid := curlDecodePercentBytes(rawUser, false)
	if !valid {
		return false
	}
	return len(user) <= 255
}

func curlProxyUsesSOCKS4(canonical string, value string) bool {
	socks4 := canonical == "--socks4" || canonical == "--socks4a"
	if delimiter := strings.Index(strings.ToLower(value), "://"); delimiter >= 0 {
		switch strings.ToLower(value[:delimiter]) {
		case "socks", "socks4", "socks4a":
			return true
		case "socks5", "socks5h", "https":
			return false
		case "http":
			return socks4
		}
	}
	return socks4
}

func curlProxyUsesSOCKS4A(canonical string, value string) bool {
	socks4a := canonical == "--socks4a"
	if delimiter := strings.Index(strings.ToLower(value), "://"); delimiter >= 0 {
		switch strings.ToLower(value[:delimiter]) {
		case "socks4a":
			return true
		case "socks", "socks4", "socks5", "socks5h", "https":
			return false
		case "http":
			return socks4a
		}
	}
	return socks4a
}

func curlSOCKS4TargetsEncodable(parsed curlArgvParse, group int) bool {
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		parsedTarget, err := url.Parse(target.Value)
		if err != nil {
			return false
		}
		address, err := netip.ParseAddr(parsedTarget.Hostname())
		if err == nil && address.Is6() {
			return false
		}
	}
	return true
}

func curlExplicitSOCKSProxyURL(value string) bool {
	delimiter := strings.Index(value, "://")
	if delimiter <= 0 {
		return false
	}
	switch strings.ToLower(value[:delimiter]) {
	case "socks", "socks4", "socks4a", "socks5", "socks5h":
		return true
	default:
		return false
	}
}

func curlStandalonePreproxyCanonical(
	value string,
	disabledMainCanonical string,
) (string, bool) {
	if curlExplicitSOCKSProxyURL(value) {
		return "--proxy", true
	}
	switch disabledMainCanonical {
	case "--socks4", "--socks4a", "--socks5", "--socks5-hostname":
		// Curl retains the proxy type selected by a SOCKS-named setter even
		// when decoded control bytes disable that main proxy. A following bare
		// (or http://) preproxy inherits the retained type; https:// can still
		// override it and is rejected later when it resolves as non-SOCKS.
		return disabledMainCanonical, true
	default:
		return "", false
	}
}

// StaticCurlFTPControlRequestComponents returns exact, target-bound FTP(S)
// login operands without depending on HTTP request-metadata projection.
func StaticCurlFTPControlRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	origin, _ := staticCurlFTPControlRequestComponents(command)
	return origin
}

// StaticCurlFTPControlRequestComponentsForFacts admits an exactly isolated
// curl child beneath transparent env/command/exec launchers. Traversing the
// complete command hierarchy is required because parent redirects or pipeline
// setup can fail before the child starts; a CommandFact alone cannot prove
// those ancestors.
func StaticCurlFTPControlRequestComponentsForFacts(
	facts Facts,
	commandID int64,
) []TransmittedRequestComponent {
	command, valid := staticCurlCommandForFacts(facts, commandID)
	if !valid {
		return nil
	}
	return StaticCurlFTPControlRequestComponents(command)
}

// StaticCurlFTPProxyRequestComponentsForFacts is the proxy-observer companion
// to StaticCurlFTPControlRequestComponentsForFacts.
func StaticCurlFTPProxyRequestComponentsForFacts(
	facts Facts,
	commandID int64,
) []TransmittedRequestComponent {
	command, valid := staticCurlCommandForFacts(facts, commandID)
	if !valid {
		return nil
	}
	return staticCurlFTPProxyRequestComponents(command)
}

func staticCurlCommandForFacts(
	facts Facts,
	commandID int64,
) (CommandFact, bool) {
	if commandID == 0 || !facts.Authoritative() || !facts.EnforcementEligible() {
		return CommandFact{}, false
	}
	for index := range facts.Commands {
		command := &facts.Commands[index]
		if command.ID != commandID {
			continue
		}
		if !isolatedPOSIXCommandFacts(facts.Commands, command) {
			return CommandFact{}, false
		}
		isolated := *command
		isolated.ParentCommandID = 0
		isolated.Wrappers = nil
		return isolated, true
	}
	return CommandFact{}, false
}

func staticCurlTelnetCommandForCommands(
	commands []CommandFact,
	commandID int64,
) (CommandFact, bool) {
	if commandID == 0 {
		return CommandFact{}, false
	}
	// isolatedPOSIXCommandFacts intentionally rejects every redirect. Erase
	// only the output-to-/dev/null forms that cannot prevent Telnet startup;
	// unsafe redirects remain and are rejected while traversing the ancestry.
	isolatedCommands := cloneSlice(commands)
	commandIndex := -1
	for index := range isolatedCommands {
		if curlTelnetOutputRedirectsSafe(isolatedCommands[index]) {
			isolatedCommands[index].Redirects = nil
		}
		if isolatedCommands[index].ID == commandID {
			if commandIndex >= 0 {
				return CommandFact{}, false
			}
			commandIndex = index
		}
	}
	if commandIndex < 0 || !isolatedPOSIXCommandFacts(
		isolatedCommands,
		&isolatedCommands[commandIndex],
	) {
		return CommandFact{}, false
	}
	isolated := isolatedCommands[commandIndex]
	isolated.ParentCommandID = 0
	isolated.Wrappers = nil
	return isolated, true
}

func staticCurlFTPProxyRequestComponents(
	command CommandFact,
) []TransmittedRequestComponent {
	_, proxy := staticCurlFTPControlRequestComponents(command)
	return proxy
}

func staticCurlFTPControlRequestComponents(
	command CommandFact,
) ([]TransmittedRequestComponent, []TransmittedRequestComponent) {
	executionEligible := (command.Dialect == DialectPOSIX ||
		command.Dialect == DialectArgv) && command.Effect == EffectExecute &&
		command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
		len(command.Redirects) == 0 &&
		exactCaseSensitivePOSIXProgram(&command, "curl")
	if !executionEligible || !command.ArgvComplete || len(command.Argv) == 0 ||
		command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return nil, nil
	}
	parsed := parseCurlArgv(command.Argv)
	nullConfigOnly := staticCurlPOSIXNullConfigOnly(command, parsed)
	if (!parsed.Complete && !nullConfigOnly) || parsed.Preview ||
		!parsed.hasValidOptionValues() || len(parsed.Targets) == 0 ||
		!curlRangeOptionsValid(parsed) {
		return nil, nil
	}
	if !staticCurlFTPEagerPreparseValid(command, parsed) {
		return nil, nil
	}
	if !staticCurlFTPParallelSetupValid(command, parsed) {
		return nil, nil
	}
	for _, target := range parsed.Targets {
		lowerTarget := strings.ToLower(target.Value)
		if !strings.HasPrefix(lowerTarget, "ftp://") &&
			!strings.HasPrefix(lowerTarget, "ftps://") {
			continue
		}
		if !validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) {
			return nil, nil
		}
		if _, finalUser := curlFinalGroupOption(
			parsed, target.Group, "--user",
		); !finalUser && !curlFTPURLCredentialsWithinCommandBounds(target.Value) {
			return nil, nil
		}
	}
	groups := make(map[int]struct{})
	maximumGroup := 0
	for _, target := range parsed.Targets {
		groups[target.Group] = struct{}{}
		maximumGroup = max(maximumGroup, target.Group)
	}
	var components []TransmittedRequestComponent
	var proxyComponents []TransmittedRequestComponent
	for group := 0; group <= maximumGroup; group++ {
		if _, present := groups[group]; !present {
			continue
		}
		if !staticCurlFTPGroupSetupValid(command, parsed, group) {
			break
		}
		if !curlRequestModeValidForGroup(parsed, group) ||
			!staticCurlGETPostDataValid(command, parsed, group) ||
			!staticCurlFTPURLQueryOptionsValid(command, parsed, group) ||
			!curlFTPRemoteNameTargetsValid(command, parsed, group) ||
			!curlStaticFormSequenceValid(command, parsed, group) ||
			!curlOriginRequestBuildAllowsPayload(command, parsed, group) {
			continue
		}
		route, routeProved := staticCurlFTPProxyRoute(command, parsed, group)
		if !routeProved {
			continue
		}
		values := staticCurlFTPControlRequestValues(command, parsed, group)
		if len(values) == 0 {
			continue
		}
		tlsState := curlEffectiveFTPTLSState(parsed, group)
		for _, target := range parsed.Targets {
			if target.Group != group {
				continue
			}
			network, valid := webTargetFact(command.ID, target.Value, NetworkDownload)
			if !valid || network.Scheme != "ftp" && network.Scheme != "ftps" {
				continue
			}
			bypassed := route.Disabled
			if route.NoProxy != "" {
				var matchValid bool
				noProxyHost, hostValid := curlNoProxyTargetHost(target.Value)
				if !hostValid {
					continue
				}
				bypassed, matchValid = curlNoProxyMatches(
					route.NoProxy,
					noProxyHost,
				)
				if !matchValid {
					continue
				}
			}
			if !bypassed && route.Explicit &&
				(route.TunnelMode == curlFTPProxyTunnelNone ||
					route.TunnelMode == curlFTPProxyTunnelFTPS &&
						network.Scheme != "ftps") {
				continue
			}
			if tlsState.requiredForScheme(network.Scheme) &&
				(tlsState.certificate != "" ||
					tlsState.caCertificate != "" && !tlsState.insecure) {
				continue
			}
			for _, value := range values {
				components = append(components, TransmittedRequestComponent{
					Value: value, Scheme: network.Scheme,
					Host: network.Host, Port: network.Port,
				})
				if network.Scheme == "ftp" && !bypassed && route.Explicit &&
					route.TunnelMode == curlFTPProxyTunnelAll &&
					!tlsState.requiredForScheme(network.Scheme) {
					for _, observer := range route.Observers {
						proxyComponents = append(
							proxyComponents,
							TransmittedRequestComponent{
								Value: value, Scheme: observer.Scheme,
								Host: observer.Host, Port: observer.Port,
							},
						)
					}
				}
			}
		}
	}
	return components, proxyComponents
}

func staticCurlFTPParallelSetupValid(
	command CommandFact,
	parsed curlArgvParse,
) bool {
	parallel := false
	for _, option := range parsed.Options {
		if option.Canonical == "--parallel" {
			parallel = option.Name != "--no-parallel"
		}
	}
	if !parallel {
		return true
	}
	groups := make(map[int]struct{})
	for _, target := range parsed.Targets {
		groups[target.Group] = struct{}{}
	}
	for _, option := range parsed.Options {
		groups[option.Group] = struct{}{}
	}
	for group := range groups {
		if !staticCurlFTPGroupSetupValid(command, parsed, group) {
			return false
		}
	}
	return true
}

func staticCurlFTPGroupSetupValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	if !curlFTPContinueAtSetupValid(parsed, group) {
		return false
	}
	posixNullDevice := command.Dialect == DialectPOSIX
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--upload-file":
			if option.Value != "" && option.Value != "-" && option.Value != "." &&
				(!posixNullDevice || option.Value != "/dev/null") {
				return false
			}
		case "--form", "--form-string":
			if curlUploadPayloadSourceUncertain(option) {
				return false
			}
			if option.Canonical == "--form" &&
				curlFormUsesPOSIXNullDevice(option.Value) && !posixNullDevice {
				return false
			}
		case "--dump-header":
			if option.Value != "-" &&
				(!posixNullDevice || option.Value != "/dev/null") {
				return false
			}
		}
	}
	return curlRequestModeValidForGroup(parsed, group) &&
		curlFTPRemoteNameTargetsValid(command, parsed, group) &&
		curlStaticFormSequenceValid(command, parsed, group)
}

func curlFTPContinueAtSetupValid(parsed curlArgvParse, group int) bool {
	value := ""
	found := false
	for _, option := range parsed.Options {
		if option.Group == group && option.Canonical == "--continue-at" {
			value = option.Value
			found = true
		}
	}
	if !found {
		return true
	}
	if value == "-" || !curlContinueAtValueValid(value) ||
		curlFTPGroupHasActiveUpload(parsed, group) {
		return false
	}
	resume, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return false
	}
	if resume == 0 {
		return true
	}
	for _, target := range parsed.Targets {
		if target.Group == group && target.Output != curlOutputStdout {
			// Curl opens resumed output files in append mode before connecting.
			return false
		}
	}
	return true
}

func curlFTPGroupHasActiveUpload(parsed curlArgvParse, group int) bool {
	for _, target := range parsed.Targets {
		if target.Group == group && target.UploadSet && target.UploadValue != "" {
			return true
		}
	}
	get := false
	hasData := false
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical == "--get" {
			get = option.Name != "--no-get"
		}
		switch option.Canonical {
		case "--form", "--form-string":
			return true
		case "--data", "--data-ascii", "--data-binary", "--data-raw",
			"--data-urlencode", "--json":
			hasData = true
		}
	}
	return hasData && !get
}

func staticCurlFTPEagerPreparseValid(
	command CommandFact,
	parsed curlArgvParse,
) bool {
	if !staticCurlFTPEagerOptionConflictsValid(parsed) ||
		!curlStaticFormEagerSyntaxValid(parsed) {
		return false
	}
	posixNullDevice := command.Dialect == DialectPOSIX
	lastUser := make(map[int]int)
	lastProxyUser := make(map[int]int)
	lastBearer := make(map[int]string)
	for _, option := range parsed.Options {
		if !staticCommandArgumentAt(command, option.ArgvIndex) ||
			option.TakesValue && !staticCurlOptionValue(command, option) ||
			!curlProxyNumericOptionWithinPortableBounds(option) {
			return false
		}
		if option.Role == curlOptionConfig &&
			(!posixNullDevice || option.Value != "/dev/null") {
			return false
		}
		switch option.Canonical {
		case "--user":
			lastUser[option.Group] = option.ArgvIndex
		case "--proxy-user":
			lastProxyUser[option.Group] = option.ArgvIndex
		case "--oauth2-bearer":
			lastBearer[option.Group] = option.Value
		case "--header", "--proxy-header":
			if !staticCurlHeaderSetupValid(command, option) {
				return false
			}
		case "--write-out":
			if strings.HasPrefix(option.Value, "@") &&
				(!posixNullDevice || option.Value != "@/dev/null") {
				return false
			}
		case "--data", "--data-ascii", "--data-binary", "--json":
			if strings.HasPrefix(option.Value, "@") &&
				(!posixNullDevice || option.Value != "@/dev/null") {
				return false
			}
		case "--data-urlencode", "--url-query":
			path, stdin, fileSource, valid := curlDataURLEncodeFile(option.Value)
			if !valid || fileSource &&
				(!posixNullDevice || stdin || path != "/dev/null") {
				return false
			}
		case "--continue-at":
			if !curlContinueAtValueValid(option.Value) {
				return false
			}
		case "--stderr":
			if option.Value != "-" &&
				(!posixNullDevice || option.Value != "/dev/null") {
				return false
			}
		}
	}
	for group := range lastUser {
		option, found := curlFinalGroupOption(parsed, group, "--user")
		if !found || !curlOriginUserAvoidsPrompt(
			option.Value,
			lastBearer[group] != "",
		) {
			return false
		}
	}
	for group := range lastProxyUser {
		option, found := curlFinalGroupOption(parsed, group, "--proxy-user")
		if !found {
			return false
		}
		if _, _, valid := curlDecodedProxyCredentials(option.Value); !valid {
			return false
		}
	}
	groups := make(map[int]struct{})
	for _, target := range parsed.Targets {
		groups[target.Group] = struct{}{}
	}
	for _, option := range parsed.Options {
		groups[option.Group] = struct{}{}
	}
	for group := range groups {
		if !staticCurlGETPostDataValid(command, parsed, group) ||
			!staticCurlFTPURLQueryOptionsValid(command, parsed, group) {
			return false
		}
	}
	return true
}

func curlContinueAtValueValid(value string) bool {
	if value == "-" {
		return true
	}
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil
}

func staticCurlFTPEagerOptionConflictsValid(parsed curlArgvParse) bool {
	type eagerState struct {
		fail         bool
		failWithBody bool
		requestMode  curlRequestMode
	}
	states := make(map[int]eagerState)
	for _, option := range parsed.Options {
		state := states[option.Group]
		switch option.Canonical {
		case "--fail":
			state.fail = option.Name != "--no-fail"
			if state.fail && state.failWithBody {
				return false
			}
		case "--fail-with-body":
			state.failWithBody = option.Name != "--no-fail-with-body"
			if state.fail && state.failWithBody {
				return false
			}
		case "--form", "--form-string":
			if state.requestMode != curlRequestModeUnspecified &&
				state.requestMode != curlRequestModeForm {
				return false
			}
			state.requestMode = curlRequestModeForm
		case "--head":
			if state.requestMode != curlRequestModeUnspecified &&
				state.requestMode != curlRequestModeHead {
				return false
			}
			state.requestMode = curlRequestModeHead
		case "--no-head":
			if state.requestMode != curlRequestModeUnspecified &&
				state.requestMode != curlRequestModeGet {
				return false
			}
			state.requestMode = curlRequestModeGet
		}
		states[option.Group] = state
	}
	return true
}

func curlFinalGroupOption(
	parsed curlArgvParse,
	group int,
	canonical string,
) (curlOptionToken, bool) {
	var final curlOptionToken
	found := false
	for _, option := range parsed.Options {
		if option.Group == group && option.Canonical == canonical &&
			option.ValuePresent {
			final = option
			found = true
		}
	}
	return final, found
}

func curlOriginUserAvoidsPrompt(value string, bearerSet bool) bool {
	if strings.IndexByte(value, 0) >= 0 {
		return false
	}
	const maximumFTPLoginFieldLength = 65_528
	user, password, hasPassword := strings.Cut(value, ":")
	if hasPassword {
		return len(user) <= maximumFTPLoginFieldLength &&
			len(password) <= maximumFTPLoginFieldLength
	}
	return len(value) <= maximumFTPLoginFieldLength &&
		(bearerSet || strings.HasPrefix(value, ";"))
}

func staticCurlNetrcSetupValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	netrc := false
	netrcOptional := false
	netrcFile := ""
	lastUser := -1
	lastBearer := ""
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--netrc":
			netrc = option.Name != "--no-netrc"
		case "--netrc-optional":
			netrcOptional = option.Name != "--no-netrc-optional"
		case "--netrc-file":
			if !staticCurlOptionValue(command, option) {
				return false
			}
			netrcFile = option.Value
		case "--user":
			lastUser = index
		case "--oauth2-bearer":
			lastBearer = option.Value
		}
	}
	if lastUser >= 0 {
		option := parsed.Options[lastUser]
		return staticCurlOptionValue(command, option) &&
			curlOriginUserAvoidsPrompt(option.Value, lastBearer != "")
	}
	if !netrc && !netrcOptional && netrcFile == "" {
		return true
	}
	return command.Dialect == DialectPOSIX && netrcFile == "/dev/null"
}

func staticCurlTelnetNetrcSetupValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	netrc := false
	netrcOptional := false
	netrcFile := ""
	lastUser := -1
	bearer := ""
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--netrc":
			netrc = option.Name != "--no-netrc"
		case "--netrc-optional":
			netrcOptional = option.Name != "--no-netrc-optional"
		case "--netrc-file":
			if !staticCurlOptionValue(command, option) {
				return false
			}
			netrcFile = option.Value
		case "--user":
			lastUser = index
		case "--oauth2-bearer":
			if !staticCurlOptionValue(command, option) {
				return false
			}
			bearer = option.Value
		}
	}
	if lastUser >= 0 {
		option := parsed.Options[lastUser]
		return staticCurlOptionValue(command, option) &&
			curlTelnetUserAvoidsPrompt(option.Value, bearer != "")
	}
	if !netrc && !netrcOptional && netrcFile == "" {
		return true
	}
	return curlPOSIXNullDeviceAvailable(command) && netrcFile == "/dev/null"
}

func curlFTPURLCredentialsWithinCommandBounds(value string) bool {
	user, userPresent, password, passwordPresent := webTargetUserinfo(value)
	if !userPresent {
		return true
	}
	const maximumFTPLoginFieldLength = 65_528
	return len(user) <= maximumFTPLoginFieldLength &&
		(!passwordPresent || len(password) <= maximumFTPLoginFieldLength)
}

func staticCurlFTPURLQueryOptionsValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	hasGet := false
	hasData := false
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical == "--get" {
			hasGet = option.Name != "--no-get"
		}
		hasData = hasData || curlOptionProvidesGETQueryData(option.Canonical)
	}
	replaced := hasGet && hasData
	var outputLengths []int
	for _, option := range parsed.Options {
		if option.Group != group || option.Canonical != "--url-query" {
			continue
		}
		if !staticCurlOptionValue(command, option) {
			return false
		}
		path, stdin, fileSource, fileValid :=
			curlDataURLEncodeFile(option.Value)
		wireValue := ""
		valid := false
		if fileSource {
			if !fileValid || stdin || command.Dialect != DialectPOSIX ||
				path != "/dev/null" {
				return false
			}
			if name, _, named := strings.Cut(option.Value, "@"); named {
				if name != "" {
					wireValue = name + "="
				}
			}
			valid = strings.IndexByte(wireValue, 0) < 0 &&
				(replaced || curlURLQueryWireBytesValid(wireValue))
		} else if replaced {
			wireValue, valid = curlURLQueryConfigBytes(option.Value)
		} else {
			wireValue, valid = curlURLQueryOptionBytes(option.Value)
		}
		if !valid {
			return false
		}
		outputLengths = append(outputLengths, len(wireValue))
	}
	if replaced {
		return curlURLQueryConfigLengthsValid(outputLengths)
	}
	var targets []curlTransferTarget
	for _, target := range parsed.Targets {
		if target.Group == group {
			targets = append(targets, target)
		}
	}
	return curlURLQueryLengthsValid(targets, outputLengths)
}

func curlFTPRemoteNameTargetsValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	for _, target := range parsed.Targets {
		if target.Group != group || target.Output != curlOutputRemoteName {
			continue
		}
		if _, valid := curlRemoteNameFilename(command, target); !valid {
			return false
		}
	}
	return true
}

func curlRemoteNameFilename(
	command CommandFact,
	target curlTransferTarget,
) (string, bool) {
	lower := strings.ToLower(target.Value)
	schemeEnd := strings.Index(lower, "://")
	if schemeEnd < 0 {
		return "", false
	}
	remainder := target.Value[schemeEnd+3:]
	path := "/"
	if pathStart := strings.IndexAny(remainder, `/\?#`); pathStart >= 0 &&
		(remainder[pathStart] == '/' || remainder[pathStart] == '\\') {
		path = remainder[pathStart:]
		if suffix := strings.IndexAny(path, "?#"); suffix >= 0 {
			path = path[:suffix]
		}
	}
	filename := path
	if separator := strings.LastIndexAny(filename, `/\`); separator >= 0 {
		filename = filename[separator+1:]
	}
	if filename == "" || filename == "." || filename == ".." ||
		command.Dialect == DialectArgv &&
			(len(filename) > 255 || strings.TrimRight(filename, " .") == "") {
		return "", false
	}
	return filename, true
}

// staticCurlFTPControlRequestValues returns the final literal operands that
// curl 8.7.1 can put on an FTP(S) control channel while authenticating. ACCT
// prefixes its operand with "ACCT "; the alternative-to-USER operand is sent
// as the complete command. Both are server-response dependent, but neither is
// transformed before transmission.
//
// The tool opens or reads several local file operands before it starts the
// transfer. Keep those failures component-local: they suppress these login
// candidates without discarding independently proven HTTP/FTP metadata.
func staticCurlFTPControlRequestValues(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) []string {
	if (command.Dialect != DialectPOSIX && command.Dialect != DialectArgv) ||
		command.Effect != EffectExecute || command.ParentCommandID != 0 ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 ||
		!exactCaseSensitivePOSIXProgram(&command, "curl") {
		return nil
	}
	if !curlFTPContinueAtSetupValid(parsed, group) {
		return nil
	}
	lastAccount := -1
	lastAlternative := -1
	lastUser := -1
	lastProxyUser := -1
	lastBearer := -1
	netrcEnabled := false
	netrcFile := ""
	posixNullDevice := command.Dialect == DialectPOSIX
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if !staticCommandArgumentAt(command, option.ArgvIndex) ||
			option.TakesValue && !staticCurlOptionValue(command, option) {
			return nil
		}
		if !curlProxyNumericOptionWithinPortableBounds(option) {
			return nil
		}
		if option.Role == curlOptionConfig &&
			(!posixNullDevice || option.Value != "/dev/null") {
			return nil
		}
		switch option.Canonical {
		case "--netrc":
			netrcEnabled = option.Name != "--no-netrc"
		case "--netrc-optional":
			netrcEnabled = option.Name != "--no-netrc-optional"
		case "--netrc-file":
			netrcFile = option.Value
		case "--ftp-account":
			lastAccount = index
		case "--ftp-alternative-to-user":
			lastAlternative = index
		case "--user":
			lastUser = index
		case "--proxy-user":
			lastProxyUser = index
		case "--oauth2-bearer":
			lastBearer = index
		case "--upload-file":
			if option.Value != "" && option.Value != "-" && option.Value != "." &&
				(option.Value != "/dev/null" || !posixNullDevice) {
				return nil
			}
		case "--data", "--data-ascii", "--data-binary", "--data-raw", "--json":
			if curlUploadPayloadSourceUncertain(option) &&
				(option.Value != "@/dev/null" || !posixNullDevice) {
				return nil
			}
		case "--data-urlencode":
			path, stdin, fileSource, valid := curlDataURLEncodeFile(option.Value)
			if !valid || fileSource &&
				(!posixNullDevice || stdin || path != "/dev/null") {
				return nil
			}
		case "--form", "--form-string":
			if curlUploadPayloadSourceUncertain(option) {
				return nil
			}
			if option.Canonical == "--form" &&
				curlFormUsesPOSIXNullDevice(option.Value) && !posixNullDevice {
				return nil
			}
		case "--header", "--proxy-header":
			if !staticCurlHeaderSetupValid(command, option) {
				return nil
			}
		case "--write-out":
			if strings.HasPrefix(option.Value, "@") &&
				(option.Value != "@/dev/null" || !posixNullDevice) {
				return nil
			}
		case "--dump-header":
			if option.Value != "-" &&
				(option.Value != "/dev/null" || !posixNullDevice) {
				return nil
			}
		case "--url-query":
			path, stdin, fileSource, valid := curlDataURLEncodeFile(option.Value)
			if !valid || fileSource &&
				(!posixNullDevice || stdin || path != "/dev/null") {
				return nil
			}
		}
	}
	if lastUser >= 0 {
		// An explicit --user sets libcurl's username even when empty, so
		// curl does not consult netrc for this operation.
	} else if netrcFile != "" {
		if !posixNullDevice || netrcFile != "/dev/null" {
			return nil
		}
	} else if netrcEnabled {
		return nil
	}
	if lastUser >= 0 && !curlOriginUserAvoidsPrompt(
		parsed.Options[lastUser].Value,
		lastBearer >= 0 && parsed.Options[lastBearer].Value != "",
	) {
		return nil
	}
	if lastProxyUser >= 0 {
		if _, _, valid := curlDecodedProxyCredentials(
			parsed.Options[lastProxyUser].Value,
		); !valid {
			return nil
		}
	}
	const (
		maximumAccountLength     = 65_528
		maximumAlternativeLength = 65_533
	)
	values := make([]string, 0, 2)
	appendFinal := func(index int, maximum int) {
		if index < 0 {
			return
		}
		value := parsed.Options[index].Value
		if value != "" && strings.IndexByte(value, 0) < 0 &&
			len(value) <= maximum {
			values = append(values, value)
		}
	}
	appendFinal(lastAccount, maximumAccountLength)
	appendFinal(lastAlternative, maximumAlternativeLength)
	return values
}

func curlURLPathBytesPreserved(value string) bool {
	if value == "" || !strings.HasPrefix(value, "/") || !visibleASCII(value) {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func curlFTPURLPathModeProved(value string) bool {
	if !strings.HasPrefix(value, "/") ||
		!webUnreservedBytesPreserved(value, "/-._~") {
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
	return strings.Contains(value, "=") &&
		curlHTTPOWSBoundedHeaderBytesPreserved(value)
}

func curlHTTPHeaderValueBytesPreserved(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] != '\t' && (value[index] < 0x20 || value[index] > 0x7e) {
			return false
		}
	}
	return true
}

func curlHTTPOWSBoundedHeaderBytesPreserved(value string) bool {
	return curlHTTPHeaderValueBytesPreserved(value) &&
		!isHTTPOptionalWhitespace(value[0]) &&
		!isHTTPOptionalWhitespace(value[len(value)-1])
}

func isHTTPOptionalWhitespace(value byte) bool {
	return value == ' ' || value == '\t'
}

func curlHTTPRequestLineBytesPreserved(value string) bool {
	return value != "" && visibleASCII(value)
}

// Curl can write unusual request-line bytes through HTTP/1.x, but an LF in
// the effective method or request target can make an HTTPS HTTP/2 request fail
// before its origin headers or body are streamed. All-HTTP targets have a
// proven H1 lane; any HTTPS target requires --http1.0 to retain authority.
func curlOriginRequestBuildAllowsPayload(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	hasHTTPS := false
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		if strings.HasPrefix(strings.ToLower(target.Value), "https://") {
			hasHTTPS = true
		}
	}
	if !hasHTTPS {
		return true
	}
	lastRequest := -1
	lastRequestTarget := -1
	for index, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		if option.Canonical == "--http1.0" {
			return true
		}
		if option.Canonical == "--request" && option.ValuePresent {
			lastRequest = index
		}
		if option.Canonical == "--request-target" && option.ValuePresent {
			lastRequestTarget = index
		}
	}
	for _, index := range []int{lastRequest, lastRequestTarget} {
		if index >= 0 {
			option := parsed.Options[index]
			if !staticCurlOptionValue(command, option) ||
				strings.ContainsRune(option.Value, '\n') {
				return false
			}
		}
	}
	return true
}

func wgetUserAgentBytesPreserved(value string) bool {
	return value != "" && validWgetUserAgent(value)
}

func wgetRefererBytesPreserved(value string) bool {
	return value != "" && !strings.ContainsRune(value, 0)
}

func curlURLQueryOptionBytes(value string) (string, bool) {
	if raw, found := strings.CutPrefix(value, "+"); found {
		if !curlURLQueryWireBytesValid(raw) {
			return "", false
		}
		return curlCanonicalURLQueryPercentHex(raw), true
	}
	_, _, fileSource, valid := curlDataURLEncodeFile(value)
	if !valid || fileSource {
		return "", false
	}
	wireValue, valid := curlDataURLEncodeBytes(value)
	if !valid || !curlURLQueryWireBytesValid(wireValue) {
		return "", false
	}
	return curlCanonicalURLQueryPercentHex(wireValue), true
}

func curlURLQueryConfigBytes(value string) (string, bool) {
	if raw, found := strings.CutPrefix(value, "+"); found {
		return raw, strings.IndexByte(raw, 0) < 0
	}
	_, _, fileSource, valid := curlDataURLEncodeFile(value)
	if !valid || fileSource {
		return "", false
	}
	return curlDataURLEncodeBytes(value)
}

func curlCanonicalURLQueryPercentHex(value string) string {
	var canonical strings.Builder
	canonical.Grow(len(value))
	for index := 0; index < len(value); index++ {
		canonical.WriteByte(value[index])
		if value[index] != '%' || index+2 >= len(value) ||
			!isASCIIHex(value[index+1]) || !isASCIIHex(value[index+2]) {
			continue
		}
		canonical.WriteByte(asciiLowerHex(value[index+1]))
		canonical.WriteByte(asciiLowerHex(value[index+2]))
		index += 2
	}
	return canonical.String()
}

func isASCIIHex(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' ||
		value >= 'A' && value <= 'F'
}

func asciiLowerHex(value byte) byte {
	if value >= 'A' && value <= 'F' {
		return value + ('a' - 'A')
	}
	return value
}

func curlURLQueryWireBytesValid(value string) bool {
	for index := range len(value) {
		if value[index] <= 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func curlURLQueryLengthsValid(
	targets []curlTransferTarget,
	outputLengths []int,
) bool {
	if len(outputLengths) == 0 {
		return true
	}
	total := len(outputLengths) - 1
	for _, length := range outputLengths {
		if length < 0 || total >= 8_000_000-length {
			return false
		}
		total += length
	}
	// Curl 8.7.1 caps only the buffer created while combining repeated
	// --url-query outputs; the first lone output bypasses this smaller cap.
	if len(outputLengths) > 1 && total >= 100_000 {
		return false
	}
	for _, target := range targets {
		// Reserve one byte for the separator between the target and appended
		// query. Curl's full URL allocation must remain below 8 MB.
		if len(target.Value) >= 8_000_000-total-1 {
			return false
		}
	}
	return true
}

func curlURLQueryConfigLengthsValid(outputLengths []int) bool {
	if len(outputLengths) <= 1 {
		return len(outputLengths) == 0 || outputLengths[0] >= 0
	}
	total := len(outputLengths) - 1
	for _, length := range outputLengths {
		if length < 0 || length >= 100_000 || total >= 100_000-length {
			return false
		}
		total += length
	}
	return true
}

func webUnreservedBytesPreserved(value string, extra string) bool {
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune(extra, rune(character)) {
			continue
		}
		return false
	}
	return true
}

func curlHTTPRequestMethodBytesPreserved(value string) bool {
	return curlHTTPRequestLineBytesPreserved(value)
}

func curlRangeBytesPreserved(value string) bool {
	if !curlHTTPHeaderValueBytesPreserved(value) ||
		isHTTPOptionalWhitespace(value[len(value)-1]) {
		return false
	}
	// Curl parses any dashless value beginning with a digit as a numeric
	// offset, discards its suffix, and sends a normalized N- form.
	return value == "" || value[0] < '0' || value[0] > '9' ||
		strings.Contains(value, "-")
}

func curlRangeOptionsValid(parsed curlArgvParse) bool {
	for _, option := range parsed.Options {
		value := option.Value
		if option.Canonical != "--range" || value == "" ||
			value[0] < '0' || value[0] > '9' || strings.Contains(value, "-") {
			continue
		}
		end := 0
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		if _, err := strconv.ParseInt(value[:end], 10, 64); err != nil {
			return false
		}
	}
	return true
}

func curlOptionProvidesGETQueryData(option string) bool {
	switch option {
	case "--data", "--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--json":
		return true
	default:
		return false
	}
}

type curlRequestMode uint8

const (
	curlRequestModeUnspecified curlRequestMode = iota
	curlRequestModeGet
	curlRequestModeHead
	curlRequestModeForm
	curlRequestModePost
	curlRequestModePut
)

func curlRequestModeValid(parsed curlArgvParse) bool {
	groups := make(map[int]struct{})
	for _, option := range parsed.Options {
		groups[option.Group] = struct{}{}
	}
	for _, target := range parsed.Targets {
		groups[target.Group] = struct{}{}
	}
	for group := range groups {
		if !curlRequestModeValidForGroup(parsed, group) {
			return false
		}
	}
	return true
}

func curlRequestModeValidForGroup(parsed curlArgvParse, group int) bool {
	mode := curlRequestModeUnspecified
	setMode := func(next curlRequestMode) bool {
		if mode != curlRequestModeUnspecified && mode != next {
			return false
		}
		mode = next
		return true
	}
	noBody := false
	hasData := false
	useHTTPGet := false
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--form", "--form-string":
			if !setMode(curlRequestModeForm) {
				return false
			}
		case "--head":
			noBody = true
			if !setMode(curlRequestModeHead) {
				return false
			}
		case "--no-head":
			noBody = false
			if !setMode(curlRequestModeGet) {
				return false
			}
		case "--get":
			useHTTPGet = option.Name != "--no-get"
		default:
			if curlOptionProvidesGETQueryData(option.Canonical) {
				hasData = true
			}
		}
	}
	if hasData {
		dataMode := curlRequestModePost
		if useHTTPGet {
			dataMode = curlRequestModeGet
			if noBody {
				dataMode = curlRequestModeHead
			}
		}
		if !setMode(dataMode) {
			return false
		}
	}
	for _, target := range parsed.Targets {
		if target.Group == group && target.UploadSet && target.UploadValue != "" &&
			!setMode(curlRequestModePut) {
			return false
		}
	}
	return true
}

func curlOptionMakesRangeWireUncertain(option string) bool {
	// This is the closed parser's complete set of options that can change
	// libcurl's internal HTTP request or resume mode. --request changes only
	// the wire method and leaves a default-GET Range header intact.
	switch option {
	case "--data", "--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--json", "--form", "--form-string",
		"--upload-file", "--get", "--head", "--no-head", "--continue-at":
		return true
	default:
		return false
	}
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
	return curlHeaderOverridesHTTPField(value, "cookie")
}

func curlHeaderOverridesHTTPField(value string, field string) bool {
	separator := strings.IndexAny(value, ":;")
	return separator >= 0 && strings.EqualFold(value[:separator], field)
}

// WgetTransmittedMetadata keeps protocol-specific metadata lanes separate so
// callers cannot pair an HTTP-only header with an FTP target. Generic Wget
// origin credentials are returned only when the closed argv state proves
// their effective values.
type WgetTransmittedMetadata struct {
	HTTPHeaders                    []string
	HTTPOriginCredentials          []string
	FTPOriginCredentials           []string
	HTTPRequestComponents          []TransmittedRequestComponent
	HTTPOriginCredentialComponents []TransmittedRequestComponent
	FTPOriginCredentialComponents  []TransmittedRequestComponent
}

// StaticWgetTransmittedMetadata returns effective literal custom headers,
// dedicated request fields, and origin credentials owned by the closed Wget
// parser. Repeated header names replace case-insensitively, and an empty
// --header clears all earlier custom headers. Credentials and dedicated fields
// require --no-config because ambient wgetrc values can otherwise affect their
// effective request bytes.
func StaticWgetTransmittedMetadata(command CommandFact) WgetTransmittedMetadata {
	if !command.ArgvComplete || !isWgetProgram(command.Program) ||
		len(command.Argv) == 0 || command.Executable != command.Argv[0] ||
		len(command.Arguments) != len(command.Argv) {
		return WgetTransmittedMetadata{}
	}
	parsed := parseWgetArgv(command.Argv)
	if !parsed.Complete || !parsed.RequestBodyValid ||
		parsed.Preview || parsed.Background ||
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
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			wgetTargetHasInvalidUserinfo(target.Value) {
			return WgetTransmittedMetadata{}
		}
	}

	lastHeaders := make(map[string]int)
	lastUser := -1
	lastPassword := -1
	lastHTTPUser := -1
	lastHTTPPassword := -1
	lastFTPUser := -1
	lastFTPPassword := -1
	lastUserAgent := -1
	lastReferer := -1
	lastMethod := -1
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
		case "--http-user":
			lastHTTPUser = index
		case "--http-password":
			lastHTTPPassword = index
		case "--ftp-user":
			lastFTPUser = index
		case "--ftp-password":
			lastFTPPassword = index
		case "--user-agent":
			lastUserAgent = index
		case "--referer":
			lastReferer = index
		case "--method":
			lastMethod = index
		}
	}

	metadata := WgetTransmittedMetadata{}
	httpAuthorizationOverridden := false
	proxyAuthorizationHeader := ""
	proxyExplicitlyDisabled := staticWgetProxyDisabled(command, parsed)
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
			if proxyExplicitlyDisabled {
				proxyAuthorizationHeader = wgetWireHeader(value.Value)
			}
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
	_, httpUserAgentOverridden := lastHeaders["user-agent"]
	_, httpRefererOverridden := lastHeaders["referer"]
	finalUserAgent := ""
	finalReferer := ""
	finalMethod := ""
	httpUserOption := wgetCredentialCandidate{}
	httpPasswordOption := wgetCredentialCandidate{}
	ftpUserOption := wgetCredentialCandidate{}
	ftpPasswordOption := wgetCredentialCandidate{}
	if parsed.ConfigDisabled {
		if lastUserAgent >= 0 {
			value := parsed.Values[lastUserAgent]
			if staticWgetValueArgument(command, value) &&
				wgetUserAgentBytesPreserved(value.Value) {
				finalUserAgent = value.Value
			}
		}
		if lastReferer >= 0 {
			value := parsed.Values[lastReferer]
			if staticWgetValueArgument(command, value) &&
				wgetRefererBytesPreserved(value.Value) {
				finalReferer = value.Value
			}
		}
		if lastMethod >= 0 {
			value := parsed.Values[lastMethod]
			if staticWgetValueArgument(command, value) {
				finalMethod = parsed.Method
			}
		}
		httpUserOption = staticWgetCredentialAt(
			command,
			parsed.Values,
			wgetEffectiveCredentialIndex(lastHTTPUser, lastUser),
		)
		httpPasswordOption = staticWgetCredentialAt(
			command,
			parsed.Values,
			wgetEffectiveCredentialIndex(lastHTTPPassword, lastPassword),
		)
		ftpUserOption = staticWgetCredentialAt(
			command,
			parsed.Values,
			wgetEffectiveCredentialIndex(lastFTPUser, lastUser),
		)
		ftpPasswordOption = staticWgetCredentialAt(
			command,
			parsed.Values,
			wgetEffectiveCredentialIndex(lastFTPPassword, lastPassword),
		)
	}
	for _, target := range parsed.TargetValues {
		network, ok := webTargetFact(
			command.ID,
			target.Value,
			NetworkDownload,
		)
		if !ok {
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
		urlUser, urlUserPresent, urlPassword, urlPasswordPresent :=
			webTargetUserinfo(target.Value)
		switch network.Scheme {
		case "http", "https":
			user := httpUserOption
			password := httpPasswordOption
			if urlUserPresent {
				user = wgetCredentialCandidate{
					Value: urlUser, Present: true, Static: true,
				}
			}
			if urlPasswordPresent {
				password = wgetCredentialCandidate{
					Value: urlPassword, Present: true, Static: true,
				}
			}
			if parsed.ConfigDisabled && user.Present && password.Present &&
				!httpAuthorizationOverridden {
				metadata.HTTPOriginCredentialComponents =
					appendWgetCredentialComponents(
						metadata.HTTPOriginCredentialComponents,
						component,
						user,
						password,
					)
			}
		case "ftp", "ftps":
			user := ftpUserOption
			password := ftpPasswordOption
			if urlUserPresent {
				user = wgetCredentialCandidate{
					Value: urlUser, Present: true, Static: true,
				}
			}
			if urlPasswordPresent {
				password = wgetCredentialCandidate{
					Value: urlPassword, Present: true, Static: true,
				}
			}
			if user.Present {
				metadata.FTPOriginCredentialComponents =
					appendWgetCredentialComponents(
						metadata.FTPOriginCredentialComponents,
						component,
						user,
						password,
					)
			}
		}
		if network.Scheme != "http" && network.Scheme != "https" {
			continue
		}
		if proxyAuthorizationHeader != "" {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(proxyAuthorizationHeader),
			)
		}
		if finalUserAgent != "" && !httpUserAgentOverridden {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(finalUserAgent),
			)
		}
		if finalReferer != "" && !httpRefererOverridden {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(finalReferer),
			)
		}
		if finalMethod != "" {
			metadata.HTTPRequestComponents = append(
				metadata.HTTPRequestComponents,
				component(finalMethod),
			)
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
		webTargetHasUserinfo(parsed.Targets[0]) {
		return metadata
	}
	httpUserIndex := wgetEffectiveCredentialIndex(lastHTTPUser, lastUser)
	httpPasswordIndex := wgetEffectiveCredentialIndex(
		lastHTTPPassword,
		lastPassword,
	)
	if httpUserIndex >= 0 && httpPasswordIndex >= 0 &&
		!httpAuthorizationOverridden {
		httpUser, userStatic := staticWgetValueAt(
			command,
			parsed.Values,
			httpUserIndex,
		)
		httpPassword, passwordStatic := staticWgetValueAt(
			command,
			parsed.Values,
			httpPasswordIndex,
		)
		if userStatic && passwordStatic && httpUser != "" {
			metadata.HTTPOriginCredentials = append(
				metadata.HTTPOriginCredentials,
				httpUser,
			)
		}
		if userStatic && passwordStatic && httpPassword != "" {
			metadata.HTTPOriginCredentials = append(
				metadata.HTTPOriginCredentials,
				httpPassword,
			)
		}
	}

	ftpUserIndex := wgetEffectiveCredentialIndex(lastFTPUser, lastUser)
	ftpPasswordIndex := wgetEffectiveCredentialIndex(
		lastFTPPassword,
		lastPassword,
	)
	if ftpUserIndex < 0 {
		return metadata
	}
	ftpUser, userStatic := staticWgetValueAt(
		command,
		parsed.Values,
		ftpUserIndex,
	)
	if !userStatic {
		return metadata
	}
	if ftpUser != "" {
		metadata.FTPOriginCredentials = append(
			metadata.FTPOriginCredentials,
			ftpUser,
		)
	}
	if ftpPasswordIndex >= 0 {
		ftpPassword, passwordStatic := staticWgetValueAt(
			command,
			parsed.Values,
			ftpPasswordIndex,
		)
		if passwordStatic && ftpPassword != "" {
			metadata.FTPOriginCredentials = append(
				metadata.FTPOriginCredentials,
				ftpPassword,
			)
		}
	}
	return metadata
}

func wgetEffectiveCredentialIndex(protocolSpecific int, generic int) int {
	if protocolSpecific >= 0 {
		return protocolSpecific
	}
	return generic
}

func staticWgetValueAt(
	command CommandFact,
	values []wgetArgvValue,
	index int,
) (string, bool) {
	if index < 0 || index >= len(values) ||
		!staticWgetValueArgument(command, values[index]) {
		return "", false
	}
	return values[index].Value, true
}

type wgetCredentialCandidate struct {
	Value   string
	Present bool
	Static  bool
}

func staticWgetCredentialAt(
	command CommandFact,
	values []wgetArgvValue,
	index int,
) wgetCredentialCandidate {
	if index < 0 || index >= len(values) {
		return wgetCredentialCandidate{}
	}
	value, static := staticWgetValueAt(command, values, index)
	return wgetCredentialCandidate{
		Value: value, Present: true, Static: static,
	}
}

func appendWgetCredentialComponents(
	destination []TransmittedRequestComponent,
	component func(string) TransmittedRequestComponent,
	candidates ...wgetCredentialCandidate,
) []TransmittedRequestComponent {
	for _, candidate := range candidates {
		if candidate.Static && candidate.Value != "" &&
			printableASCII(candidate.Value) {
			destination = append(destination, component(candidate.Value))
		}
	}
	return destination
}

func staticWgetValueArgument(command CommandFact, value wgetArgvValue) bool {
	return value.ValueIndex >= 0 && staticCommandArgumentAt(
		command,
		value.ValueIndex,
	)
}

func staticWgetProxyDisabled(
	command CommandFact,
	parsed wgetArgvParse,
) bool {
	if !parsed.ProxySet || parsed.Proxy || parsed.ProxyOptionIndex < 0 ||
		!staticCommandArgumentAt(command, parsed.ProxyOptionIndex) {
		return false
	}
	return parsed.ProxyValueIndex < 0 ||
		parsed.ProxyValueIndex == parsed.ProxyOptionIndex ||
		staticCommandArgumentAt(command, parsed.ProxyValueIndex)
}

func wgetWireHeader(value string) string {
	name, headerValue, _ := strings.Cut(value, ":")
	headerValue = strings.TrimLeftFunc(headerValue, func(character rune) bool {
		return character <= 0x7f && isWgetASCIIWhitespace(byte(character))
	})
	return name + ": " + headerValue
}

func wgetQueryBytesPreserved(value string) bool {
	return wgetURLBytesPreserved(value, "!$&'()*+,-./:;=?@[]_~")
}

func wgetURLPathBytesPreserved(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.Contains(value, "//") ||
		!wgetURLBytesPreserved(value, "!$&'()*+,-./:;=@[]_~") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func wgetURLBytesPreserved(value string, punctuation string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if isASCIIAlphaNumeric(character) ||
			strings.ContainsRune(punctuation, rune(character)) {
			continue
		}
		if character != '%' || index+2 >= len(value) ||
			!isASCIIHexByte(value[index+1]) || !isASCIIHexByte(value[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func isASCIIHexByte(value byte) bool {
	return value >= '0' && value <= '9' ||
		value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func webTargetHasUserinfo(value string) bool {
	parsed, err := url.Parse(value)
	return err != nil || parsed.User != nil
}

func webTargetUserinfo(
	value string,
) (user string, userPresent bool, password string, passwordPresent bool) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.User == nil {
		return "", false, "", false
	}
	user = parsed.User.Username()
	password, passwordPresent = parsed.User.Password()
	return user, true, password, passwordPresent
}

func curlTargetHasInvalidUserinfo(value string) bool {
	user, userPresent, password, passwordPresent := webTargetUserinfo(value)
	return userPresent && !printableASCII(user) ||
		passwordPresent && !printableASCII(password)
}

func wgetTargetHasInvalidUserinfo(value string) bool {
	user, present, _, _ := webTargetUserinfo(value)
	return present && user == ""
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
		len(parsed.Targets) == 0 {
		return nil
	}
	hasHTTPTarget := false
	for _, target := range parsed.TargetValues {
		network, ok := webTargetFact(command.ID, target.Value, NetworkUpload)
		if !ok || !webMetadataTargetSchemeSupported(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) ||
			wgetTargetHasInvalidUserinfo(target.Value) {
			return nil
		}
		switch network.Scheme {
		case "http", "https":
			hasHTTPTarget = true
		case "ftp", "ftps":
		default:
			return nil
		}
	}
	if !hasHTTPTarget {
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

func staticCurlUploadPayloads(option curlOptionToken) ([]string, bool, bool) {
	value := option.Value
	switch option.Canonical {
	case "--data", "--data-ascii", "--data-binary", "--json":
		if _, _, fileSource := webDataFile(value); fileSource {
			return nil, false, false
		}
		if value == "" {
			return nil, true, false
		}
		return []string{value}, true, false
	case "--data-urlencode":
		_, _, fileSource, valid := curlDataURLEncodeFile(value)
		if !valid || fileSource {
			return nil, false, false
		}
		encoded, valid := curlDataURLEncodeBytes(value)
		if !valid {
			return nil, false, false
		}
		if encoded == "" {
			return nil, true, false
		}
		return []string{encoded}, true, false
	case "--data-raw":
		if value == "" {
			return nil, true, false
		}
		return []string{value}, true, false
	case "--form", "--form-string":
		return curlStaticFormPayloads(option)
	default:
		return nil, false, false
	}
}

func curlStaticFormSequenceValid(
	command CommandFact,
	parsed curlArgvParse,
	group int,
) bool {
	depth := 0
	for _, option := range parsed.Options {
		if option.Group != group ||
			(option.Canonical != "--form" && option.Canonical != "--form-string") {
			continue
		}
		if !staticCurlOptionValue(command, option) {
			return false
		}
		if option.Canonical == "--form" &&
			curlFormUsesPOSIXNullDevice(option.Value) &&
			!curlPOSIXNullDeviceAvailable(command) {
			return false
		}
		if option.Canonical == "--form" {
			name, specification, found := strings.Cut(option.Value, "=")
			if !found {
				return false
			}
			switch {
			case strings.HasPrefix(specification, "("):
				depth++
			case name == "" && specification == ")":
				if depth == 0 {
					return false
				}
				depth--
			}
		}
		if _, valid, _ := curlStaticFormPayloads(option); !valid {
			return false
		}
	}
	// Curl transmits an unterminated nested multipart by implicitly closing it.
	return true
}

// curlStaticFormEagerSyntaxValid mirrors the syntax-only part of curl 8.7.1's
// formparse/get_param_part pass. Curl parses every operation before starting
// the first transfer, so malformed syntax in a later --next group prevents an
// earlier FTP login. Ordinary form file availability remains a per-transfer
// setup concern and is deliberately not checked here.
func curlStaticFormEagerSyntaxValid(parsed curlArgvParse) bool {
	depths := make(map[int]int)
	for _, option := range parsed.Options {
		if option.Canonical != "--form" && option.Canonical != "--form-string" {
			continue
		}
		if strings.IndexByte(option.Value, 0) >= 0 {
			return false
		}
		name, specification, found := strings.Cut(option.Value, "=")
		if !found {
			return false
		}
		if option.Canonical == "--form-string" {
			continue
		}
		switch {
		case strings.HasPrefix(specification, "("):
			if _, _, valid := curlFormParameterSyntax(
				specification, 0, 0,
			); !valid {
				return false
			}
			depths[option.Group]++
		case name == "" && specification == ")":
			if depths[option.Group] == 0 {
				return false
			}
			depths[option.Group]--
		case strings.HasPrefix(specification, "@"):
			position := 1
			for {
				next, separator, valid := curlFormParameterSyntax(
					specification, position, ',',
				)
				if !valid {
					return false
				}
				if separator == 0 {
					break
				}
				position = next + 1
			}
		case strings.HasPrefix(specification, "<"):
			if _, _, valid := curlFormParameterSyntax(
				specification, 1, 0,
			); !valid {
				return false
			}
		default:
			if _, _, valid := curlFormParameterSyntax(
				specification, 0, 0,
			); !valid {
				return false
			}
		}
	}
	// Curl implicitly closes an unterminated multipart at operation teardown.
	return true
}

// curlFormParameterSyntax mirrors get_param_part without opening any of the
// referenced files. The returned position points at the terminating comma
// when endCharacter is nonzero.
func curlFormParameterSyntax(
	value string,
	position int,
	endCharacter byte,
) (int, byte, bool) {
	position = curlSkipFormSpace(value, position)
	endCharacters := ";"
	if endCharacter != 0 {
		endCharacters += string(endCharacter)
	}
	_, position = curlFormParameterWordUntil(
		value, position, endCharacters,
	)
	separator := byte(0)
	if position < len(value) {
		separator = value[position]
	}
	typeActive := false
	for separator == ';' {
		position = curlSkipFormSpace(value, position+1)
		switch {
		case !typeActive && curlFormHasFoldedPrefix(value, position, "type="):
			position = curlSkipFormSpace(value, position+len("type="))
			var valid bool
			position, valid = curlFormTypePrefix(value, position)
			if !valid {
				return 0, 0, false
			}
			for position < len(value) && value[position] != ';' &&
				(endCharacter == 0 || value[position] != endCharacter) {
				position++
			}
			typeActive = true
		case curlFormHasFoldedPrefix(value, position, "filename="):
			typeActive = false
			position = curlSkipFormSpace(value, position+len("filename="))
			_, position = curlFormParameterWordUntil(
				value, position, endCharacters,
			)
		case curlFormHasFoldedPrefix(value, position, "headers="):
			typeActive = false
			position += len("headers=")
			if position < len(value) &&
				(value[position] == '@' || value[position] == '<') {
				position = curlSkipFormSpace(value, position+1)
			} else {
				position = curlSkipFormSpace(value, position)
			}
			_, position = curlFormParameterWordUntil(
				value, position, endCharacters,
			)
		case curlFormHasFoldedPrefix(value, position, "encoder="):
			typeActive = false
			position = curlSkipFormSpace(value, position+len("encoder="))
			_, position = curlFormParameterWordUntil(
				value, position, endCharacters,
			)
		case typeActive:
			for position < len(value) && value[position] != ';' &&
				(endCharacter == 0 || value[position] != endCharacter) {
				position++
			}
		default:
			_, position = curlFormParameterWordUntil(
				value, position, endCharacters,
			)
		}
		separator = 0
		if position < len(value) {
			separator = value[position]
		}
	}
	if separator != 0 && separator != endCharacter {
		return 0, 0, false
	}
	return position, separator, true
}

// curlStaticFormPayloads projects only contiguous bytes that curl 8.7.1 puts
// on the wire for the closed literal multipart subset below. In particular,
// name=content is not itself a wire substring: the name is emitted in the
// part headers and the parsed content is emitted later as the MIME body.
func curlStaticFormPayloads(option curlOptionToken) ([]string, bool, bool) {
	if strings.IndexByte(option.Value, 0) >= 0 {
		return nil, false, false
	}
	name, specification, found := strings.Cut(option.Value, "=")
	if !found {
		return nil, false, false
	}
	if option.Canonical == "--form-string" {
		nameComponent, valid := curlStaticFormNameComponent(name)
		if !valid {
			return nil, false, false
		}
		components := nameComponent
		if specification != "" {
			components = append(components, specification)
		}
		return components, true, false
	}
	if option.Canonical != "--form" {
		return nil, false, false
	}
	if strings.HasPrefix(specification, "@") {
		fileEntries, valid := curlMIMEFormFileEntries(specification[1:])
		if !valid {
			return nil, false, false
		}
		if len(fileEntries) > 1 {
			components, valid := curlStaticFormNameComponent(name)
			if !valid {
				return nil, false, false
			}
			for _, fileEntry := range fileEntries {
				fileOption := option
				fileOption.Value = "=@" + fileEntry
				fileComponents, valid, transmissionStops :=
					curlStaticFormPayloads(fileOption)
				if !valid || transmissionStops {
					return nil, false, false
				}
				components = append(components, fileComponents...)
			}
			return components, true, false
		}
	}
	multipartOpener := strings.HasPrefix(specification, "(")
	if name == "" && specification == ")" {
		return nil, true, false
	}

	body := ""
	position := 0
	fileSourceMarker := byte(0)
	if strings.HasPrefix(specification, "@") ||
		strings.HasPrefix(specification, "<") {
		fileSourceMarker = specification[0]
		// The fixed POSIX null device cannot fail after argv validation and has
		// no body bytes. Every other file/stdin source remains opaque.
		var source string
		position = curlSkipFormSpace(specification, 1)
		source, position = curlFormParameterWord(specification, position)
		if source != "/dev/null" {
			return nil, false, false
		}
	} else {
		position = curlSkipFormSpace(specification, 0)
		body, position = curlFormParameterWord(specification, position)
	}
	typeActive := false
	typeStart := 0
	effectiveType := ""
	effectiveFilename := ""
	var inlineHeaders []string
	contentDispositionOverridden := false
	inlineContentType := ""
	inlineContentTypeSet := false
	encoder := ""
	encoderSet := false
	for position < len(specification) {
		if specification[position] != ';' {
			return nil, false, false
		}
		position = curlSkipFormSpace(specification, position+1)
		switch {
		case !typeActive && curlFormHasFoldedPrefix(specification, position, "type="):
			position = curlSkipFormSpace(specification, position+len("type="))
			typeStart = position
			var valid bool
			position, valid = curlFormTypePrefix(specification, position)
			if !valid {
				return nil, false, false
			}
			for position < len(specification) && specification[position] != ';' {
				position++
			}
			effectiveType = curlTrimRightFormSpace(specification[typeStart:position])
			typeActive = true
		case curlFormHasFoldedPrefix(specification, position, "filename="):
			typeActive = false
			position = curlSkipFormSpace(specification, position+len("filename="))
			effectiveFilename, position = curlFormParameterWord(specification, position)
		case curlFormHasFoldedPrefix(specification, position, "headers="):
			typeActive = false
			position += len("headers=")
			if position < len(specification) &&
				(specification[position] == '@' || specification[position] == '<') {
				position++
				position = curlSkipFormSpace(specification, position)
				headerSource, nextPosition := curlFormParameterWord(
					specification,
					position,
				)
				if headerSource != "" && headerSource != "/dev/null" {
					return nil, false, false
				}
				// fopen("") fails non-fatally and /dev/null is empty; curl
				// continues without adding a header in either finite case, so
				// neither source hides the literal body.
				position = nextPosition
				continue
			}
			position = curlSkipFormSpace(specification, position)
			var header string
			header, position = curlFormParameterWord(specification, position)
			inlineHeaders = append(inlineHeaders, header)
			contentDispositionOverridden = contentDispositionOverridden ||
				curlMIMEHeaderOverridesField(header, "content-disposition")
			if contentType, matches := curlMIMEHeaderFieldValue(
				header,
				"content-type",
			); matches && !inlineContentTypeSet {
				inlineContentType = contentType
				inlineContentTypeSet = true
			}
		case curlFormHasFoldedPrefix(specification, position, "encoder="):
			typeActive = false
			position = curlSkipFormSpace(specification, position+len("encoder="))
			encoder, position = curlFormParameterWord(specification, position)
			encoderSet = true
		case typeActive:
			for position < len(specification) && specification[position] != ';' {
				position++
			}
			effectiveType = curlTrimRightFormSpace(specification[typeStart:position])
		default:
			_, position = curlFormParameterWord(specification, position)
		}
	}
	var components []string
	if !contentDispositionOverridden {
		nameComponent, valid := curlStaticFormNameComponent(name)
		if !valid {
			return nil, false, false
		}
		components = append(components, nameComponent...)
		if !multipartOpener && fileSourceMarker != '<' && effectiveFilename != "" {
			filenameComponent, valid := curlMIMEFormEscape(effectiveFilename)
			if !valid {
				return nil, false, false
			}
			components = append(components, filenameComponent)
		}
	}
	// A type= attribute takes precedence over every inline Content-Type header.
	// Without type=, curl uses the first inline Content-Type value to generate
	// the part header. The original Content-Type userheaders are then skipped.
	if effectiveType != "" {
		components = append(components, effectiveType)
	} else if inlineContentTypeSet && inlineContentType != "" {
		components = append(components, inlineContentType)
	}
	for _, header := range inlineHeaders {
		if _, contentType := curlMIMEHeaderFieldValue(
			header,
			"content-type",
		); contentType {
			continue
		}
		if header != "" {
			components = append(components, header)
		}
	}
	if multipartOpener {
		// filename= and encoder= are parsed but ignored for a multipart node;
		// type and inline headers are handled above, and header files stay opaque.
		return components, true, false
	}
	bodyComponent := body
	transmissionStops := false
	if encoderSet {
		switch {
		case curlASCIIEqualFold(encoder, "binary"),
			curlASCIIEqualFold(encoder, "8bit"):
		case curlASCIIEqualFold(encoder, "7bit"):
			for index := 0; index < len(body); index++ {
				if body[index]&0x80 != 0 {
					// The encoder reports an error at the first high byte, but curl
					// may already have transmitted the exact ASCII prefix.
					bodyComponent = body[:index]
					transmissionStops = true
					break
				}
			}
		case curlASCIIEqualFold(encoder, "quoted-printable"):
			bodyComponent = curlMIMEQuotedPrintableBytes(body)
		case curlASCIIEqualFold(encoder, "base64"):
			bodyComponent = ""
		default:
			// curl_mime_encoder rejects unknown encoders before the request.
			return nil, false, false
		}
	}
	if bodyComponent != "" {
		components = append(components, bodyComponent)
	}
	return components, true, transmissionStops
}

// curlMIMEQuotedPrintableBytes mirrors curl 8.7.1's encoder_qp_read for an
// in-memory literal body. Its line position excludes CRLF and soft breaks.
func curlMIMEQuotedPrintableBytes(value string) string {
	const maximumEncodedLineLength = 76

	var encoded strings.Builder
	linePosition := 0
	for inputPosition := 0; inputPosition < len(value); {
		if value[inputPosition] == '\r' && inputPosition+1 < len(value) &&
			value[inputPosition+1] == '\n' {
			encoded.WriteString("\r\n")
			linePosition = 0
			inputPosition += 2
			continue
		}

		character := value[inputPosition]
		nextPosition := inputPosition + 1
		nextIsEnd := nextPosition == len(value)
		nextIsCRLF := nextPosition+1 < len(value) &&
			value[nextPosition] == '\r' && value[nextPosition+1] == '\n'
		unitLength := 1
		raw := character >= 0x21 && character <= 0x3c ||
			character >= 0x3e && character <= 0x7e
		if character == ' ' || character == '\t' {
			raw = !nextIsEnd && !nextIsCRLF
		}
		if !raw {
			unitLength = 3
		}
		if linePosition+unitLength > maximumEncodedLineLength ||
			linePosition+unitLength == maximumEncodedLineLength &&
				!nextIsEnd && !nextIsCRLF {
			encoded.WriteString("=\r\n")
			linePosition = 0
		}
		if raw {
			encoded.WriteByte(character)
		} else {
			const uppercaseHex = "0123456789ABCDEF"
			encoded.WriteByte('=')
			encoded.WriteByte(uppercaseHex[character>>4])
			encoded.WriteByte(uppercaseHex[character&0x0f])
		}
		linePosition += unitLength
		inputPosition++
	}
	return encoded.String()
}

func curlStaticFormNameComponent(name string) ([]string, bool) {
	if name == "" {
		return nil, true
	}
	escaped, valid := curlMIMEFormEscape(name)
	if !valid {
		return nil, false
	}
	return []string{escaped}, true
}

// curlMIMEFormEscape mirrors curl 8.7.1's default form-data name and filename
// escaping. --form-escape is outside the closed parser, so only quote, CR, and
// LF are replaced; all other bytes, including UTF-8, remain exact.
func curlMIMEFormEscape(value string) (string, bool) {
	outputLength := 0
	for index := range len(value) {
		switch value[index] {
		case '"', '\r', '\n':
			outputLength += 3
		default:
			outputLength++
		}
		if outputLength >= 8_000_000 {
			return "", false
		}
	}
	if outputLength == len(value) {
		return value, true
	}
	var escaped strings.Builder
	escaped.Grow(outputLength)
	for index := range len(value) {
		switch value[index] {
		case '"':
			escaped.WriteString("%22")
		case '\r':
			escaped.WriteString("%0D")
		case '\n':
			escaped.WriteString("%0A")
		default:
			escaped.WriteByte(value[index])
		}
	}
	return escaped.String(), true
}

func curlSkipFormSpace(value string, position int) int {
	for position < len(value) && curlFormSpace(value[position]) {
		position++
	}
	return position
}

func curlTrimRightFormSpace(value string) string {
	for len(value) > 0 && curlFormSpace(value[len(value)-1]) {
		value = value[:len(value)-1]
	}
	return value
}

func curlFormSpace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}

// curlFormParameterWord mirrors curl 8.7.1's get_param_word for a form part:
// quoted words lose their quotes and only escaped backslashes and quotes are
// unescaped; an unclosed quote falls back to the ordinary unquoted grammar.
func curlFormParameterWord(value string, position int) (string, int) {
	return curlFormParameterWordUntil(value, position, ";")
}

func curlFormParameterWordUntil(
	value string,
	position int,
	endCharacters string,
) (string, int) {
	start := position
	if position < len(value) && value[position] == '"' {
		position++
		var word strings.Builder
		for position < len(value) {
			if value[position] == '\\' && position+1 < len(value) &&
				(value[position+1] == '\\' || value[position+1] == '"') {
				word.WriteByte(value[position+1])
				position += 2
				continue
			}
			if value[position] == '"' {
				position++
				for position < len(value) &&
					!strings.ContainsRune(endCharacters, rune(value[position])) {
					position++
				}
				return word.String(), position
			}
			word.WriteByte(value[position])
			position++
		}
		position = start
	}
	for position < len(value) &&
		!strings.ContainsRune(endCharacters, rune(value[position])) {
		position++
	}
	end := position
	for end > start && curlFormSpace(value[end-1]) {
		end--
	}
	return value[start:end], position
}

func curlMIMEFormFileEntries(value string) ([]string, bool) {
	var entries []string
	entryStart := 0
	position := 0
	for {
		typeActive := false
		position = curlSkipFormSpace(value, position)
		_, position = curlFormParameterWordUntil(value, position, ";,")
		for position < len(value) && value[position] == ';' {
			position = curlSkipFormSpace(value, position+1)
			switch {
			case !typeActive && curlFormHasFoldedPrefix(value, position, "type="):
				position = curlSkipFormSpace(value, position+len("type="))
				for position < len(value) && value[position] != ';' &&
					value[position] != ',' {
					position++
				}
				typeActive = true
			case curlFormHasFoldedPrefix(value, position, "filename="):
				typeActive = false
				position = curlSkipFormSpace(value, position+len("filename="))
				_, position = curlFormParameterWordUntil(value, position, ";,")
			case curlFormHasFoldedPrefix(value, position, "headers="):
				typeActive = false
				position += len("headers=")
				if position < len(value) &&
					(value[position] == '@' || value[position] == '<') {
					position = curlSkipFormSpace(value, position+1)
				}
				_, position = curlFormParameterWordUntil(value, position, ";,")
			case curlFormHasFoldedPrefix(value, position, "encoder="):
				typeActive = false
				position = curlSkipFormSpace(value, position+len("encoder="))
				_, position = curlFormParameterWordUntil(value, position, ";,")
			case typeActive:
				// Curl's endct branch extends the active Content-Type by scanning
				// raw bytes. Quotes do not protect a comma here: that comma starts
				// the next file entry and can make the command fail before connect.
				for position < len(value) && value[position] != ';' &&
					value[position] != ',' {
					position++
				}
			default:
				_, position = curlFormParameterWordUntil(value, position, ";,")
			}
		}
		if position < len(value) && value[position] != ',' {
			return nil, false
		}
		entries = append(entries, value[entryStart:position])
		if position == len(value) {
			return entries, true
		}
		position++
		entryStart = position
	}
}

func curlFormHasFoldedPrefix(value string, position int, prefix string) bool {
	return position >= 0 && position+len(prefix) <= len(value) &&
		curlASCIIEqualFold(value[position:position+len(prefix)], prefix)
}

func curlMIMEHeaderOverridesField(value string, field string) bool {
	return len(value) > len(field) &&
		curlASCIIEqualFold(value[:len(field)], field) && value[len(field)] == ':'
}

func curlASCIIEqualFold(value string, expected string) bool {
	if len(value) != len(expected) {
		return false
	}
	for index := range len(value) {
		left := value[index]
		right := expected[index]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func curlMIMEHeaderFieldValue(value string, field string) (string, bool) {
	if !curlMIMEHeaderOverridesField(value, field) {
		return "", false
	}
	// mime.c's match_header skips only literal spaces after the colon.
	return strings.TrimLeft(value[len(field)+1:], " "), true
}

// curlFormTypePrefix mirrors the two bounded scansets used by curl 8.7.1's
// get_param_part. The caller consumes any remaining type text up to ';'.
func curlFormTypePrefix(value string, position int) (int, bool) {
	majorStart := position
	for position < len(value) && position-majorStart < 127 &&
		value[position] != '/' && value[position] != ' ' {
		position++
	}
	if position == majorStart || position >= len(value) || value[position] != '/' {
		return 0, false
	}
	position++
	minorStart := position
	for position < len(value) && position-minorStart < 127 {
		switch value[position] {
		case ';', ',', ' ', '\n':
			return position, position > minorStart
		default:
			position++
		}
	}
	return position, position > minorStart
}

func curlDataURLEncodeBytes(value string) (string, bool) {
	name, content, hasEquals := strings.Cut(value, "=")
	if hasEquals {
		encoded, valid := curlFormURLEncodeBytes(content)
		if !valid || strings.IndexByte(name, 0) >= 0 {
			return "", false
		}
		if name == "" {
			return encoded, true
		}
		return name + "=" + encoded, true
	}
	if strings.Contains(value, "@") {
		return "", false
	}
	encoded, valid := curlFormURLEncodeBytes(value)
	return encoded, valid
}

func curlFormURLEncodeBytes(value string) (string, bool) {
	const upperHex = "0123456789ABCDEF"
	var encoded strings.Builder
	for index := range len(value) {
		character := value[index]
		switch {
		case character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '.' ||
			character == '_' || character == '~':
			encoded.WriteByte(character)
		case character == ' ':
			encoded.WriteByte('+')
		case character == 0:
			return "", false
		default:
			encoded.WriteByte('%')
			encoded.WriteByte(upperHex[character>>4])
			encoded.WriteByte(upperHex[character&0x0f])
		}
	}
	return encoded.String(), true
}

func curlGroupTargetsAreFTPFamily(parsed curlArgvParse, group int) bool {
	found := false
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		found = true
		lower := strings.ToLower(target.Value)
		if !strings.HasPrefix(lower, "ftp://") &&
			!strings.HasPrefix(lower, "ftps://") {
			return false
		}
	}
	return found
}

type curlFTPTLSState struct {
	try           bool
	required      bool
	control       bool
	insecure      bool
	certificate   string
	caCertificate string
}

func curlEffectiveFTPTLSState(parsed curlArgvParse, group int) curlFTPTLSState {
	state := curlFTPTLSState{}
	for _, option := range parsed.Options {
		if option.Group != group {
			continue
		}
		switch option.Canonical {
		case "--ssl":
			state.try = option.Name != "--no-ssl" &&
				option.Name != "--no-ftp-ssl"
		case "--ssl-reqd":
			state.required = option.Name != "--no-ssl-reqd" &&
				option.Name != "--no-ftp-ssl-reqd"
		case "--ftp-ssl-control":
			state.control = option.Name != "--no-ftp-ssl-control"
		case "--insecure":
			state.insecure = option.Name != "--no-insecure"
		case "--cert":
			state.certificate = option.Value
		case "--cacert":
			state.caCertificate = option.Value
		}
	}
	return state
}

func (state curlFTPTLSState) requiredForScheme(scheme string) bool {
	switch scheme {
	case "https", "ftps", "smtps", "wss":
		return true
	case "ftp", "smtp":
		return state.required || state.control && !state.try
	default:
		return false
	}
}

func curlGroupRequiresPreloginTLS(parsed curlArgvParse, group int) bool {
	state := curlEffectiveFTPTLSState(parsed, group)
	for _, target := range parsed.Targets {
		if target.Group != group {
			continue
		}
		network, valid := webTargetFact(0, target.Value, NetworkDownload)
		if !valid {
			network, valid = curlSMTPTargetFact(
				0,
				target.Value,
				NetworkDownload,
			)
		}
		if valid && state.requiredForScheme(network.Scheme) {
			return true
		}
	}
	return false
}

func curlGroupHasPlainFTPUpgradeTLS(parsed curlArgvParse, group int) bool {
	state := curlEffectiveFTPTLSState(parsed, group)
	if !state.requiredForScheme("ftp") {
		return false
	}
	for _, target := range parsed.Targets {
		if target.Group == group &&
			strings.HasPrefix(strings.ToLower(target.Value), "ftp://") {
			return true
		}
	}
	return false
}

func curlGroupFinalOptionValue(
	parsed curlArgvParse,
	group int,
	canonical string,
) string {
	value := ""
	for _, option := range parsed.Options {
		if option.Group == group && option.Canonical == canonical &&
			option.ValuePresent {
			value = option.Value
		}
	}
	return value
}

func classifyParsedCurlTransfer(out *parseOutput, command *CommandFact) {
	parsed := parseCurlArgv(command.Argv)
	proxyCommand := *command
	if command.ParentCommandID != 0 || len(command.Wrappers) != 0 {
		if isolatedPOSIXCommand(out, command) {
			proxyCommand.ParentCommandID = 0
			proxyCommand.Wrappers = nil
		}
	}
	proxyNetwork, _, proxyProved := staticCurlProxyDestination(proxyCommand)
	proxyNetworks := []NetworkFact(nil)
	proxyRoutingProved := make(map[int]bool)
	if proxyProved {
		proxyNetworks = append(proxyNetworks, proxyNetwork)
		if len(parsed.Targets) > 0 {
			proxyRoutingProved[parsed.Targets[0].Group] = true
		}
	}
	if !proxyProved && len(parsed.Targets) > 0 {
		groups := make(map[int]struct{})
		for _, target := range parsed.Targets {
			groups[target.Group] = struct{}{}
		}
		for group := range groups {
			ftpProxyRoute, proved := staticCurlFTPProxyRoute(
				*command, parsed, group,
			)
			proved = proved && curlGroupTargetsAreFTPFamily(parsed, group)
			proxyRoutingProved[group] = proved
			if proved && len(ftpProxyRoute.Networks) != 0 {
				proxyNetworks = append(proxyNetworks, ftpProxyRoute.Networks...)
				proxyProved = true
			}
		}
	}
	nullConfigOnly := staticCurlPOSIXNullConfigOnly(*command, parsed)
	valid := (parsed.Complete || nullConfigOnly) &&
		!parsed.EmptyTransferGroup &&
		parsed.hasValidOptionValues() && curlRequestModeValid(parsed) &&
		curlRangeOptionsValid(parsed)
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
	telnetNetwork := NetworkFact{}
	telnetRoutingProved := false
	if telnetCommand, isolated := staticCurlTelnetCommandForCommands(
		out.commands,
		command.ID,
	); isolated {
		var telnetValid bool
		telnetNetwork, _, telnetValid = staticCurlTelnetOptionProjection(
			telnetCommand,
			parsed,
		)
		telnetRoutingProved = telnetValid
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
		if option.Canonical == "--proto-default" && !telnetRoutingProved {
			// A schemeless target is not generically HTTP once curl has a
			// protocol default. Only the exact Telnet projector currently owns
			// this runtime-capability-dependent route selection.
			out.markPartial(IssueUnsupportedConstruct)
		}
		if option.Role == curlOptionTelnetProof && !telnetRoutingProved {
			// Parser ownership for the exact Telnet projector must not make a
			// previously unknown option authoritative for generic curl targets.
			out.markPartial(IssueUnsupportedConstruct)
		}
		if !option.ValuePresent {
			continue
		}
		group := &groups[option.Group]
		value := option.Value
		switch option.Canonical {
		case "--config":
			if nullConfigOnly && value == "/dev/null" {
				continue
			}
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
		case "--stderr":
			if value == "-" ||
				command.Dialect == DialectPOSIX && value == "/dev/null" {
				continue
			}
			if value != "" && value != "-" {
				appendCommandPath(out, command, PathAccessWrite, value)
			}
			// Curl opens this destination before connecting. Without a proven
			// null device the transfer can deterministically fail before any
			// projected network bytes are sent.
			out.markPartial(IssueUnsupportedConstruct)
		case "--unix-socket":
			group.hasUnix = true
			group.unixSocket = value
		case "--output-dir":
			group.hasOutputDir = true
			group.outputDir = value
			for _, target := range parsed.Targets {
				if target.Group == option.Group &&
					target.Output != curlOutputStdout {
					out.markPartial(IssueUnsupportedConstruct)
					break
				}
			}
		case "--cacert":
			group.hasCACert = true
			group.cacert = value
		case "--key":
			group.hasKey = true
			group.key = value
		case "--cert":
			// A certificate operand may include a password suffix. Until that
			// grammar is represented, retain it as diagnostic-only context.
			if curlGroupRequiresPreloginTLS(parsed, option.Group) &&
				curlGroupFinalOptionValue(parsed, option.Group, "--cert") != "" {
				out.markPartial(IssueUnknownOperandGrammar)
			}
		case "--proxy", "--proxy1.0", "--socks4", "--socks4a",
			"--socks5", "--socks5-hostname", "--preproxy":
			if !proxyRoutingProved[option.Group] && !telnetRoutingProved {
				out.markPartial(IssueUnsupportedConstruct)
			}
		case "--noproxy":
			if !proxyRoutingProved[option.Group] && !telnetRoutingProved {
				out.markPartial(IssueUnsupportedConstruct)
			}
		case "--interface":
			final, found := curlFinalGroupOption(
				parsed, option.Group, "--interface",
			)
			if found && option.ArgvIndex == final.ArgvIndex &&
				!proxyRoutingProved[option.Group] {
				out.markPartial(IssueUnsupportedConstruct)
			}
		case "--proxy-header":
			if strings.HasPrefix(value, "@") {
				if value == "@/dev/null" && command.Dialect == DialectPOSIX {
					continue
				}
				if path := strings.TrimPrefix(value, "@"); path != "" && path != "-" {
					appendCommandPath(out, command, PathAccessRead, path)
				}
				out.markPartial(IssueUnsupportedConstruct)
			}
		case "--connect-to", "--dns-servers", "--resolve":
			// These options can replace the actual peer while leaving the
			// logical URL unchanged.
			out.markPartial(IssueUnsupportedConstruct)
		case "--doh-url":
			if !telnetRoutingProved {
				out.markPartial(IssueUnsupportedConstruct)
			}
		}
	}

	for index := range groups {
		group := &groups[index]
		ipv4Only, _ := curlEffectiveIPv4Only(parsed, index)
		if ipv4Only && curlGroupTargetsAreFTPFamily(parsed, index) &&
			!proxyRoutingProved[index] {
			out.markPartial(IssueUnsupportedConstruct)
		}
		requiresTLS := curlGroupRequiresPreloginTLS(parsed, index)
		tlsState := curlEffectiveFTPTLSState(parsed, index)
		activeCert := tlsState.certificate != ""
		insecure := tlsState.insecure
		if curlGroupHasPlainFTPUpgradeTLS(parsed, index) &&
			(group.hasCACert && group.cacert != "" && group.cacert != "-" &&
				!insecure ||
				tlsState.certificate != "" && tlsState.certificate != "-" ||
				group.hasKey && group.key != "" && group.key != "-" && activeCert) {
			// TLS support-file reads are not request payloads. Preserve the
			// pre-existing detection-only boundary for newly owned FTP upgrade
			// modes until path facts can distinguish trust inputs from uploads.
			out.markPartial(IssueUnsupportedConstruct)
		}
		for _, input := range []struct {
			set   bool
			value string
			used  bool
		}{
			{
				set: group.hasCACert, value: group.cacert,
				used: requiresTLS && !insecure,
			},
			{
				set: group.hasKey, value: group.key,
				used: requiresTLS && activeCert,
			},
		} {
			if input.used && input.set && input.value != "" && input.value != "-" {
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
	if proxyProved {
		addOperation(command, OperationConnect)
		for _, network := range proxyNetworks {
			if !out.appendNetwork(network) {
				out.markPartial(IssueUnknownOperandGrammar)
			}
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
		if target.UploadSet {
			switch target.UploadValue {
			case "-", ".":
				group.hasUploadStdin = true
			case "":
				// An empty --upload-file clears upload for this target.
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
		case curlOutputRemoteName:
			filename, filenameValid := curlRemoteNameFilename(*command, target)
			if command.Dialect != DialectPOSIX || !filenameValid ||
				group.hasOutputDir {
				out.markPartial(IssueUnknownOperandGrammar)
				break
			}
			appendCommandPath(out, command, PathAccessWrite, filename)
			group.hasDownloadFile = true
		case curlOutputUnknown:
			out.markPartial(IssueUnknownOperandGrammar)
		}

		fact := NetworkFact{}
		ok := false
		if telnetRoutingProved {
			// The Telnet projector has already proved the command has exactly
			// one target. Prefer its normalized fact so --proto-default telnet
			// cannot be reinterpreted as the generic schemeless HTTP fallback.
			fact = telnetNetwork
			ok = true
		} else if !curlTargetSelectsTelnet(parsed, target) {
			fact, ok = webTargetFact(command.ID, target.Value, NetworkDownload)
		}
		if !ok {
			fact, ok = curlSMTPTargetFact(
				command.ID,
				target.Value,
				NetworkDownload,
			)
		}
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		targetUpload := target.UploadSet && target.UploadValue != "" || group.upload &&
			(fact.Scheme == "http" || fact.Scheme == "https")
		if targetUpload {
			fact.Action = NetworkUpload
			group.hasUploadTarget = true
		} else {
			group.hasDownloadTarget = true
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

	if parsed.RequestBodyValid {
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

	hasUploadNetwork := false
	hasDownloadNetwork := false
	for _, target := range parsed.Targets {
		fact, ok := webTargetFact(command.ID, target, NetworkDownload)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		targetUpload := upload &&
			(fact.Scheme == "http" || fact.Scheme == "https")
		if targetUpload {
			fact.Action = NetworkUpload
		}
		if out.appendNetwork(fact) {
			hasNetwork = true
			if targetUpload {
				hasUploadNetwork = true
			} else {
				hasDownloadNetwork = true
			}
		}
	}
	if !hasNetwork {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if hasUploadNetwork {
		addOperation(command, OperationUpload)
		addWebTransferFlows(
			out,
			command.ID,
			true,
			true,
			hasUploadFile,
			false,
			hasProcessUpload,
			hasDownloadFile,
		)
	}
	if hasDownloadNetwork {
		addOperation(command, OperationFetch)
		addWebTransferFlows(
			out,
			command.ID,
			false,
			true,
			false,
			false,
			false,
			hasDownloadFile,
		)
	}
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
	// Curl gives the first '=' precedence over '@' file syntax. In that form
	// the name is transmitted raw and only the content after '=' is encoded.
	if strings.Contains(value, "=") {
		return "", false, false, true
	}
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
		if curlFormHasFoldedPrefix(parameter, 0, "headers=") {
			// Curl applies its own quoted header-source grammar after shell quote
			// removal. Only an immediate @ or < after '=' selects a file; leading
			// whitespace instead makes the value an inline literal header.
			header := parameter[len("headers="):]
			if strings.HasPrefix(header, "@") || strings.HasPrefix(header, "<") {
				position := curlSkipFormSpace(header, 1)
				source, _ := curlFormParameterWord(header, position)
				if source != "" && source != "/dev/null" {
					return true
				}
				continue
			}
			if strings.HasPrefix(header, `"@`) || strings.HasPrefix(header, `"<`) ||
				strings.HasPrefix(header, `'@`) || strings.HasPrefix(header, `'<`) {
				return true
			}
		}
	}
	_, payload, hasName := strings.Cut(value, "=")
	if !hasName {
		payload = value
	}
	if payload == "" || payload[0] != '@' && payload[0] != '<' {
		return false
	}
	if payload[0] == '@' {
		fileEntries, valid := curlMIMEFormFileEntries(payload[1:])
		if valid && len(fileEntries) > 1 {
			for _, fileEntry := range fileEntries {
				_, entryValid, _ := curlStaticFormPayloads(curlOptionToken{
					Canonical: "--form",
					Value:     "=@" + fileEntry,
				})
				if !entryValid {
					return true
				}
			}
			return false
		}
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
