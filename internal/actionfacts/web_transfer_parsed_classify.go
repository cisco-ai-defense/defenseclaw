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
	"strconv"
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
	for _, target := range parsed.Targets {
		if !webMetadataTargetSchemeSupported(target.Value) ||
			!validLiteralRequestTarget(target.Value) ||
			curlTargetHasInvalidUserinfo(target.Value) ||
			curlHasUnmodeledGlob(target.Value) ||
			!staticCommandArgumentAt(command, target.ArgvIndex) {
			return CurlTransmittedMetadata{}
		}
	}

	lastUser := -1
	lastBearer := -1
	lastRequestTarget := -1
	lastUserAgent := -1
	lastReferer := -1
	lastRange := -1
	lastRequestMethod := -1
	rangeWireUncertain := false
	getQueryDataSet := false
	httpGetSet := false
	netrcSet := false
	var urlQueryValues []string
	var urlQueryOutputLengths []int
	urlQueryFragmentSeen := false
	var ftpQuoteValues []string
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
		if option.Canonical == "--get" {
			httpGetSet = true
		}
		if option.Canonical == "--netrc" {
			netrcSet = true
		}
		if curlOptionProvidesGETQueryData(option.Canonical) {
			getQueryDataSet = true
		}
		if option.Canonical == "--url-query" {
			if !staticCurlOptionValue(command, option) {
				return CurlTransmittedMetadata{}
			}
			wireValue, preserved := curlURLQueryOptionBytes(option.Value)
			if !preserved {
				if raw, rawForm := strings.CutPrefix(option.Value, "+"); rawForm {
					if !visibleASCII(raw) {
						return CurlTransmittedMetadata{}
					}
					// Curl retains an empty output as the first query buffer, so a
					// later occurrence still incurs the joining ampersand and the
					// repeated-query size cap.
					urlQueryOutputLengths = append(urlQueryOutputLengths, len(raw))
					prefix, _, fragment := strings.Cut(raw, "#")
					if !urlQueryFragmentSeen && prefix != "" {
						urlQueryValues = append(urlQueryValues, prefix)
					}
					urlQueryFragmentSeen = urlQueryFragmentSeen || fragment
					continue
				}
				_, _, fileForm, valid := curlDataURLEncodeFile(option.Value)
				if !valid || fileForm {
					return CurlTransmittedMetadata{}
				}
				// Non-file data-urlencode forms may transform their content.
				// Omit only that candidate; they do not invalidate independent
				// literal headers or credentials from the same request.
				if len(option.Value) >= 8_000_000/3 {
					return CurlTransmittedMetadata{}
				}
				urlQueryOutputLengths = append(
					urlQueryOutputLengths,
					3*len(option.Value),
				)
				continue
			}
			if wireValue != "" {
				if !urlQueryFragmentSeen {
					urlQueryValues = append(urlQueryValues, wireValue)
				}
			}
			urlQueryOutputLengths = append(urlQueryOutputLengths, len(wireValue))
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
	if httpGetSet && getQueryDataSet {
		// In curl 8.7.1, -G with a data option replaces --url-query as the
		// appended query source instead of combining the two.
		urlQueryValues = nil
		urlQueryOutputLengths = nil
	}
	if !curlURLQueryLengthsValid(parsed.Targets, urlQueryOutputLengths) {
		return CurlTransmittedMetadata{}
	}
	requestTargetValue := ""
	requestTargetSet := lastRequestTarget >= 0
	if lastRequestTarget >= 0 {
		requestTarget := parsed.Options[lastRequestTarget]
		if staticCurlOptionValue(command, requestTarget) &&
			curlHTTPRequestLineBytesPreserved(requestTarget.Value) {
			requestTargetValue = requestTarget.Value
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
		if requestTargetSet {
			if requestTargetValue != "" {
				metadata.HTTPRequestComponents = append(
					metadata.HTTPRequestComponents,
					component(requestTargetValue),
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
		for _, query := range urlQueryValues {
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

func wgetUserAgentBytesPreserved(value string) bool {
	return value != "" && validWgetUserAgent(value)
}

func wgetRefererBytesPreserved(value string) bool {
	return value != "" && !strings.ContainsRune(value, 0)
}

func curlURLQueryOptionBytes(value string) (string, bool) {
	if raw, found := strings.CutPrefix(value, "+"); found {
		return raw, curlRawURLQueryBytesPreserved(raw)
	}
	name, content, hasEquals := strings.Cut(value, "=")
	if hasEquals {
		if !webUnreservedBytesPreserved(name, "-._~") ||
			!webUnreservedBytesPreserved(content, "-._~") {
			return "", false
		}
		if name == "" {
			return content, true
		}
		return name + "=" + content, true
	}
	if strings.Contains(value, "@") ||
		!webUnreservedBytesPreserved(value, "-._~") {
		return "", false
	}
	return value, true
}

func curlRawURLQueryBytesPreserved(value string) bool {
	return visibleASCII(value) && !strings.Contains(value, "#")
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
			useHTTPGet = true
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
		if target.UploadSet && target.UploadValue != "" &&
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
		if !valid || fileSource {
			return "", false
		}
		return curlDataURLEncodeBytes(value)
	case "--data-raw", "--form-string":
		return value, value != ""
	case "--form":
		if curlFormHasUnmodeledFileReference(value) ||
			curlFormHasEncoderParameter(value) {
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

func curlDataURLEncodeBytes(value string) (string, bool) {
	name, content, hasEquals := strings.Cut(value, "=")
	if hasEquals {
		if !webUnreservedBytesPreserved(name, "-._~") ||
			!webUnreservedBytesPreserved(content, "-._~") {
			return "", false
		}
		if name == "" {
			return content, content != ""
		}
		return name + "=" + content, true
	}
	if strings.Contains(value, "@") ||
		!webUnreservedBytesPreserved(value, "-._~") {
		return "", false
	}
	return value, value != ""
}

func classifyParsedCurlTransfer(out *parseOutput, command *CommandFact) {
	parsed := parseCurlArgv(command.Argv)
	valid := parsed.Complete && !parsed.EmptyTransferGroup &&
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

		fact, ok := webTargetFact(command.ID, target.Value, NetworkDownload)
		if !ok {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		targetUpload := target.UploadSet || group.upload &&
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

func curlFormHasEncoderParameter(value string) bool {
	for _, parameter := range strings.Split(value, ";")[1:] {
		name, _, found := strings.Cut(parameter, "=")
		if found && strings.EqualFold(strings.TrimSpace(name), "encoder") {
			return true
		}
	}
	return false
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
