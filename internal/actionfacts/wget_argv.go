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
	"strconv"
	"strings"
)

type wgetArgvValue struct {
	Option      string
	Value       string
	OptionIndex int
	ValueIndex  int
	Joined      bool
}

type wgetRequestBodyIssue string

const (
	wgetRequestBodyIssueNone             wgetRequestBodyIssue = ""
	wgetRequestBodyIssueMissingMethod    wgetRequestBodyIssue = "missing_method"
	wgetRequestBodyIssuePostConflict     wgetRequestBodyIssue = "post_data_file_conflict"
	wgetRequestBodyIssuePostWithMethod   wgetRequestBodyIssue = "post_with_method"
	wgetRequestBodyIssueBodyConflict     wgetRequestBodyIssue = "body_data_file_conflict"
	wgetRequestBodyIssueInvalidFileValue wgetRequestBodyIssue = "invalid_file_value"
)

// wgetArgvParse is a closed, side-effect-free projection of the GNU Wget
// command-line state that affects response ownership. Complete denotes the
// parser's closed proof subset, which intentionally rejects unknown options
// and undocumented numeric-prefix quirks that some Wget builds accept. Values
// records every recognized value-taking occurrence, including legal empty
// values, so classifiers consume the same token ownership as the proof layer.
type wgetArgvParse struct {
	Complete bool

	Targets []string
	Values  []wgetArgvValue

	OutputSet    bool
	Output       string
	LogOutputSet bool
	LogOutput    string
	AppendLog    bool

	InputFileSet bool
	InputFile    string

	Preview          bool
	Background       bool
	ConfigIndirect   bool
	ConfigDisabled   bool
	Spider           bool
	MethodSet        bool
	Method           string
	RequestBodyValid bool
	RequestBodyIssue wgetRequestBodyIssue

	PostDataSet bool
	PostData    string
	PostFileSet bool
	PostFile    string
	BodyDataSet bool
	BodyData    string
	BodyFileSet bool
	BodyFile    string

	quietSet       bool
	quiet          bool
	verboseSet     bool
	verbose        bool
	ipv4           bool
	ipv6           bool
	timestamping   bool
	noClobber      bool
	convertLinks   bool
	recursive      bool
	pageRequisites bool
}

// provesResponseStdout reports whether the closed argv grammar establishes
// response ownership under the package's standard argv-only assumptions.
// Explicit input/config indirection and background or control modes are
// deliberately outside that proof.
func (parsed wgetArgvParse) provesResponseStdout() bool {
	return parsed.Complete &&
		!parsed.Preview &&
		!parsed.Background &&
		!parsed.ConfigIndirect &&
		!parsed.InputFileSet &&
		!parsed.Spider &&
		(!parsed.LogOutputSet || parsed.LogOutput != "-") &&
		parsed.OutputSet && parsed.Output == "-"
}

type wgetOptionArity uint8

const (
	wgetOptionFlag wgetOptionArity = iota
	wgetOptionRequiredValue
	wgetOptionOptionalBoolean
)

type wgetOptionEffect uint8

const (
	wgetEffectNone wgetOptionEffect = iota
	wgetEffectPreview
	wgetEffectBackground
	wgetEffectConfigFile
	wgetEffectExecute
	wgetEffectInputFile
	wgetEffectOutputDocument
	wgetEffectLogOutput
	wgetEffectMethod
	wgetEffectPostData
	wgetEffectPostFile
	wgetEffectBodyData
	wgetEffectBodyFile
	wgetEffectSpider
	wgetEffectQuiet
	wgetEffectVerbose
	wgetEffectIPv4
	wgetEffectIPv6
	wgetEffectNoBundle
	wgetEffectTimestamping
	wgetEffectNoClobber
	wgetEffectConvertLinks
	wgetEffectRecursive
	wgetEffectPageRequisites
	wgetEffectMirror
)

type wgetOptionSpec struct {
	name          string
	arity         wgetOptionArity
	effect        wgetOptionEffect
	allowEmpty    bool
	validate      func(string) bool
	flagValue     bool
	validateFinal bool
}

var wgetShortOptionSpecs = map[byte]wgetOptionSpec{
	'A': wgetValueSpec("--accept", true, nil),
	'B': wgetValueSpec("--base", false, nil),
	'D': wgetValueSpec("--domains", true, nil),
	'E': wgetFlagSpec("--adjust-extension", wgetEffectNone, true),
	'F': wgetFlagSpec("--force-html", wgetEffectNone, true),
	'H': wgetFlagSpec("--span-hosts", wgetEffectNone, true),
	'I': wgetValueSpec("--include-directories", true, nil),
	'K': wgetFlagSpec("--backup-converted", wgetEffectNone, true),
	'L': wgetFlagSpec("--relative", wgetEffectNone, true),
	'N': wgetFlagSpec("--timestamping", wgetEffectTimestamping, true),
	'O': wgetFinalEffectValueSpec("--output-document", wgetEffectOutputDocument, nil),
	'P': wgetValueSpec("--directory-prefix", false, nil),
	'Q': wgetValueSpec("--quota", false, validWgetBytes),
	'R': wgetValueSpec("--reject", true, nil),
	'S': wgetFlagSpec("--server-response", wgetEffectNone, true),
	'T': wgetValueSpec("--timeout", false, validWgetTime),
	'U': wgetValueSpec("--user-agent", true, validWgetUserAgent),
	'V': wgetFlagSpec("--version", wgetEffectPreview, true),
	'X': wgetValueSpec("--exclude-directories", true, nil),
	'Y': wgetValueSpec("--proxy", false, validWgetBoolean),
	'a': wgetFinalEffectValueSpec("--append-output", wgetEffectLogOutput, nil),
	'b': wgetFlagSpec("--background", wgetEffectBackground, true),
	'c': wgetFlagSpec("--continue", wgetEffectNone, true),
	'd': wgetFlagSpec("--debug", wgetEffectNone, true),
	'e': wgetEffectValueSpec("--execute", false, wgetEffectExecute, nil),
	'h': wgetFlagSpec("--help", wgetEffectPreview, true),
	'i': wgetFinalEffectValueSpec("--input-file", wgetEffectInputFile, nil),
	'k': wgetFlagSpec("--convert-links", wgetEffectConvertLinks, true),
	'l': wgetValueSpec("--level", false, validWgetCount),
	'm': wgetFlagSpec("--mirror", wgetEffectMirror, true),
	'n': wgetEffectValueSpec("--no", false, wgetEffectNoBundle, validWgetNoBundle),
	'o': wgetFinalEffectValueSpec("--output-file", wgetEffectLogOutput, nil),
	'p': wgetFlagSpec("--page-requisites", wgetEffectPageRequisites, true),
	'q': wgetFlagSpec("--quiet", wgetEffectQuiet, true),
	'r': wgetFlagSpec("--recursive", wgetEffectRecursive, true),
	't': wgetValueSpec("--tries", false, validWgetCount),
	'v': wgetFlagSpec("--verbose", wgetEffectVerbose, true),
	'w': wgetValueSpec("--wait", false, validWgetTime),
	'x': wgetFlagSpec("--force-directories", wgetEffectNone, true),
	'4': wgetFlagSpec("--inet4-only", wgetEffectIPv4, true),
	'6': wgetFlagSpec("--inet6-only", wgetEffectIPv6, true),
}

var wgetLongOptionSpecs = map[string]wgetOptionSpec{
	"accept":               wgetValueSpec("--accept", true, nil),
	"adjust-extension":     wgetBooleanSpec("--adjust-extension", wgetEffectNone),
	"append-output":        wgetFinalEffectValueSpec("--append-output", wgetEffectLogOutput, nil),
	"background":           wgetBooleanSpec("--background", wgetEffectBackground),
	"backup-converted":     wgetBooleanSpec("--backup-converted", wgetEffectNone),
	"base":                 wgetValueSpec("--base", false, nil),
	"bind-address":         wgetValueSpec("--bind-address", false, nil),
	"body-data":            wgetEffectValueSpec("--body-data", true, wgetEffectBodyData, nil),
	"body-file":            wgetFinalEffectValueSpec("--body-file", wgetEffectBodyFile, nil),
	"config":               wgetEffectValueSpec("--config", false, wgetEffectConfigFile, nil),
	"content-disposition":  wgetBooleanSpec("--content-disposition", wgetEffectNone),
	"continue":             wgetBooleanSpec("--continue", wgetEffectNone),
	"convert-links":        wgetBooleanSpec("--convert-links", wgetEffectConvertLinks),
	"debug":                wgetBooleanSpec("--debug", wgetEffectNone),
	"directory-prefix":     wgetValueSpec("--directory-prefix", false, nil),
	"domains":              wgetValueSpec("--domains", true, nil),
	"execute":              wgetEffectValueSpec("--execute", false, wgetEffectExecute, nil),
	"exclude-directories":  wgetValueSpec("--exclude-directories", true, nil),
	"force-directories":    wgetBooleanSpec("--force-directories", wgetEffectNone),
	"force-html":           wgetBooleanSpec("--force-html", wgetEffectNone),
	"header":               wgetValueSpec("--header", true, validWgetHeader),
	"help":                 wgetFlagSpec("--help", wgetEffectPreview, true),
	"include-directories":  wgetValueSpec("--include-directories", true, nil),
	"inet4-only":           wgetBooleanSpec("--inet4-only", wgetEffectIPv4),
	"inet6-only":           wgetBooleanSpec("--inet6-only", wgetEffectIPv6),
	"input-file":           wgetFinalEffectValueSpec("--input-file", wgetEffectInputFile, nil),
	"level":                wgetValueSpec("--level", false, validWgetCount),
	"method":               wgetFinalEffectValueSpec("--method", wgetEffectMethod, validWgetMethod),
	"mirror":               wgetBooleanSpec("--mirror", wgetEffectMirror),
	"no-check-certificate": wgetFlagSpec("--no-check-certificate", wgetEffectNone, true),
	"no-clobber":           wgetBooleanSpec("--no-clobber", wgetEffectNoClobber),
	"no-config":            wgetBooleanSpec("--no-config", wgetEffectNone),
	"output-document":      wgetFinalEffectValueSpec("--output-document", wgetEffectOutputDocument, nil),
	"output-file":          wgetFinalEffectValueSpec("--output-file", wgetEffectLogOutput, nil),
	"page-requisites":      wgetBooleanSpec("--page-requisites", wgetEffectPageRequisites),
	"password":             wgetValueSpec("--password", true, nil),
	"post-data":            wgetEffectValueSpec("--post-data", true, wgetEffectPostData, nil),
	"post-file":            wgetFinalEffectValueSpec("--post-file", wgetEffectPostFile, nil),
	"proxy":                wgetBooleanSpec("--proxy", wgetEffectNone),
	"proxy-password":       wgetValueSpec("--proxy-password", true, nil),
	"proxy-user":           wgetValueSpec("--proxy-user", true, nil),
	"quiet":                wgetBooleanSpec("--quiet", wgetEffectQuiet),
	"quota":                wgetValueSpec("--quota", false, validWgetBytes),
	"recursive":            wgetBooleanSpec("--recursive", wgetEffectRecursive),
	"referer":              wgetValueSpec("--referer", true, nil),
	"reject":               wgetValueSpec("--reject", true, nil),
	"relative":             wgetBooleanSpec("--relative", wgetEffectNone),
	"server-response":      wgetBooleanSpec("--server-response", wgetEffectNone),
	"span-hosts":           wgetBooleanSpec("--span-hosts", wgetEffectNone),
	"spider":               wgetBooleanSpec("--spider", wgetEffectSpider),
	"timestamping":         wgetBooleanSpec("--timestamping", wgetEffectTimestamping),
	"timeout":              wgetValueSpec("--timeout", false, validWgetTime),
	"tries":                wgetValueSpec("--tries", false, validWgetCount),
	"user":                 wgetValueSpec("--user", true, nil),
	"user-agent":           wgetValueSpec("--user-agent", true, validWgetUserAgent),
	"verbose":              wgetBooleanSpec("--verbose", wgetEffectVerbose),
	"version":              wgetFlagSpec("--version", wgetEffectPreview, true),
	"wait":                 wgetValueSpec("--wait", false, validWgetTime),
}

func wgetFlagSpec(name string, effect wgetOptionEffect, value bool) wgetOptionSpec {
	return wgetOptionSpec{
		name:      name,
		arity:     wgetOptionFlag,
		effect:    effect,
		flagValue: value,
	}
}

func wgetBooleanSpec(name string, effect wgetOptionEffect) wgetOptionSpec {
	return wgetOptionSpec{
		name:      name,
		arity:     wgetOptionOptionalBoolean,
		effect:    effect,
		flagValue: true,
	}
}

func wgetValueSpec(
	name string,
	allowEmpty bool,
	validate func(string) bool,
) wgetOptionSpec {
	return wgetEffectValueSpec(name, allowEmpty, wgetEffectNone, validate)
}

func wgetEffectValueSpec(
	name string,
	allowEmpty bool,
	effect wgetOptionEffect,
	validate func(string) bool,
) wgetOptionSpec {
	return wgetOptionSpec{
		name:       name,
		arity:      wgetOptionRequiredValue,
		effect:     effect,
		allowEmpty: allowEmpty,
		validate:   validate,
	}
}

func wgetFinalEffectValueSpec(
	name string,
	effect wgetOptionEffect,
	validate func(string) bool,
) wgetOptionSpec {
	return wgetOptionSpec{
		name:          name,
		arity:         wgetOptionRequiredValue,
		effect:        effect,
		validate:      validate,
		validateFinal: true,
	}
}

// parseWgetArgv parses GNU Wget option ownership without consulting ambient
// configuration. It follows GNU short-bundle rules: a required-value option
// owns the rest of its token, or the entire next argv token when separated.
func parseWgetArgv(argv []string) wgetArgvParse {
	parsed := wgetArgvParse{
		Complete:         true,
		RequestBodyValid: true,
	}
	if len(argv) == 0 || argv[0] == "" {
		parsed.Complete = false
		return parsed
	}
	parsed.ConfigDisabled, parsed.ConfigIndirect = scanWgetConfigPrepass(argv)

	options := true
	stop := false
	for index := 1; index < len(argv) && !stop; index++ {
		argument := argv[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if !options || argument == "-" || !strings.HasPrefix(argument, "-") {
			parsed.Targets = append(parsed.Targets, argument)
			continue
		}

		if strings.HasPrefix(argument, "--") {
			stop = !parseWgetLongOption(&parsed, argv, &index)
			continue
		}
		stop = !parseWgetShortOptions(&parsed, argv, &index)
	}

	finalizeWgetArgv(&parsed)
	return parsed
}

// scanWgetConfigPrepass mirrors Wget's first getopt_long pass. Wget resolves
// an explicit config file, or suppresses ambient configuration, before its
// normal option pass can execute help or version callbacks.
func scanWgetConfigPrepass(argv []string) (disabled bool, indirect bool) {
	options := true
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if options && argument == "--" {
			options = false
			continue
		}
		if !options || argument == "-" || !strings.HasPrefix(argument, "-") {
			continue
		}

		if strings.HasPrefix(argument, "--") {
			name, _, joined := strings.Cut(argument[2:], "=")
			switch name {
			case "no-config":
				// The pre-pass checks the underlying option identity before
				// the ordinary pass validates an optional boolean value.
				return true, false
			case "no-no-config":
				if !joined {
					return true, false
				}
			case "config":
				if joined || index+1 < len(argv) {
					return false, true
				}
			}

			spec, known := lookupWgetLongOption(name)
			if known && spec.arity == wgetOptionRequiredValue && !joined && index+1 < len(argv) {
				index++
			}
			continue
		}

		for offset := 1; offset < len(argument); offset++ {
			spec, known := wgetShortOptionSpecs[argument[offset]]
			if !known {
				continue
			}
			if spec.arity != wgetOptionRequiredValue {
				continue
			}
			if offset+1 == len(argument) && index+1 < len(argv) {
				index++
			}
			break
		}
	}
	return false, false
}

func parseWgetLongOption(
	parsed *wgetArgvParse,
	argv []string,
	index *int,
) bool {
	optionIndex := *index
	argument := argv[*index]
	name, joinedValue, joined := strings.Cut(argument[2:], "=")
	if name == "" {
		parsed.Complete = false
		return false
	}
	spec, ok := lookupWgetLongOption(name)
	if !ok {
		parsed.Complete = false
		return false
	}

	switch spec.arity {
	case wgetOptionFlag:
		if joined {
			parsed.Complete = false
			return false
		}
		applyWgetFlag(parsed, spec)
		return !parsed.Preview
	case wgetOptionOptionalBoolean:
		value := spec.flagValue
		if joined {
			var valid bool
			value, valid = parseWgetBoolean(joinedValue)
			parsed.Values = append(parsed.Values, wgetArgvValue{
				Option:      spec.name,
				Value:       joinedValue,
				OptionIndex: optionIndex,
				ValueIndex:  optionIndex,
				Joined:      true,
			})
			if !valid {
				parsed.Complete = false
				return false
			}
		}
		spec.flagValue = value
		applyWgetFlag(parsed, spec)
		return true
	case wgetOptionRequiredValue:
		value := joinedValue
		valueIndex := *index
		if !joined {
			if *index+1 >= len(argv) {
				parsed.Complete = false
				return false
			}
			*index++
			valueIndex = *index
			value = argv[*index]
		}
		parsed.Values = append(parsed.Values, wgetArgvValue{
			Option:      spec.name,
			Value:       value,
			OptionIndex: optionIndex,
			ValueIndex:  valueIndex,
			Joined:      joined,
		})
		if !spec.validateFinal && !validWgetOptionValue(spec, value) {
			parsed.Complete = false
			applyWgetValue(parsed, spec, value)
			return false
		}
		applyWgetValue(parsed, spec, value)
		return true
	default:
		parsed.Complete = false
		return false
	}
}

func lookupWgetLongOption(name string) (wgetOptionSpec, bool) {
	if spec, ok := wgetLongOptionSpecs[name]; ok {
		return spec, true
	}
	base, negated := strings.CutPrefix(name, "no-")
	if !negated {
		return wgetOptionSpec{}, false
	}
	spec, ok := wgetLongOptionSpecs[base]
	if !ok || spec.arity != wgetOptionOptionalBoolean {
		return wgetOptionSpec{}, false
	}
	// getopt_long synthesizes no-OPTION aliases for Wget boolean
	// options. Unlike the positive spelling, a negated alias takes no
	// optional =VALUE operand.
	spec.arity = wgetOptionFlag
	spec.flagValue = false
	return spec, true
}

func parseWgetShortOptions(
	parsed *wgetArgvParse,
	argv []string,
	index *int,
) bool {
	optionIndex := *index
	argument := argv[*index]
	for offset := 1; offset < len(argument); offset++ {
		spec, ok := wgetShortOptionSpecs[argument[offset]]
		if !ok {
			parsed.Complete = false
			return false
		}
		if spec.arity == wgetOptionFlag {
			applyWgetFlag(parsed, spec)
			if parsed.Preview {
				return false
			}
			continue
		}
		if spec.arity != wgetOptionRequiredValue {
			parsed.Complete = false
			return false
		}

		joined := offset+1 < len(argument)
		value := ""
		valueIndex := *index
		if joined {
			value = argument[offset+1:]
		} else {
			if *index+1 >= len(argv) {
				parsed.Complete = false
				return false
			}
			*index++
			valueIndex = *index
			value = argv[*index]
		}
		parsed.Values = append(parsed.Values, wgetArgvValue{
			Option:      spec.name,
			Value:       value,
			OptionIndex: optionIndex,
			ValueIndex:  valueIndex,
			Joined:      joined,
		})
		if !spec.validateFinal && !validWgetOptionValue(spec, value) {
			parsed.Complete = false
			applyWgetValue(parsed, spec, value)
			return false
		}
		applyWgetValue(parsed, spec, value)
		return true
	}
	return true
}

func validWgetOptionValue(spec wgetOptionSpec, value string) bool {
	if value == "" && !spec.allowEmpty {
		return false
	}
	return spec.validate == nil || spec.validate(value)
}

func applyWgetFlag(parsed *wgetArgvParse, spec wgetOptionSpec) {
	switch spec.effect {
	case wgetEffectPreview:
		parsed.Preview = spec.flagValue
	case wgetEffectBackground:
		parsed.Background = spec.flagValue
	case wgetEffectSpider:
		parsed.Spider = spec.flagValue
	case wgetEffectQuiet:
		parsed.quietSet = true
		parsed.quiet = spec.flagValue
	case wgetEffectVerbose:
		parsed.verboseSet = true
		parsed.verbose = spec.flagValue
	case wgetEffectIPv4:
		parsed.ipv4 = spec.flagValue
	case wgetEffectIPv6:
		parsed.ipv6 = spec.flagValue
	case wgetEffectTimestamping:
		parsed.timestamping = spec.flagValue
	case wgetEffectNoClobber:
		parsed.noClobber = spec.flagValue
	case wgetEffectConvertLinks:
		parsed.convertLinks = spec.flagValue
	case wgetEffectRecursive:
		parsed.recursive = spec.flagValue
	case wgetEffectPageRequisites:
		parsed.pageRequisites = spec.flagValue
	case wgetEffectMirror:
		if spec.flagValue {
			parsed.recursive = true
			parsed.timestamping = true
		}
	}
}

func applyWgetValue(parsed *wgetArgvParse, spec wgetOptionSpec, value string) {
	switch spec.effect {
	case wgetEffectConfigFile:
		parsed.ConfigIndirect = true
	case wgetEffectExecute:
		parsed.ConfigIndirect = true
	case wgetEffectInputFile:
		parsed.InputFileSet = true
		parsed.InputFile = value
	case wgetEffectOutputDocument:
		parsed.OutputSet = true
		parsed.Output = value
	case wgetEffectLogOutput:
		parsed.LogOutputSet = true
		parsed.LogOutput = value
		if spec.name == "--append-output" {
			parsed.AppendLog = true
		}
	case wgetEffectMethod:
		parsed.MethodSet = true
		parsed.Method = strings.ToUpper(value)
	case wgetEffectPostData:
		parsed.PostDataSet = true
		parsed.PostData = value
	case wgetEffectPostFile:
		parsed.PostFileSet = true
		parsed.PostFile = value
	case wgetEffectBodyData:
		parsed.BodyDataSet = true
		parsed.BodyData = value
	case wgetEffectBodyFile:
		parsed.BodyFileSet = true
		parsed.BodyFile = value
	case wgetEffectNoBundle:
		for _, option := range value {
			switch option {
			case 'v':
				parsed.verboseSet = true
				parsed.verbose = false
			case 'c':
				parsed.noClobber = true
			}
		}
	}
}

func finalizeWgetArgv(parsed *wgetArgvParse) {
	if parsed.Preview {
		return
	}
	if len(parsed.Targets) == 0 && !parsed.InputFileSet {
		parsed.Complete = false
	}
	for _, target := range parsed.Targets {
		if target == "" {
			parsed.Complete = false
		}
	}
	if parsed.quietSet && parsed.verboseSet && parsed.quiet && parsed.verbose {
		parsed.Complete = false
	}
	if parsed.ipv4 && parsed.ipv6 {
		parsed.Complete = false
	}
	if parsed.noClobber && parsed.convertLinks {
		// Wget resolves this combination by disabling no-clobber before
		// checking its timestamping incompatibility.
		parsed.noClobber = false
	}
	if parsed.timestamping && parsed.noClobber {
		parsed.Complete = false
	}
	if parsed.OutputSet && parsed.Output == "" {
		parsed.Complete = false
	}
	if parsed.LogOutputSet && parsed.LogOutput == "" {
		parsed.Complete = false
	}
	if parsed.InputFileSet && parsed.InputFile == "" {
		parsed.Complete = false
	}
	if parsed.MethodSet && !validWgetMethod(parsed.Method) {
		parsed.Complete = false
	}
	if parsed.OutputSet && parsed.convertLinks &&
		(len(parsed.Targets) > 1 || parsed.pageRequisites || parsed.recursive) {
		parsed.Complete = false
	}
	if parsed.OutputSet && parsed.Output == "-" &&
		(parsed.convertLinks || parsed.recursive) {
		parsed.Complete = false
	}

	parsed.RequestBodyValid = true
	switch {
	case parsed.PostDataSet && parsed.PostFileSet:
		parsed.RequestBodyValid = false
		parsed.RequestBodyIssue = wgetRequestBodyIssuePostConflict
	case (parsed.PostDataSet || parsed.PostFileSet) && parsed.MethodSet:
		parsed.RequestBodyValid = false
		parsed.RequestBodyIssue = wgetRequestBodyIssuePostWithMethod
	case (parsed.BodyDataSet || parsed.BodyFileSet) && !parsed.MethodSet:
		parsed.RequestBodyValid = false
		parsed.RequestBodyIssue = wgetRequestBodyIssueMissingMethod
	case parsed.BodyDataSet && parsed.BodyFileSet:
		parsed.RequestBodyValid = false
		parsed.RequestBodyIssue = wgetRequestBodyIssueBodyConflict
	case parsed.PostFileSet && parsed.PostFile == "" ||
		parsed.BodyFileSet && parsed.BodyFile == "":
		parsed.RequestBodyValid = false
		parsed.RequestBodyIssue = wgetRequestBodyIssueInvalidFileValue
	}
	if !parsed.RequestBodyValid {
		parsed.Complete = false
	}
	if parsed.RequestBodyValid && (parsed.PostDataSet || parsed.PostFileSet) {
		// Wget normalizes the legacy post options to a final POST method
		// after validating that no explicit custom method was supplied.
		parsed.MethodSet = true
		parsed.Method = "POST"
	}
	if parsed.MethodSet && strings.EqualFold(parsed.Method, "HEAD") {
		parsed.Spider = true
	}
}

func parseWgetBoolean(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "on", "yes", "1":
		return true, true
	case "off", "no", "0":
		return false, true
	default:
		return false, false
	}
}

func validWgetBoolean(value string) bool {
	_, valid := parseWgetBoolean(value)
	return valid
}

func validWgetNoBundle(value string) bool {
	if value == "" {
		return false
	}
	for _, option := range value {
		if !strings.ContainsRune("vHdcp", option) {
			return false
		}
	}
	return true
}

func validWgetCount(value string) bool {
	// Wget's current strtol call accepts trailing junk because it does not
	// inspect an end pointer. Keep the proof grammar to documented decimal
	// counts (and inf) rather than treating that implementation quirk as
	// authoritative input.
	value = trimWgetASCIIWhitespace(value)
	if strings.EqualFold(value, "inf") {
		return true
	}
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	}
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(value, 10, 31)
	return err == nil && number <= math.MaxInt32
}

func validWgetTime(value string) bool {
	value = trimWgetASCIIWhitespace(value)
	if value == "" {
		return false
	}
	last := value[len(value)-1]
	if strings.ContainsRune("sSmMhHdDwW", rune(last)) {
		value = trimWgetASCIIWhitespace(value[:len(value)-1])
	}
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	} else if strings.HasPrefix(value, "-") {
		return false
	}
	if value == "" {
		return false
	}
	digits := 0
	dots := 0
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
			digits++
		case char == '.':
			dots++
		default:
			return false
		}
	}
	return digits > 0 && dots <= 1
}

func validWgetBytes(value string) bool {
	if value == "inf" {
		return true
	}
	value = trimWgetASCIIWhitespace(value)
	if value == "" {
		return false
	}
	multiplier := 1.0
	switch value[len(value)-1] {
	case 'k', 'K':
		multiplier = 1 << 10
		value = trimWgetASCIIWhitespace(value[:len(value)-1])
	case 'm', 'M':
		multiplier = 1 << 20
		value = trimWgetASCIIWhitespace(value[:len(value)-1])
	case 'g', 'G':
		multiplier = 1 << 30
		value = trimWgetASCIIWhitespace(value[:len(value)-1])
	case 't', 'T':
		multiplier = 1 << 40
		value = trimWgetASCIIWhitespace(value[:len(value)-1])
	}
	if strings.HasPrefix(value, "+") {
		value = value[1:]
	} else if strings.HasPrefix(value, "-") {
		return false
	}
	if value == "" {
		return false
	}
	digits := 0
	dots := 0
	for _, char := range value {
		switch {
		case char >= '0' && char <= '9':
			digits++
		case char == '.':
			dots++
		default:
			return false
		}
	}
	if digits == 0 || dots > 1 {
		return false
	}
	number, err := strconv.ParseFloat(value, 64)
	return err == nil && !math.IsInf(number, 0) &&
		number <= float64(math.MaxInt64)/multiplier
}

func validWgetHeader(value string) bool {
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, "\r\n") {
		return false
	}
	name, _, found := strings.Cut(value, ":")
	if !found || name == "" {
		return false
	}
	for index := range len(name) {
		if isWgetASCIIWhitespace(name[index]) {
			return false
		}
	}
	return true
}

func validWgetUserAgent(value string) bool {
	return !strings.ContainsRune(value, '\n')
}

func validWgetMethod(value string) bool {
	if value == "" {
		return false
	}
	for _, char := range value {
		if char <= 0x20 || char >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", char) {
			return false
		}
	}
	return true
}

func trimWgetASCIIWhitespace(value string) string {
	return strings.TrimFunc(value, func(char rune) bool {
		return char <= 0x7f && isWgetASCIIWhitespace(byte(char))
	})
}

func isWgetASCIIWhitespace(char byte) bool {
	switch char {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}
