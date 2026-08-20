// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// curlOptionArity describes lexical operand ownership. In particular, a
// required operand owns the next argv element even when it is empty or starts
// with '-'. Curl stops expanding a short-option bundle once such an option is
// reached; the remainder of that token is the joined operand.
type curlOptionArity uint8

const (
	curlOptionNoValue curlOptionArity = iota
	curlOptionRequiredValue
	curlOptionOptionalValue
)

// curlOptionRole captures only behavior needed to project transfer ownership.
// Callers can use Canonical on curlOptionToken for more detailed classification
// without re-parsing argv.
type curlOptionRole uint8

const (
	curlOptionNeutral curlOptionRole = iota
	curlOptionConfig
	curlOptionTarget
	curlOptionOutput
	curlOptionRemoteName
	curlOptionRemoteNameAll
	curlOptionNoRemoteName
	curlOptionNoRemoteNameAll
	curlOptionMethod
	curlOptionUpload
	curlOptionHead
	curlOptionNoHead
	curlOptionPreview
	curlOptionNetworkOverride
)

type curlOptionSpec struct {
	canonical string
	arity     curlOptionArity
	role      curlOptionRole
}

func curlFlag(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{canonical: canonical, role: role}
}

func curlValue(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{
		canonical: canonical,
		arity:     curlOptionRequiredValue,
		role:      role,
	}
}

func curlOptionalValue(canonical string, role curlOptionRole) curlOptionSpec {
	return curlOptionSpec{
		canonical: canonical,
		arity:     curlOptionOptionalValue,
		role:      role,
	}
}

// curlLongOptionSpecs is intentionally metadata, rather than parser control
// flow. Short and long aliases resolve to the same canonical name and role.
// Adding a known option therefore updates lexical ownership for control-mode,
// classification, and exact-output consumers together when they integrate
// with parseCurlArgv.
var curlLongOptionSpecs = map[string]curlOptionSpec{
	"--append":        curlFlag("--append", curlOptionNeutral),
	"--no-append":     curlFlag("--append", curlOptionNeutral),
	"--buffer":        curlFlag("--no-buffer", curlOptionNeutral),
	"--compressed":    curlFlag("--compressed", curlOptionNeutral),
	"--no-compressed": curlFlag("--compressed", curlOptionNeutral),
	"--disable":       curlFlag("--disable", curlOptionNeutral),
	"--disable-eprt":  curlFlag("--disable-eprt", curlOptionNeutral),
	"--no-disable-eprt": curlFlag(
		"--disable-eprt",
		curlOptionNeutral,
	),
	"--eprt":         curlFlag("--disable-eprt", curlOptionNeutral),
	"--no-eprt":      curlFlag("--disable-eprt", curlOptionNeutral),
	"--disable-epsv": curlFlag("--disable-epsv", curlOptionNeutral),
	"--no-disable-epsv": curlFlag(
		"--disable-epsv",
		curlOptionNeutral,
	),
	"--epsv":           curlFlag("--disable-epsv", curlOptionNeutral),
	"--no-epsv":        curlFlag("--disable-epsv", curlOptionNeutral),
	"--fail":           curlFlag("--fail", curlOptionNeutral),
	"--no-fail":        curlFlag("--fail", curlOptionNeutral),
	"--fail-with-body": curlFlag("--fail-with-body", curlOptionNeutral),
	"--no-fail-with-body": curlFlag(
		"--fail-with-body",
		curlOptionNeutral,
	),
	"--get":         curlFlag("--get", curlOptionNeutral),
	"--no-get":      curlFlag("--get", curlOptionNeutral),
	"--globoff":     curlFlag("--globoff", curlOptionNeutral),
	"--no-globoff":  curlFlag("--globoff", curlOptionNeutral),
	"--head":        curlFlag("--head", curlOptionHead),
	"--http1.0":     curlFlag("--http1.0", curlOptionNeutral),
	"--help":        curlOptionalValue("--help", curlOptionPreview),
	"--include":     curlFlag("--include", curlOptionNeutral),
	"--no-include":  curlFlag("--include", curlOptionNeutral),
	"--insecure":    curlFlag("--insecure", curlOptionNeutral),
	"--no-insecure": curlFlag("--insecure", curlOptionNeutral),
	"--ipv4":        curlFlag("--ipv4", curlOptionNeutral),
	"--ipv6":        curlFlag("--ipv6", curlOptionNeutral),
	"--crlf":        curlFlag("--crlf", curlOptionNeutral),
	"--no-crlf":     curlFlag("--crlf", curlOptionNeutral),
	"--ftp-create-dirs": curlFlag(
		"--ftp-create-dirs",
		curlOptionNeutral,
	),
	"--no-ftp-create-dirs": curlFlag(
		"--ftp-create-dirs",
		curlOptionNeutral,
	),
	"--ftp-pasv":         curlFlag("--ftp-pasv", curlOptionNeutral),
	"--no-ftp-pasv":      curlFlag("--ftp-pasv", curlOptionNeutral),
	"--ftp-pret":         curlFlag("--ftp-pret", curlOptionNeutral),
	"--no-ftp-pret":      curlFlag("--ftp-pret", curlOptionNeutral),
	"--ftp-skip-pasv-ip": curlFlag("--ftp-skip-pasv-ip", curlOptionNeutral),
	"--no-ftp-skip-pasv-ip": curlFlag(
		"--ftp-skip-pasv-ip",
		curlOptionNeutral,
	),
	"--ftp-ssl-ccc":    curlFlag("--ftp-ssl-ccc", curlOptionNeutral),
	"--no-ftp-ssl-ccc": curlFlag("--ftp-ssl-ccc", curlOptionNeutral),
	"--ignore-content-length": curlFlag(
		"--ignore-content-length",
		curlOptionNeutral,
	),
	"--no-ignore-content-length": curlFlag(
		"--ignore-content-length",
		curlOptionNeutral,
	),
	"--ssl":                curlFlag("--ssl", curlOptionNeutral),
	"--no-ssl":             curlFlag("--ssl", curlOptionNeutral),
	"--ftp-ssl":            curlFlag("--ssl", curlOptionNeutral),
	"--no-ftp-ssl":         curlFlag("--ssl", curlOptionNeutral),
	"--ssl-reqd":           curlFlag("--ssl-reqd", curlOptionNeutral),
	"--no-ssl-reqd":        curlFlag("--ssl-reqd", curlOptionNeutral),
	"--ftp-ssl-reqd":       curlFlag("--ssl-reqd", curlOptionNeutral),
	"--no-ftp-ssl-reqd":    curlFlag("--ssl-reqd", curlOptionNeutral),
	"--ftp-ssl-control":    curlFlag("--ftp-ssl-control", curlOptionNeutral),
	"--no-ftp-ssl-control": curlFlag("--ftp-ssl-control", curlOptionNeutral),
	"--junk-session-cookies": curlFlag(
		"--junk-session-cookies",
		curlOptionNeutral,
	),
	"--no-junk-session-cookies": curlFlag(
		"--junk-session-cookies",
		curlOptionNeutral,
	),
	"--list-only":          curlFlag("--list-only", curlOptionNeutral),
	"--no-list-only":       curlFlag("--list-only", curlOptionNeutral),
	"--location":           curlFlag("--location", curlOptionNeutral),
	"--no-location":        curlFlag("--location", curlOptionNeutral),
	"--manual":             curlFlag("--manual", curlOptionPreview),
	"--no-buffer":          curlFlag("--no-buffer", curlOptionNeutral),
	"--no-head":            curlFlag("--no-head", curlOptionNoHead),
	"--netrc":              curlFlag("--netrc", curlOptionNeutral),
	"--no-netrc":           curlFlag("--netrc", curlOptionNeutral),
	"--netrc-optional":     curlFlag("--netrc-optional", curlOptionNeutral),
	"--no-netrc-optional":  curlFlag("--netrc-optional", curlOptionNeutral),
	"--no-progress-meter":  curlFlag("--no-progress-meter", curlOptionNeutral),
	"--no-remote-name":     curlFlag("--no-remote-name", curlOptionNoRemoteName),
	"--no-remote-name-all": curlFlag("--no-remote-name-all", curlOptionNoRemoteNameAll),
	"--parallel":           curlFlag("--parallel", curlOptionNeutral),
	"--no-parallel":        curlFlag("--parallel", curlOptionNeutral),
	"--progress-bar":       curlFlag("--progress-bar", curlOptionNeutral),
	"--no-progress-bar":    curlFlag("--progress-bar", curlOptionNeutral),
	"--progress-meter":     curlFlag("--no-progress-meter", curlOptionNeutral),
	"--proxytunnel":        curlFlag("--proxytunnel", curlOptionNeutral),
	"--no-proxytunnel":     curlFlag("--proxytunnel", curlOptionNeutral),
	"--remote-name":        curlFlag("--remote-name", curlOptionRemoteName),
	"--remote-name-all":    curlFlag("--remote-name-all", curlOptionRemoteNameAll),
	"--remote-time":        curlFlag("--remote-time", curlOptionNeutral),
	"--no-remote-time":     curlFlag("--remote-time", curlOptionNeutral),
	"--show-error":         curlFlag("--show-error", curlOptionNeutral),
	"--no-show-error":      curlFlag("--show-error", curlOptionNeutral),
	"--silent":             curlFlag("--silent", curlOptionNeutral),
	"--no-silent":          curlFlag("--silent", curlOptionNeutral),
	"--sslv2":              curlFlag("--sslv2", curlOptionNeutral),
	"--sslv3":              curlFlag("--sslv3", curlOptionNeutral),
	"--tlsv1":              curlFlag("--tlsv1", curlOptionNeutral),
	"--use-ascii":          curlFlag("--use-ascii", curlOptionNeutral),
	"--no-use-ascii":       curlFlag("--use-ascii", curlOptionNeutral),
	"--verbose":            curlFlag("--verbose", curlOptionNeutral),
	"--no-verbose":         curlFlag("--verbose", curlOptionNeutral),
	"--version":            curlFlag("--version", curlOptionPreview),

	"--cacert":          curlValue("--cacert", curlOptionNeutral),
	"--cert":            curlValue("--cert", curlOptionNeutral),
	"--config":          curlValue("--config", curlOptionConfig),
	"--connect-timeout": curlValue("--connect-timeout", curlOptionNeutral),
	"--connect-to":      curlValue("--connect-to", curlOptionNetworkOverride),
	"--continue-at":     curlValue("--continue-at", curlOptionNeutral),
	"--cookie":          curlValue("--cookie", curlOptionNeutral),
	"--cookie-jar":      curlValue("--cookie-jar", curlOptionNeutral),
	"--data":            curlValue("--data", curlOptionNeutral),
	"--data-ascii":      curlValue("--data-ascii", curlOptionNeutral),
	"--data-binary":     curlValue("--data-binary", curlOptionNeutral),
	"--data-raw":        curlValue("--data-raw", curlOptionNeutral),
	"--data-urlencode":  curlValue("--data-urlencode", curlOptionNeutral),
	"--dns-servers":     curlValue("--dns-servers", curlOptionNetworkOverride),
	"--doh-url":         curlValue("--doh-url", curlOptionNetworkOverride),
	"--dump-header":     curlValue("--dump-header", curlOptionNeutral),
	"--form":            curlValue("--form", curlOptionNeutral),
	"--form-string":     curlValue("--form-string", curlOptionNeutral),
	"--ftp-account":     curlValue("--ftp-account", curlOptionNeutral),
	"--ftp-alternative-to-user": curlValue(
		"--ftp-alternative-to-user",
		curlOptionNeutral,
	),
	"--ftp-port":   curlValue("--ftp-port", curlOptionNeutral),
	"--ftp-method": curlValue("--ftp-method", curlOptionNeutral),
	"--ftp-ssl-ccc-mode": curlValue(
		"--ftp-ssl-ccc-mode",
		curlOptionNeutral,
	),
	"--header":    curlValue("--header", curlOptionNeutral),
	"--interface": curlValue("--interface", curlOptionNetworkOverride),
	"--json":      curlValue("--json", curlOptionNeutral),
	"--key":       curlValue("--key", curlOptionNeutral),
	"--mail-auth": curlValue("--mail-auth", curlOptionNeutral),
	"--mail-from": curlValue("--mail-from", curlOptionNeutral),
	"--mail-rcpt": curlValue("--mail-rcpt", curlOptionNeutral),
	"--mail-rcpt-allowfails": curlFlag(
		"--mail-rcpt-allowfails",
		curlOptionNeutral,
	),
	"--no-mail-rcpt-allowfails": curlFlag(
		"--mail-rcpt-allowfails",
		curlOptionNeutral,
	),
	"--max-time":        curlValue("--max-time", curlOptionNeutral),
	"--netrc-file":      curlValue("--netrc-file", curlOptionNeutral),
	"--noproxy":         curlValue("--noproxy", curlOptionNetworkOverride),
	"--oauth2-bearer":   curlValue("--oauth2-bearer", curlOptionNeutral),
	"--output":          curlValue("--output", curlOptionOutput),
	"--output-dir":      curlValue("--output-dir", curlOptionNeutral),
	"--preproxy":        curlValue("--preproxy", curlOptionNetworkOverride),
	"--proxy":           curlValue("--proxy", curlOptionNetworkOverride),
	"--proxy-header":    curlValue("--proxy-header", curlOptionNeutral),
	"--proxy-user":      curlValue("--proxy-user", curlOptionNeutral),
	"--proxy1.0":        curlValue("--proxy1.0", curlOptionNetworkOverride),
	"--quote":           curlValue("--quote", curlOptionNeutral),
	"--range":           curlValue("--range", curlOptionNeutral),
	"--referer":         curlValue("--referer", curlOptionNeutral),
	"--request":         curlValue("--request", curlOptionMethod),
	"--request-target":  curlValue("--request-target", curlOptionNeutral),
	"--resolve":         curlValue("--resolve", curlOptionNetworkOverride),
	"--retry":           curlValue("--retry", curlOptionNeutral),
	"--retry-delay":     curlValue("--retry-delay", curlOptionNeutral),
	"--retry-max-time":  curlValue("--retry-max-time", curlOptionNeutral),
	"--socks4":          curlValue("--socks4", curlOptionNetworkOverride),
	"--socks4a":         curlValue("--socks4a", curlOptionNetworkOverride),
	"--socks5":          curlValue("--socks5", curlOptionNetworkOverride),
	"--socks5-hostname": curlValue("--socks5-hostname", curlOptionNetworkOverride),
	"--speed-limit":     curlValue("--speed-limit", curlOptionNeutral),
	"--speed-time":      curlValue("--speed-time", curlOptionNeutral),
	"--telnet-option":   curlValue("--telnet-option", curlOptionNeutral),
	"--time-cond":       curlValue("--time-cond", curlOptionNeutral),
	"--unix-socket":     curlValue("--unix-socket", curlOptionNetworkOverride),
	"--upload-file":     curlValue("--upload-file", curlOptionUpload),
	"--url":             curlValue("--url", curlOptionTarget),
	"--url-query":       curlValue("--url-query", curlOptionNeutral),
	"--user":            curlValue("--user", curlOptionNeutral),
	"--user-agent":      curlValue("--user-agent", curlOptionNeutral),
	"--write-out":       curlValue("--write-out", curlOptionNeutral),
}

var curlShortOptionSpecs = map[byte]curlOptionSpec{
	'#': curlFlag("--progress-bar", curlOptionNeutral),
	'0': curlFlag("--http1.0", curlOptionNeutral),
	'1': curlFlag("--tlsv1", curlOptionNeutral),
	'2': curlFlag("--sslv2", curlOptionNeutral),
	'3': curlFlag("--sslv3", curlOptionNeutral),
	'4': curlFlag("--ipv4", curlOptionNeutral),
	'6': curlFlag("--ipv6", curlOptionNeutral),
	'a': curlFlag("--append", curlOptionNeutral),
	'B': curlFlag("--use-ascii", curlOptionNeutral),
	'f': curlFlag("--fail", curlOptionNeutral),
	'G': curlFlag("--get", curlOptionNeutral),
	'g': curlFlag("--globoff", curlOptionNeutral),
	'I': curlFlag("--head", curlOptionHead),
	'i': curlFlag("--include", curlOptionNeutral),
	'j': curlFlag("--junk-session-cookies", curlOptionNeutral),
	'k': curlFlag("--insecure", curlOptionNeutral),
	'L': curlFlag("--location", curlOptionNeutral),
	'l': curlFlag("--list-only", curlOptionNeutral),
	'M': curlFlag("--manual", curlOptionPreview),
	'N': curlFlag("--no-buffer", curlOptionNeutral),
	'n': curlFlag("--netrc", curlOptionNeutral),
	'O': curlFlag("--remote-name", curlOptionRemoteName),
	'p': curlFlag("--proxytunnel", curlOptionNeutral),
	'q': curlFlag("--disable", curlOptionNeutral),
	'R': curlFlag("--remote-time", curlOptionNeutral),
	'S': curlFlag("--show-error", curlOptionNeutral),
	's': curlFlag("--silent", curlOptionNeutral),
	'V': curlFlag("--version", curlOptionPreview),
	'v': curlFlag("--verbose", curlOptionNeutral),
	'Z': curlFlag("--parallel", curlOptionNeutral),

	'A': curlValue("--user-agent", curlOptionNeutral),
	'b': curlValue("--cookie", curlOptionNeutral),
	'c': curlValue("--cookie-jar", curlOptionNeutral),
	'C': curlValue("--continue-at", curlOptionNeutral),
	'd': curlValue("--data", curlOptionNeutral),
	'D': curlValue("--dump-header", curlOptionNeutral),
	'e': curlValue("--referer", curlOptionNeutral),
	'E': curlValue("--cert", curlOptionNeutral),
	'F': curlValue("--form", curlOptionNeutral),
	'H': curlValue("--header", curlOptionNeutral),
	'h': curlOptionalValue("--help", curlOptionPreview),
	'K': curlValue("--config", curlOptionConfig),
	'm': curlValue("--max-time", curlOptionNeutral),
	'o': curlValue("--output", curlOptionOutput),
	'P': curlValue("--ftp-port", curlOptionNeutral),
	'Q': curlValue("--quote", curlOptionNeutral),
	'r': curlValue("--range", curlOptionNeutral),
	't': curlValue("--telnet-option", curlOptionNeutral),
	'T': curlValue("--upload-file", curlOptionUpload),
	'u': curlValue("--user", curlOptionNeutral),
	'U': curlValue("--proxy-user", curlOptionNeutral),
	'w': curlValue("--write-out", curlOptionNeutral),
	'x': curlValue("--proxy", curlOptionNetworkOverride),
	'X': curlValue("--request", curlOptionMethod),
	'y': curlValue("--speed-time", curlOptionNeutral),
	'Y': curlValue("--speed-limit", curlOptionNeutral),
	'z': curlValue("--time-cond", curlOptionNeutral),
}

// curlOptionToken retains both the source spelling and canonical ownership.
// ValuePresent distinguishes a present empty value from a missing operand.
type curlOptionToken struct {
	ArgvIndex      int
	ValueArgvIndex int
	ShortOffset    int
	Group          int
	Raw            string
	Name           string
	Canonical      string
	Known          bool
	TakesValue     bool
	ValuePresent   bool
	ValueJoined    bool
	Value          string
	Role           curlOptionRole
}

type curlArgvUnresolved struct {
	ArgvIndex int
	Raw       string
	Reason    string
}

type curlOutputKind uint8

const (
	curlOutputUnknown curlOutputKind = iota
	curlOutputStdout
	curlOutputFile
	curlOutputRemoteName
)

type curlTransferTarget struct {
	ArgvIndex          int
	Group              int
	Value              string
	ViaURLOption       bool
	Output             curlOutputKind
	OutputValue        string
	Method             string
	Head               bool
	Preview            bool
	ResponseBodyStdout bool
	UploadSet          bool
	UploadValue        string
}

type curlResponseStdoutState uint8

const (
	curlResponseStdoutUnknown curlResponseStdoutState = iota
	curlResponseStdoutNone
	curlResponseStdoutPresent
)

// curlArgvParse is a lossless-enough curl command-line projection for later
// classifiers. Complete means output/method/target ownership is known. A
// syntactically complete invocation with no targets remains Complete and has a
// known no-stdout result. ConfigOpaque and Unresolved explain incomplete cases.
type curlArgvParse struct {
	Complete           bool
	ConfigOpaque       bool
	Preview            bool
	EmptyTransferGroup bool
	Options            []curlOptionToken
	Targets            []curlTransferTarget
	Unresolved         []curlArgvUnresolved
}

func (parsed curlArgvParse) responseStdoutState() curlResponseStdoutState {
	if !parsed.Complete || parsed.ConfigOpaque {
		return curlResponseStdoutUnknown
	}
	for _, target := range parsed.Targets {
		if target.ResponseBodyStdout {
			return curlResponseStdoutPresent
		}
	}
	return curlResponseStdoutNone
}

func (parsed curlArgvParse) provesResponseStdout() bool {
	if parsed.responseStdoutState() != curlResponseStdoutPresent ||
		!parsed.hasValidOptionValues() {
		return false
	}
	for _, target := range parsed.Targets {
		if !target.ResponseBodyStdout {
			continue
		}
		if _, ok := webTargetFact(0, target.Value, NetworkDownload); ok {
			return true
		}
	}
	return false
}

func (parsed curlArgvParse) hasValidOptionValues() bool {
	for _, option := range parsed.Options {
		if !option.TakesValue || !option.ValuePresent {
			continue
		}
		if option.Value == "" && !curlOptionAllowsEmptyValue(option.Canonical) {
			return false
		}
		switch option.Canonical {
		case "--connect-timeout", "--max-time":
			if !validCurlDecimal(option.Value) {
				return false
			}
		case "--retry", "--retry-delay", "--retry-max-time",
			"--speed-limit", "--speed-time":
			if !validCurlUnsignedInteger(option.Value) {
				return false
			}
		}
	}
	return true
}

func curlOptionAllowsEmptyValue(option string) bool {
	switch option {
	case "--cert", "--connect-to", "--cookie", "--data",
		"--data-ascii", "--data-binary", "--data-raw",
		"--data-urlencode", "--doh-url", "--header", "--json",
		"--ftp-method", "--ftp-ssl-ccc-mode", "--mail-rcpt", "--noproxy",
		"--proxy", "--proxy-header", "--proxy-user", "--upload-file",
		"--quote", "--referer",
		"--telnet-option", "--time-cond", "--user",
		"--url-query", "--user-agent", "--write-out":
		return true
	default:
		return false
	}
}

func validCurlDecimal(value string) bool {
	if value == "" {
		return false
	}
	digits := 0
	dots := 0
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
			digits++
		case character == '.':
			dots++
		default:
			return false
		}
	}
	return digits > 0 && dots <= 1
}

func validCurlUnsignedInteger(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

type curlTargetOperand struct {
	argvIndex    int
	value        string
	viaURLOption bool
	remoteName   bool
}

type curlOutputSlot struct {
	kind  curlOutputKind
	value string
}

type curlUploadSlot struct {
	value string
}

type curlArgvGroup struct {
	index         int
	targets       []curlTargetOperand
	outputs       []curlOutputSlot
	uploads       []curlUploadSlot
	remoteNameAll bool
	method        string
	head          bool
}

func parseCurlArgv(argv []string) curlArgvParse {
	parsed := curlArgvParse{Complete: true}
	if len(argv) == 0 {
		parsed.markUnresolved(-1, "", "missing curl executable")
		return parsed
	}

	groups := []curlArgvGroup{{index: 0}}
	group := &groups[0]
	options := true
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		if options && (argument == "--next" || argument == "-:") {
			parsed.Options = append(parsed.Options, curlOptionToken{
				ArgvIndex:      index,
				ValueArgvIndex: -1,
				ShortOffset:    -1,
				Group:          group.index,
				Raw:            argument,
				Name:           argument,
				Canonical:      "--next",
				Known:          true,
				Role:           curlOptionNeutral,
			})
			groups = append(groups, curlArgvGroup{index: len(groups)})
			group = &groups[len(groups)-1]
			options = true
			continue
		}
		if options && argument == "--" {
			parsed.Options = append(parsed.Options, curlOptionToken{
				ArgvIndex:      index,
				ValueArgvIndex: -1,
				ShortOffset:    -1,
				Group:          group.index,
				Raw:            argument,
				Name:           argument,
				Canonical:      "--",
				Known:          true,
				Role:           curlOptionNeutral,
			})
			options = false
			continue
		}
		if !options || argument == "-" || !strings.HasPrefix(argument, "-") {
			parsed.appendTarget(group, index, argument, false)
			continue
		}
		if strings.HasPrefix(argument, "--") {
			parsed.parseLongOption(argv, &index, group)
			continue
		}
		parsed.parseShortOptions(argv, &index, group)
	}

	for groupIndex := range groups {
		if len(groups) > 1 && len(groups[groupIndex].targets) == 0 {
			parsed.EmptyTransferGroup = true
			if groupIndex != len(groups)-1 {
				// Curl validates a leading or interior empty transfer before it
				// starts any group. A trailing empty group is diagnosed only after
				// earlier transfers have already emitted their output.
				parsed.Targets = nil
			}
			break
		}
		parsed.finalizeGroup(&groups[groupIndex])
	}
	return parsed
}

func (parsed *curlArgvParse) parseLongOption(
	argv []string,
	index *int,
	group *curlArgvGroup,
) {
	argument := argv[*index]
	name, joinedValue, joined := strings.Cut(argument, "=")
	spec, known := curlLongOptionSpecs[name]
	option := curlOptionToken{
		ArgvIndex:      *index,
		ValueArgvIndex: -1,
		ShortOffset:    -1,
		Group:          group.index,
		Raw:            argument,
		Name:           name,
		Canonical:      name,
		Known:          known,
	}
	if !known {
		parsed.Options = append(parsed.Options, option)
		parsed.markUnresolved(*index, argument, "unknown long option grammar")
		return
	}
	option.Canonical = spec.canonical
	option.Role = spec.role
	option.TakesValue = spec.arity != curlOptionNoValue
	if joined {
		parsed.Options = append(parsed.Options, option)
		parsed.markUnresolved(
			*index,
			argument,
			"joined value is not accepted for this curl option",
		)
		return
	}

	switch spec.arity {
	case curlOptionNoValue:
		if joined {
			parsed.markUnresolved(*index, argument, "value supplied to no-value option")
		}
	case curlOptionRequiredValue:
		switch {
		case joined:
			option.ValuePresent = true
			option.ValueJoined = true
			option.Value = joinedValue
		case *index+1 < len(argv):
			*index++
			option.ValuePresent = true
			option.ValueArgvIndex = *index
			option.Value = argv[*index]
		default:
			parsed.markUnresolved(option.ArgvIndex, argument, "missing required option value")
		}
	case curlOptionOptionalValue:
		if joined {
			option.ValuePresent = true
			option.ValueJoined = true
			option.Value = joinedValue
		} else if *index+1 < len(argv) && argv[*index+1] != "--" &&
			!strings.HasPrefix(argv[*index+1], "-") {
			*index++
			option.ValuePresent = true
			option.ValueArgvIndex = *index
			option.Value = argv[*index]
		}
	}
	parsed.Options = append(parsed.Options, option)
	parsed.applyOption(group, option)
}

func (parsed *curlArgvParse) parseShortOptions(
	argv []string,
	index *int,
	group *curlArgvGroup,
) {
	argument := argv[*index]
	for offset := 1; offset < len(argument); offset++ {
		short := argument[offset]
		spec, known := curlShortOptionSpecs[short]
		option := curlOptionToken{
			ArgvIndex:      *index,
			ValueArgvIndex: -1,
			ShortOffset:    offset,
			Group:          group.index,
			Raw:            argument,
			Name:           "-" + string(short),
			Canonical:      "-" + string(short),
			Known:          known,
		}
		if !known {
			parsed.Options = append(parsed.Options, option)
			parsed.markUnresolved(*index, argument, "unknown short option grammar")
			return
		}
		option.Canonical = spec.canonical
		option.Role = spec.role
		option.TakesValue = spec.arity != curlOptionNoValue

		switch spec.arity {
		case curlOptionNoValue:
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			continue
		case curlOptionRequiredValue:
			if offset+1 < len(argument) {
				option.ValuePresent = true
				option.ValueJoined = true
				option.Value = argument[offset+1:]
			} else if *index+1 < len(argv) {
				*index++
				option.ValuePresent = true
				option.ValueArgvIndex = *index
				option.Value = argv[*index]
			} else {
				parsed.markUnresolved(option.ArgvIndex, argument, "missing required option value")
			}
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			return
		case curlOptionOptionalValue:
			if offset+1 < len(argument) {
				option.ValuePresent = true
				option.ValueJoined = true
				option.Value = argument[offset+1:]
			} else if *index+1 < len(argv) && argv[*index+1] != "--" &&
				!strings.HasPrefix(argv[*index+1], "-") {
				*index++
				option.ValuePresent = true
				option.ValueArgvIndex = *index
				option.Value = argv[*index]
			}
			parsed.Options = append(parsed.Options, option)
			parsed.applyOption(group, option)
			return
		}
	}
}

func (parsed *curlArgvParse) applyOption(
	group *curlArgvGroup,
	option curlOptionToken,
) {
	switch option.Role {
	case curlOptionConfig:
		parsed.ConfigOpaque = true
		parsed.markUnresolved(
			option.ArgvIndex,
			option.Raw,
			"curl configuration can alter transfer semantics",
		)
	case curlOptionTarget:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty URL option value")
			return
		}
		valueIndex := option.ValueArgvIndex
		if option.ValueJoined {
			valueIndex = option.ArgvIndex
		}
		parsed.appendTarget(group, valueIndex, option.Value, true)
	case curlOptionOutput:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty output option value")
			group.outputs = append(group.outputs, curlOutputSlot{kind: curlOutputUnknown})
			return
		}
		kind := curlOutputFile
		if option.Value == "-" {
			kind = curlOutputStdout
		}
		group.outputs = append(group.outputs, curlOutputSlot{
			kind:  kind,
			value: option.Value,
		})
	case curlOptionRemoteName:
		group.outputs = append(group.outputs, curlOutputSlot{
			kind: curlOutputRemoteName,
		})
	case curlOptionRemoteNameAll:
		group.remoteNameAll = true
	case curlOptionNoRemoteName:
		if group.remoteNameAll {
			group.outputs = append(group.outputs, curlOutputSlot{
				kind: curlOutputStdout,
			})
		}
	case curlOptionNoRemoteNameAll:
		group.remoteNameAll = false
	case curlOptionMethod:
		if !option.ValuePresent || option.Value == "" {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "empty request method")
			return
		}
		group.method = option.Value
	case curlOptionUpload:
		if !option.ValuePresent {
			parsed.markUnresolved(option.ArgvIndex, option.Raw, "missing upload file")
			return
		}
		group.uploads = append(group.uploads, curlUploadSlot{
			value: option.Value,
		})
	case curlOptionHead:
		group.head = true
	case curlOptionNoHead:
		group.head = false
	case curlOptionPreview:
		parsed.Preview = true
	}
}

func (parsed *curlArgvParse) appendTarget(
	group *curlArgvGroup,
	argvIndex int,
	value string,
	viaURLOption bool,
) {
	if value == "" {
		parsed.markUnresolved(argvIndex, value, "empty transfer target")
		return
	}
	group.targets = append(group.targets, curlTargetOperand{
		argvIndex:    argvIndex,
		value:        value,
		viaURLOption: viaURLOption,
		remoteName:   group.remoteNameAll,
	})
}

func (parsed *curlArgvParse) finalizeGroup(group *curlArgvGroup) {
	for targetIndex, target := range group.targets {
		output := curlOutputSlot{kind: curlOutputStdout}
		if target.remoteName {
			output.kind = curlOutputRemoteName
		}
		if targetIndex < len(group.outputs) {
			output = group.outputs[targetIndex]
		}
		responseBodyStdout := output.kind == curlOutputStdout &&
			!parsed.Preview && !group.head &&
			!strings.EqualFold(group.method, "HEAD")
		transfer := curlTransferTarget{
			ArgvIndex:          target.argvIndex,
			Group:              group.index,
			Value:              target.value,
			ViaURLOption:       target.viaURLOption,
			Output:             output.kind,
			OutputValue:        output.value,
			Method:             group.method,
			Head:               group.head,
			Preview:            parsed.Preview,
			ResponseBodyStdout: responseBodyStdout,
		}
		if targetIndex < len(group.uploads) {
			transfer.UploadSet = true
			transfer.UploadValue = group.uploads[targetIndex].value
		}
		parsed.Targets = append(parsed.Targets, transfer)
	}
}

func (parsed *curlArgvParse) markUnresolved(
	argvIndex int,
	raw string,
	reason string,
) {
	parsed.Complete = false
	parsed.Unresolved = append(parsed.Unresolved, curlArgvUnresolved{
		ArgvIndex: argvIndex,
		Raw:       raw,
		Reason:    reason,
	})
}
