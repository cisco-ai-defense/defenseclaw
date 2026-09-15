// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

const maxPowerShellTCPCommandLoopBytes = 8 * 1024

var (
	powerShellTCPConstructor = regexp.MustCompile(`(?is)^\s*(\$[a-z_][a-z0-9_]*)\s*=\s*New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient\s*\(\s*["']((?:[a-z0-9-]+\.)+[a-z0-9-]+|(?:\d{1,3}\.){3}\d{1,3})["']\s*,\s*(\d{1,5})\s*\)\s*;`)
	powerShellTCPGetStream   = regexp.MustCompile(`(?is)(\$[a-z_][a-z0-9_]*)\s*=\s*(\$[a-z_][a-z0-9_]*)\.GetStream\s*\(\s*\)\s*;`)
	powerShellTCPReadLoop    = regexp.MustCompile(`(?is)\bwhile\s*\(\s*\(\s*(\$[a-z_][a-z0-9_]*)\s*=\s*(\$[a-z_][a-z0-9_]*)\.Read\s*\(\s*(\$[a-z_][a-z0-9_]*)\s*,\s*0\s*,\s*(\$[a-z_][a-z0-9_]*)\.Length\s*\)\s*\)\s*-ne\s*0\s*\)\s*\{`)
	powerShellTCPDecode      = regexp.MustCompile(`(?is)(\$[a-z_][a-z0-9_]*)\s*=\s*(?:(?:\(\s*New-Object\s+Text\.(?:ASCII|UTF8)Encoding\s*\))|(?:\(\s*\[Text\.Encoding\]::(?:ASCII|UTF8)\s*\)))\.GetString\s*\(\s*(\$[a-z_][a-z0-9_]*)\s*,\s*0\s*,\s*(\$[a-z_][a-z0-9_]*)\s*\)\s*;`)
	powerShellTCPExecute     = regexp.MustCompile(`(?is)(\$[a-z_][a-z0-9_]*)\s*=\s*\(\s*(?:iex|Invoke-Expression)\s+(\$[a-z_][a-z0-9_]*)\b[^;{}\r\n]{0,256}\)\s*;`)
	powerShellTCPEncode      = regexp.MustCompile(`(?is)(\$[a-z_][a-z0-9_]*)\s*=\s*\(\s*\[Text\.Encoding\]::(?:ASCII|UTF8)\s*\)\.GetBytes\s*\(\s*(\$[a-z_][a-z0-9_]*)\s*\)\s*;`)
	powerShellTCPWrite       = regexp.MustCompile(`(?is)(\$[a-z_][a-z0-9_]*)\.Write\s*\(\s*(\$[a-z_][a-z0-9_]*)\s*,\s*0\s*,\s*(\$[a-z_][a-z0-9_]*)\.Length\s*\)`)
	powerShellTCPLoopClose   = regexp.MustCompile(`(?is)^[^{}]{0,256}\}`)
)

// ExactPowerShellTCPCommandLoop reports whether a value-free closed grammar
// proves a static TCP receive, command-evaluation, and response-write loop.
func ExactPowerShellTCPCommandLoop(facts Facts) bool {
	return len(facts.PowerShellTCPCommandLoops) == 1
}

func projectPowerShellTCPCommandLoops(input Input, facts Facts) []PowerShellTCPCommandLoopFact {
	if facts.Parse.Dialect != DialectPowerShell || len(input.Command) == 0 ||
		len(input.Command) > maxPowerShellTCPCommandLoopBytes {
		return nil
	}
	command := strings.TrimSpace(input.Command)
	constructor := powerShellTCPConstructor.FindStringSubmatchIndex(command)
	if constructor == nil {
		return nil
	}
	port, err := strconv.Atoi(command[constructor[6]:constructor[7]])
	if err != nil || port < 1 || port > 65535 {
		return nil
	}
	host := command[constructor[4]:constructor[5]]
	if address := net.ParseIP(host); address != nil &&
		(address.IsLoopback() || address.IsUnspecified()) {
		return nil
	}
	client := strings.ToLower(command[constructor[2]:constructor[3]])
	rest := command[constructor[1]:]
	streamMatch := powerShellTCPGetStream.FindStringSubmatchIndex(rest)
	if streamMatch == nil || streamMatch[0] > 1000 ||
		!strings.EqualFold(rest[streamMatch[4]:streamMatch[5]], client) {
		return nil
	}
	stream := strings.ToLower(rest[streamMatch[2]:streamMatch[3]])
	rest = rest[streamMatch[1]:]
	readMatch := powerShellTCPReadLoop.FindStringSubmatchIndex(rest)
	if readMatch == nil || readMatch[0] > 1000 ||
		!strings.EqualFold(rest[readMatch[4]:readMatch[5]], stream) ||
		!strings.EqualFold(rest[readMatch[6]:readMatch[7]], rest[readMatch[8]:readMatch[9]]) {
		return nil
	}
	countVariable := rest[readMatch[2]:readMatch[3]]
	bufferVariable := rest[readMatch[6]:readMatch[7]]
	rest = rest[readMatch[1]:]
	decodeMatch := powerShellTCPDecode.FindStringSubmatchIndex(rest)
	if decodeMatch == nil || decodeMatch[0] > 1000 ||
		strings.ContainsAny(rest[:decodeMatch[0]], "{}") ||
		!strings.EqualFold(rest[decodeMatch[4]:decodeMatch[5]], bufferVariable) ||
		!strings.EqualFold(rest[decodeMatch[6]:decodeMatch[7]], countVariable) {
		return nil
	}
	commandVariable := rest[decodeMatch[2]:decodeMatch[3]]
	rest = rest[decodeMatch[1]:]
	executeMatch := powerShellTCPExecute.FindStringSubmatchIndex(rest)
	if executeMatch == nil || executeMatch[0] > 1000 ||
		strings.ContainsAny(rest[:executeMatch[0]], "{}") ||
		!strings.EqualFold(rest[executeMatch[4]:executeMatch[5]], commandVariable) {
		return nil
	}
	resultVariable := rest[executeMatch[2]:executeMatch[3]]
	rest = rest[executeMatch[1]:]
	encodeMatch := powerShellTCPEncode.FindStringSubmatchIndex(rest)
	if encodeMatch == nil || encodeMatch[0] > 1000 ||
		strings.ContainsAny(rest[:encodeMatch[0]], "{}") ||
		!strings.EqualFold(rest[encodeMatch[4]:encodeMatch[5]], resultVariable) {
		return nil
	}
	outputVariable := rest[encodeMatch[2]:encodeMatch[3]]
	rest = rest[encodeMatch[1]:]
	writeMatch := powerShellTCPWrite.FindStringSubmatchIndex(rest)
	if writeMatch == nil || writeMatch[0] > 1000 ||
		strings.ContainsAny(rest[:writeMatch[0]], "{}") ||
		!strings.EqualFold(rest[writeMatch[2]:writeMatch[3]], stream) ||
		!strings.EqualFold(rest[writeMatch[4]:writeMatch[5]], outputVariable) ||
		!strings.EqualFold(rest[writeMatch[6]:writeMatch[7]], outputVariable) {
		return nil
	}
	if !powerShellTCPLoopClose.MatchString(rest[writeMatch[1]:]) {
		return nil
	}
	return []PowerShellTCPCommandLoopFact{{}}
}
