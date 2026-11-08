// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const dockerDaemonConfigPath = "/etc/docker/daemon.json"

// ExactDockerInsecureRegistryWrite reports whether one authenticated
// whole-file write replaces Docker's daemon configuration with a strict JSON
// document whose only setting enables at least one non-loopback literal HTTP
// registry. The write is read from the closed argument shapes of every native
// file tool (nativeFileWrites: Write, the write_file aliases whichever name
// they give the path, Copilot create, OpenCode write, a patch that adds the
// file), for the file the call names or the file an existing link reaches. It
// deliberately returns no path, registry, or content.
//
// Substring editors, patch hunks and appends are excluded: their arguments
// cannot prove that the replacement is the complete final daemon.json
// document.
func ExactDockerInsecureRegistryWrite(input Input, facts Facts) bool {
	if input.Command != "" || len(input.Argv) != 0 ||
		!facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Tool != input.Tool {
		return false
	}
	writes := nativeFileWrites(input.Tool, input.Args)
	for _, write := range writes {
		content := write.added
		if !write.whole || content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
			strings.ContainsRune(content, 0) {
			continue
		}
		// An absolute name the call gives must itself be the canonical
		// spelling; a relative name (a link in the project) is placed in the
		// working directory of the call, as the tool does, and a link or a
		// name the gateway cannot place is read from the client answer.
		files := nativeClientReachedFiles(input, write.target)
		if canonical, absolute := nativeAbsoluteTarget(write.target, input.CWD); absolute &&
			(!strings.HasPrefix(write.target, "/") || canonical == write.target) &&
			nativeOperandsCoverTarget(facts, len(writes), canonical) {
			files = append(nativeReachedFiles(facts, canonical), files...)
		}
		for _, file := range files {
			if EtcSpelling(file) == dockerDaemonConfigPath &&
				writeToolNamesItsFile(input) &&
				exactDockerInsecureRegistryDocument(content) {
				return true
			}
		}
	}
	return false
}

// writeToolNamesItsFile reports whether a Write call names its file the way
// Claude Code's tool does, file_path: a Write that gives the path another name
// is a call the tool refuses, not a write of that file. The other tools
// (write_file aliases, Copilot, OpenCode, patches) take their spellings from
// nativeFileWrites.
func writeToolNamesItsFile(input Input) bool {
	if input.Tool != "Write" {
		return true
	}
	object, problem := exactJSONObject(input.Args)
	_, named := object["file_path"]
	return problem.status == "" && named
}

func exactDockerInsecureRegistryDocument(content string) bool {
	raw := []byte(content)
	if validateJSONWithStringLimit(raw, maxScalarBytes) != "" {
		return false
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil || len(document) != 1 {
		return false
	}
	registriesValue, ok := document["insecure-registries"]
	if !ok {
		return false
	}
	registries, ok := registriesValue.([]any)
	if !ok || len(registries) == 0 {
		return false
	}

	seen := make(map[string]struct{}, len(registries))
	foundHTTP := false
	for _, value := range registries {
		registry, ok := value.(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[registry]; duplicate {
			return false
		}
		seen[registry] = struct{}{}
		insecure, valid := exactDockerRegistryURL(registry)
		if !valid {
			return false
		}
		foundHTTP = foundHTTP || insecure
	}
	return foundHTTP
}

func exactDockerRegistryURL(value string) (insecure bool, valid bool) {
	if value == "" || len(value) > maxScalarBytes ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") ||
		containsDockerRegistryInterpolation(value) {
		return false, false
	}
	isHTTP := strings.HasPrefix(value, "http://")
	isHTTPS := strings.HasPrefix(value, "https://")
	if !isHTTP && !isHTTPS {
		return false, false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Opaque != "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" ||
		parsed.RawPath != "" || parsed.Host == "" {
		return false, false
	}
	if (isHTTP && parsed.Scheme != "http") ||
		(isHTTPS && parsed.Scheme != "https") {
		return false, false
	}
	host := parsed.Hostname()
	if !exactNonLoopbackRegistryHost(host) || !exactDockerRegistryPort(parsed.Port()) {
		return false, false
	}
	return isHTTP, true
}

func containsDockerRegistryInterpolation(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.ContainsRune(value, '`')
}

func exactNonLoopbackRegistryHost(host string) bool {
	if host == "" || len(host) > 253 || !dockerRegistryASCII(host) {
		return false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return false
	}
	if address, err := netip.ParseAddr(host); err == nil {
		address = address.Unmap()
		return address.Zone() == "" && !address.IsLoopback() &&
			!address.IsUnspecified()
	}
	// Reject non-canonical numeric IPv4 spellings rather than relying on a
	// platform resolver to decide whether they denote loopback.
	if dockerRegistryNumericHost(host) {
		return false
	}
	if strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func dockerRegistryNumericHost(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			if character != '.' {
				return false
			}
		}
	}
	return true
}

func exactDockerRegistryPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 || len(port) > 1 && port[0] == '0' {
		return false
	}
	value, err := strconv.ParseUint(port, 10, 16)
	return err == nil && value != 0
}

func dockerRegistryASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
