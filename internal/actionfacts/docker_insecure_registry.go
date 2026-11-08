// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

const dockerDaemonConfigPath = "/etc/docker/daemon.json"

// ExactDockerInsecureRegistryWrite reports whether one authenticated
// whole-file write replaces Docker's daemon configuration with a strict JSON
// document whose only setting lists at least one non-loopback insecure
// registry in any spelling Docker accepts (host, host:port, IP, IPv6
// [addr]:port, CIDR, or an http:// or https:// URL). The write is read from
// the closed argument shapes of every native file tool (nativeFileWrites:
// Write, the write_file aliases whichever name they give the path, Copilot
// create, OpenCode write, a patch that adds the file), for the file the call
// names or the file an existing link reaches. It
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
		// A relative name (a link in the project) is placed in the working
		// directory of the call, as the tool does; an absolute one must
		// already be canonical.
		canonical, absolute := nativeAbsoluteTarget(write.target, input.CWD)
		if !write.whole || !absolute || strings.HasPrefix(write.target, "/") && canonical != write.target ||
			!nativeOperandsCoverTarget(facts, len(writes), canonical) {
			continue
		}
		content := write.added
		if content == "" || len(content) > maxCommandBytes || !utf8.ValidString(content) ||
			strings.ContainsRune(content, 0) {
			continue
		}
		for _, file := range nativeReachedFiles(facts, canonical) {
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
	foundInsecure := false
	for _, value := range registries {
		registry, ok := value.(string)
		if !ok {
			return false
		}
		if _, duplicate := seen[registry]; duplicate {
			return false
		}
		seen[registry] = struct{}{}
		insecure, valid := exactDockerRegistryEntry(registry)
		if !valid {
			return false
		}
		foundInsecure = foundInsecure || insecure
	}
	return foundInsecure
}

// exactDockerRegistryEntry classifies one insecure-registries element. Docker
// accepts four spellings: an http:// or https:// URL, a CIDR block, a bare
// IP address, and host or host:port (including [IPv6]:port). Every spelling
// makes the named registry insecure, so the spelling never decides the
// verdict; only the address does. valid is false for anything the closed
// grammar cannot prove, which leaves the whole document unproven. insecure is
// true for a registry that is not covered by the built-in loopback exception.
func exactDockerRegistryEntry(value string) (insecure bool, valid bool) {
	if value == "" || len(value) > maxScalarBytes ||
		strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") ||
		containsDockerRegistryInterpolation(value) {
		return false, false
	}
	switch {
	case strings.Contains(value, "://"):
		return exactDockerRegistryURL(value)
	case strings.Contains(value, "/"):
		return exactDockerRegistryCIDR(value)
	default:
		return exactDockerRegistryHostPort(value)
	}
}

func exactDockerRegistryURL(value string) (insecure bool, valid bool) {
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
	insecure, valid = exactDockerRegistryHost(parsed.Hostname())
	if !valid || !exactDockerRegistryPort(parsed.Port()) {
		return false, false
	}
	return insecure, true
}

// exactDockerRegistryHostPort reads the scheme-less spellings: a bare IPv4 or
// IPv6 address, a host, host:port or IPv4:port, and a bracketed [IPv6]:port.
func exactDockerRegistryHostPort(value string) (insecure bool, valid bool) {
	if address, err := netip.ParseAddr(value); err == nil {
		return exactDockerRegistryAddress(address)
	}
	host := value
	if strings.Contains(value, ":") {
		var port string
		var err error
		host, port, err = net.SplitHostPort(value)
		if err != nil || port == "" || !exactDockerRegistryPort(port) {
			return false, false
		}
		if strings.HasPrefix(value, "[") {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is6() {
				return false, false
			}
		}
	}
	return exactDockerRegistryHost(host)
}

// exactDockerRegistryCIDR reads a CIDR block. A block is the loopback
// exception only when every address in it is loopback; a wider block (for
// example one that spans private ranges) names non-loopback registries.
func exactDockerRegistryCIDR(value string) (insecure bool, valid bool) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || prefix.Addr().Zone() != "" {
		return false, false
	}
	address, bits := prefix.Addr(), prefix.Bits()
	if address.Is4In6() {
		if bits < 96 {
			return true, true
		}
		address, bits = address.Unmap(), bits-96
	}
	if address.IsLoopback() && bits >= loopbackBlockBits(address) ||
		address.IsUnspecified() && bits == address.BitLen() {
		return false, true
	}
	return true, true
}

// loopbackBlockBits is the shortest prefix that keeps a block inside the
// loopback range: 127.0.0.0/8 for IPv4, the single address ::1 for IPv6.
func loopbackBlockBits(address netip.Addr) int {
	if address.Is4() {
		return 8
	}
	return address.BitLen()
}

func containsDockerRegistryInterpolation(value string) bool {
	return strings.Contains(value, "${") || strings.Contains(value, "$(") ||
		strings.Contains(value, "{{") || strings.Contains(value, "}}") ||
		strings.ContainsRune(value, 0x60)
}

// exactDockerRegistryHost classifies a registry host name or address. A
// loopback name or address is valid but not insecure: Docker already trusts
// it, so it cannot make a document hazardous, and it must not make a document
// that also lists a remote registry unprovable.
func exactDockerRegistryHost(host string) (insecure bool, valid bool) {
	if host == "" || len(host) > 253 || !dockerRegistryASCII(host) {
		return false, false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return false, true
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return exactDockerRegistryAddress(address)
	}
	// Reject non-canonical numeric IPv4 spellings rather than relying on a
	// platform resolver to decide whether they denote loopback.
	if dockerRegistryNumericHost(host) {
		return false, false
	}
	if strings.HasSuffix(host, ".") {
		return false, false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false, false
		}
		for _, character := range label {
			if !strings.ContainsRune(dockerRegistryLabelCharacters, character) {
				return false, false
			}
		}
	}
	return true, true
}

const dockerRegistryLabelCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"

func exactDockerRegistryAddress(address netip.Addr) (insecure bool, valid bool) {
	address = address.Unmap()
	if address.Zone() != "" {
		return false, false
	}
	return !address.IsLoopback() && !address.IsUnspecified(), true
}

func dockerRegistryNumericHost(value string) bool {
	return strings.Trim(value, "0123456789.") == ""
}

func exactDockerRegistryPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 || len(port) > 1 && strings.HasPrefix(port, "0") {
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
