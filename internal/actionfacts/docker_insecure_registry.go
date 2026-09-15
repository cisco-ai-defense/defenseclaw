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

// ExactDockerInsecureRegistryWrite reports whether one authenticated,
// closed-schema full-file write replaces Docker's daemon configuration with a
// strict JSON document whose only setting enables at least one non-loopback
// literal HTTP registry. It deliberately returns no path, registry, or content.
//
// Substring editors are excluded: their arguments cannot prove that the
// replacement is the complete final daemon.json document.
func ExactDockerInsecureRegistryWrite(input Input, facts Facts) bool {
	if input.Command != "" || len(input.Argv) != 0 ||
		!facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Tool != input.Tool || !exactDockerDaemonWriteFacts(facts) {
		return false
	}

	target, content, ok := exactDockerDaemonFullWrite(input)
	return ok && target == dockerDaemonConfigPath &&
		exactDockerInsecureRegistryDocument(content)
}

func exactDockerDaemonWriteFacts(facts Facts) bool {
	if len(facts.Commands) != 1 || len(facts.Paths) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.Effect != EffectExecute ||
		!hasFactOperation(command, OperationExecute) ||
		!hasFactOperation(command, OperationWrite) ||
		len(command.Operations) != 2 {
		return false
	}
	path := facts.Paths[0]
	return path.CommandID == command.ID && path.Access == PathAccessWrite &&
		path.Flavor == PathFlavorPOSIX && path.Value == dockerDaemonConfigPath &&
		path.Normalized == dockerDaemonConfigPath && path.Absolute &&
		path.Resolved == dockerDaemonConfigPath
}

// exactDockerDaemonFullWrite owns only the full-document write contracts that
// are already authenticated by the generic ActionFacts projection:
//
//   - Write: {"file_path": string, "content": string}
//   - write_file aliases: {"path": string, "content": string}
//
// No case folding, semantic aliases, modes, metadata, nesting, or additional
// fields are accepted here. In particular, Edit old_string/new_string calls
// are partial replacements and cannot establish a final-document proof.
func exactDockerDaemonFullWrite(input Input) (string, string, bool) {
	object, problem := exactJSONObject(input.Args)
	if problem.status != "" || len(object) != 2 {
		return "", "", false
	}

	pathKey := ""
	switch input.Tool {
	case "Write":
		pathKey = "file_path"
	case "write_file", "write-file", "writefile":
		pathKey = "path"
	default:
		return "", "", false
	}
	for key := range object {
		if key != pathKey && key != "content" {
			return "", "", false
		}
	}
	target, targetOK := object[pathKey].(string)
	content, contentOK := object["content"].(string)
	if !targetOK || !contentOK || target != dockerDaemonConfigPath ||
		content == "" || len(content) > maxCommandBytes ||
		!utf8.ValidString(content) || strings.ContainsRune(content, 0) {
		return "", "", false
	}
	return target, content, true
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
