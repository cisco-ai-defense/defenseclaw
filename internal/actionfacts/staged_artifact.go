// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	stagedPOSIXPathPattern = regexp.MustCompile(
		`/[A-Za-z0-9._@%+,=:-]+(?:/[A-Za-z0-9._@%+,=:-]+)+`,
	)
	stagedIPv4Pattern = regexp.MustCompile(
		`(?:^|[^0-9])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:[^0-9]|$)`,
	)
)

// ExactSensitiveEgressArtifactWrite returns the only exact artifact created by
// a closed structured-write schema whose source text contains both a protected
// credential/secret path and a literal non-local network endpoint. The source
// text and endpoint never enter Facts or persisted chain state.
//
// This is detection evidence, not an enforcement proof. A later bounded chain
// must prove execution of the same normalized artifact before raising a result.
func ExactSensitiveEgressArtifactWrite(facts Facts) (PathFact, bool) {
	if len(facts.SensitiveEgressArtifactWrites) != 1 {
		return PathFact{}, false
	}
	candidate := facts.SensitiveEgressArtifactWrites[0]
	if candidate.Access != PathAccessWrite || candidate.Resolved == "" ||
		candidate.Flavor != PathFlavorPOSIX {
		return PathFact{}, false
	}
	return candidate, true
}

func projectSensitiveEgressArtifactWrites(input Input) []PathFact {
	artifactPath, source, ok := exactStructuredArtifactCreate(input)
	if !ok || !containsProtectedSourcePath(source) ||
		!containsNonLocalLiteralEndpoint(source) ||
		!containsNetworkSinkCapability(source) {
		return nil
	}
	candidate := PathFact{
		Access: PathAccessWrite,
		Flavor: pathFlavor(artifactPath),
		Value:  artifactPath,
	}
	paths := []PathFact{candidate}
	normalizePathFacts(paths, input.CWD, input.ActiveHome)
	candidate = paths[0]
	if candidate.Flavor != PathFlavorPOSIX || candidate.Resolved == "" ||
		hasUnresolvedPathSyntax(candidate.Value) {
		return nil
	}
	return []PathFact{candidate}
}

func exactStructuredArtifactCreate(input Input) (string, string, bool) {
	if strings.ToLower(input.Tool) != "text_editor" ||
		strings.TrimSpace(input.Tool) != input.Tool ||
		len(input.Args) == 0 || len(input.Args) > maxArgsJSONBytes ||
		!utf8.Valid(input.Args) {
		return "", "", false
	}
	if issue := validateJSONWithStringLimit(input.Args, maxArgsJSONBytes); issue != "" {
		return "", "", false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(input.Args))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 3 {
		return "", "", false
	}
	operation, operationOK := object["command"].(string)
	artifactPath, pathOK := object["path"].(string)
	source, sourceOK := object["file_text"].(string)
	if !operationOK || operation != "create" || !pathOK || !sourceOK ||
		strings.TrimSpace(artifactPath) != artifactPath || artifactPath == "" ||
		len(artifactPath) > maxScalarBytes || strings.IndexByte(artifactPath, 0) >= 0 ||
		source == "" || pathFlavor(artifactPath) != PathFlavorPOSIX ||
		!strings.HasPrefix(artifactPath, "/") {
		return "", "", false
	}
	for key := range object {
		if key != "command" && key != "path" && key != "file_text" {
			return "", "", false
		}
	}
	return artifactPath, source, true
}

func containsProtectedSourcePath(source string) bool {
	for _, candidate := range stagedPOSIXPathPattern.FindAllString(source, -1) {
		canonical := strings.ToLower(path.Clean(candidate))
		base := path.Base(canonical)
		switch canonical {
		case "/etc/shadow", "/etc/gshadow":
			return true
		}
		if strings.HasSuffix(canonical, "/.aws/credentials") ||
			strings.HasSuffix(canonical, "/.git-credentials") ||
			strings.HasSuffix(canonical, "/.netrc") ||
			strings.HasSuffix(canonical, "/.npmrc") ||
			strings.HasSuffix(canonical, "/.pypirc") ||
			strings.HasSuffix(canonical, "/.kube/config") ||
			strings.HasSuffix(canonical, "/.docker/config.json") ||
			(strings.Contains(canonical, "/.ssh/") &&
				strings.HasPrefix(base, "id_") &&
				!strings.HasSuffix(base, ".pub")) {
			return true
		}
		protectedRoot := strings.HasPrefix(canonical, "/opt/configs/") ||
			strings.HasPrefix(canonical, "/var/run/secrets/")
		if protectedRoot && sensitiveArtifactBasename(base) {
			return true
		}
	}
	return false
}

func sensitiveArtifactBasename(base string) bool {
	for _, marker := range []string{
		"api_key", "apikey", "credential", "jwt", "password", "secret", "token",
	} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return false
}

func containsNonLocalLiteralEndpoint(source string) bool {
	for _, match := range stagedIPv4Pattern.FindAllStringSubmatch(source, -1) {
		address, err := netip.ParseAddr(match[1])
		if err != nil {
			continue
		}
		address = address.Unmap()
		if !address.IsLoopback() && !address.IsPrivate() &&
			!address.IsLinkLocalUnicast() && !address.IsLinkLocalMulticast() &&
			!address.IsUnspecified() && !address.IsMulticast() {
			return true
		}
	}
	return false
}

func containsNetworkSinkCapability(source string) bool {
	lower := strings.ToLower(source)
	for _, marker := range []string{
		"http://", "https://", "requests.", "urllib.", "http.client",
		"socket.", ".connect(", ".send(", ".sendall(", "curl ", "wget ",
		"send_log", "upload", "webhook",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
