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
	"bytes"
	"encoding/json"
	"net/netip"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	stagedPayloadPathIdentityDomain = "defenseclaw/actionfacts/staged-payload-persistence-path/v1"
	stagedPayloadMaxScriptBytes     = 8 << 10
	stagedPayloadMaxScriptLines     = 64
)

// ExactStagedPayloadPersistenceOperation returns one value-free exact
// operation and its opaque path identity. It is intended only for a bounded,
// same-path chain whose runtime layer separately proves successful ordering.
func ExactStagedPayloadPersistenceOperation(
	facts Facts,
) (StagedPayloadPersistenceOperation, string, bool) {
	if len(facts.StagedPayloadPersistenceOperations) != 1 {
		return "", "", false
	}
	fact := facts.StagedPayloadPersistenceOperations[0]
	switch fact.Operation {
	case StagedPayloadWrite, StagedPayloadMutation, StagedPersistenceInstall:
	default:
		return "", "", false
	}
	if !validPrivateDigest(fact.PathIdentityDigest) {
		return "", "", false
	}
	return fact.Operation, fact.PathIdentityDigest, true
}

func projectStagedPayloadPersistenceOperations(
	input Input,
) []StagedPayloadPersistenceOperationFact {
	if target, content, ok := exactStagedPayloadWriteInput(input); ok {
		operation := StagedPayloadMutation
		if exactAuthoritativePOSIXReverseShellScript(content) {
			operation = StagedPayloadWrite
		}
		return stagedPayloadPersistenceFact(operation, target)
	}
	if target, ok := exactPersistenceInstallTarget(input); ok {
		return stagedPayloadPersistenceFact(StagedPersistenceInstall, target)
	}
	return nil
}

func stagedPayloadPersistenceFact(
	operation StagedPayloadPersistenceOperation,
	target string,
) []StagedPayloadPersistenceOperationFact {
	digest := framedPrivateDigest(stagedPayloadPathIdentityDomain, target)
	if !validPrivateDigest(digest) {
		return nil
	}
	return []StagedPayloadPersistenceOperationFact{{
		Operation: operation, PathIdentityDigest: digest,
	}}
}

// exactStagedPayloadWriteInput owns only these schemas:
//
//	file_write: {"path": string, "content": string, "mode"?: "overwrite"}
//	text_editor: {"command": "create"|"overwrite", "path": string,
//	              "file_text": string}
//
// No aliases, case folding, nested JSON, or additional fields are accepted.
func exactStagedPayloadWriteInput(input Input) (string, string, bool) {
	if input.Tool != "file_write" && input.Tool != "text_editor" {
		return "", "", false
	}
	object, ok := exactStagedPayloadObject(input.Args)
	if !ok {
		return "", "", false
	}
	var target, content string
	switch input.Tool {
	case "file_write":
		if len(object) != 2 && len(object) != 3 {
			return "", "", false
		}
		target, ok = object["path"].(string)
		if !ok {
			return "", "", false
		}
		content, ok = object["content"].(string)
		if !ok {
			return "", "", false
		}
		for key := range object {
			switch key {
			case "path", "content":
			case "mode":
				mode, modeOK := object[key].(string)
				if !modeOK || mode != "overwrite" {
					return "", "", false
				}
			default:
				return "", "", false
			}
		}
	case "text_editor":
		if len(object) != 3 {
			return "", "", false
		}
		command, commandOK := object["command"].(string)
		target, ok = object["path"].(string)
		content, _ = object["file_text"].(string)
		if !commandOK || !ok || (command != "create" && command != "overwrite") {
			return "", "", false
		}
		for key := range object {
			if key != "command" && key != "path" && key != "file_text" {
				return "", "", false
			}
		}
	}
	if !exactStagedPayloadPOSIXPath(target) || content == "" ||
		len(content) > stagedPayloadMaxScriptBytes || !utf8.ValidString(content) {
		return "", "", false
	}
	return target, content, true
}

func exactStagedPayloadObject(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes || !utf8.Valid(raw) ||
		validateJSONWithStringLimit(raw, stagedPayloadMaxScriptBytes) != "" {
		return nil, false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	return object, true
}

// exactAuthoritativePOSIXReverseShellScript accepts at most one exact shebang,
// comment/blank lines, and exactly one executable statement. The statement is
// then proved by the existing POSIX parser and netcat classifier; raw source
// matching is not sufficient.
func exactAuthoritativePOSIXReverseShellScript(source string) bool {
	if source == "" || len(source) > stagedPayloadMaxScriptBytes ||
		!utf8.ValidString(source) || strings.ContainsRune(source, '\r') {
		return false
	}
	lines := strings.Split(source, "\n")
	if len(lines) > stagedPayloadMaxScriptLines {
		return false
	}
	statements := make([]string, 0, 4)
	for index, line := range lines {
		if index == 0 && (line == "#!/bin/sh" || line == "#!/bin/bash") {
			continue
		}
		if strings.HasPrefix(line, "#!") {
			return false
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(statements) >= 4 {
			return false
		}
		statements = append(statements, line)
	}
	if len(statements) == 1 && strings.TrimSpace(statements[0]) == statements[0] {
		return exactAuthoritativePOSIXReverseShellCommand(statements[0])
	}
	if len(statements) != 4 || statements[0] != "while true; do" ||
		!strings.HasPrefix(statements[1], "  ") ||
		strings.HasPrefix(statements[1], "   ") ||
		!strings.HasPrefix(statements[2], "  sleep ") || statements[3] != "done" {
		return false
	}
	inner := strings.TrimPrefix(statements[1], "  ")
	delay := strings.TrimPrefix(statements[2], "  sleep ")
	if inner == "" || strings.TrimSpace(inner) != inner ||
		!exactBoundedLoopDelay(delay) {
		return false
	}
	return exactAuthoritativePOSIXReverseShellCommand(inner)
}

func exactAuthoritativePOSIXReverseShellCommand(command string) bool {
	parsed := parsePOSIX(command, 1, 0)
	classifyOutput(&parsed)
	projected := parsed.facts("staged_payload", "/")
	if exactAuthoritativeNetcatReverseShell(projected) {
		return true
	}
	return exactClosedBashTCPReverseShell(command, projected)
}

func exactBoundedLoopDelay(value string) bool {
	if value == "" || len(value) > 5 || value[0] == '0' {
		return false
	}
	seconds := 0
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
		seconds = seconds*10 + int(character-'0')
	}
	return seconds >= 1 && seconds <= 86400
}

func exactAuthoritativeNetcatReverseShell(projected Facts) bool {
	if !projected.Authoritative() || !projected.EnforcementEligible() ||
		len(projected.Commands) != 1 || len(projected.Network) != 1 ||
		len(projected.Paths) != 1 {
		return false
	}
	invocation := projected.Commands[0]
	if !exactUnconditionalTopLevelCommand(invocation) ||
		!invocation.ArgvComplete || !hasFactOperation(invocation, OperationConnect) ||
		!exactNetcatReverseShellArgv(invocation.Argv) {
		return false
	}
	if !exactReverseShellNetwork(projected.Network[0], invocation.ID) {
		return false
	}
	executed := projected.Paths[0]
	return executed.CommandID == invocation.ID &&
		executed.Access == PathAccessExecute &&
		exactReverseShellExecutable(executed.Resolved)
}

// exactClosedBashTCPReverseShell compensates only for the two constructs that
// the generic parser intentionally leaves non-authoritative: interactive bash
// without a command operand and the final 0>&1 descriptor copy. Every token,
// redirect, endpoint, and parser issue is nevertheless fixed and checked.
func exactClosedBashTCPReverseShell(command string, projected Facts) bool {
	if projected.Parse.Status != StatusPartial ||
		!exactIssueSet(projected.Parse.Issues, IssueUnsupportedConstruct, IssueOpaqueArtifact) ||
		len(projected.Commands) != 1 || len(projected.Network) != 0 ||
		len(projected.Paths) != 0 {
		return false
	}
	invocation := projected.Commands[0]
	if invocation.ControlFlowUncertain || invocation.ParentCommandID != 0 ||
		invocation.PipelineID != 0 || invocation.Kind != CommandKindProcess ||
		invocation.Effect != EffectExecute || !invocation.ArgvComplete ||
		len(invocation.Wrappers) != 0 || len(invocation.Argv) != 2 ||
		(invocation.Argv[0] != "bash" && invocation.Argv[0] != "/bin/bash") ||
		invocation.Argv[1] != "-i" || len(invocation.Redirects) != 2 ||
		len(invocation.Operations) != 1 || invocation.Operations[0] != OperationExecute {
		return false
	}
	networkRedirect := invocation.Redirects[0]
	descriptorCopy := invocation.Redirects[1]
	if networkRedirect.FD != 1 || networkRedirect.Access != PathAccessWrite ||
		networkRedirect.Target != "" || networkRedirect.Expands ||
		descriptorCopy.FD != 0 || descriptorCopy.Access != PathAccessWrite ||
		descriptorCopy.Target != "" || descriptorCopy.Expands {
		return false
	}
	prefix := invocation.Argv[0] + " -i >& "
	const suffix = " 0>&1"
	if !strings.HasPrefix(command, prefix) || !strings.HasSuffix(command, suffix) {
		return false
	}
	target := strings.TrimSuffix(strings.TrimPrefix(command, prefix), suffix)
	if strings.ContainsRune(target, ' ') || prefix+target+suffix != command {
		return false
	}
	network, ok := devNetworkRedirect(invocation.ID, target)
	if !ok {
		return false
	}
	networks := []NetworkFact{network}
	normalizeNetworkFacts(networks)
	return exactReverseShellNetwork(networks[0], invocation.ID)
}

func exactIssueSet(issues []IssueCode, expected ...IssueCode) bool {
	if len(issues) != len(expected) {
		return false
	}
	for index := range issues {
		if issues[index] != expected[index] {
			return false
		}
	}
	return true
}

func exactReverseShellNetwork(network NetworkFact, commandID int64) bool {
	if network.CommandID != commandID || network.Action != NetworkConnect ||
		network.Scheme != "tcp" || network.Host == "" ||
		network.NormalizedHost == "" || network.Port < 1 || network.Port > 65535 ||
		network.Scope == NetworkScopeLoopback || network.Scope == NetworkScopeLinkLocal {
		return false
	}
	if address, err := netip.ParseAddr(network.NormalizedHost); err == nil {
		address = address.Unmap()
		return !address.IsLoopback() && !address.IsLinkLocalUnicast() &&
			!address.IsLinkLocalMulticast() && !address.IsUnspecified() &&
			!address.IsMulticast()
	}
	return validNetworkHost(network.NormalizedHost) &&
		network.NormalizedHost == strings.ToLower(network.Host)
}

func exactNetcatReverseShellArgv(argv []string) bool {
	if len(argv) != 5 {
		return false
	}
	switch path.Base(argv[0]) {
	case "nc", "ncat", "netcat":
	default:
		return false
	}
	if argv[1] == "-e" {
		return exactReverseShellExecutable(argv[2]) &&
			validNetworkHost(argv[3]) && exactNetworkPort(argv[4])
	}
	return validNetworkHost(argv[1]) && exactNetworkPort(argv[2]) &&
		argv[3] == "-e" && exactReverseShellExecutable(argv[4])
}

func exactReverseShellExecutable(value string) bool {
	return value == "/bin/sh" || value == "/bin/bash"
}

func exactNetworkPort(value string) bool {
	_, ok := parseNetworkPort(value)
	return ok
}

func exactPersistenceInstallTarget(input Input) (string, bool) {
	if input.Tool != "persist" {
		return "", false
	}
	object, ok := exactStagedPayloadObject(input.Args)
	if !ok || len(object) != 2 {
		return "", false
	}
	method, methodOK := object["method"].(string)
	payload, payloadOK := object["payload"].(string)
	if !methodOK || !payloadOK || payload == "" || len(payload) > maxCommandBytes ||
		strings.TrimSpace(payload) != payload {
		return "", false
	}
	for key := range object {
		if key != "method" && key != "payload" {
			return "", false
		}
	}

	var target string
	switch method {
	case "cron":
		command, commandOK := exactPersistenceCronCommand(payload)
		if !commandOK {
			return "", false
		}
		target, ok = exactStagedPayloadCronCommandTarget(command)
		if !ok {
			return "", false
		}
	case "systemd":
		target, ok = exactStagedPayloadSystemdTarget(payload)
		if !ok {
			return "", false
		}
	case "pam_module":
		target, ok = exactStagedPayloadPAMTarget(payload)
		if !ok {
			return "", false
		}
	default:
		return "", false
	}
	if safeStagedPayloadSystemPath(target) {
		return "", false
	}
	return target, true
}

func exactStagedPayloadCronCommandTarget(command string) (string, bool) {
	if exactStagedPayloadPOSIXPath(command) {
		return command, true
	}
	fields := strings.Fields(command)
	if len(fields) != 2 || strings.Join(fields, " ") != command ||
		(fields[0] != "/bin/bash" && fields[0] != "/bin/sh") ||
		!exactStagedPayloadPOSIXPath(fields[1]) {
		return "", false
	}
	return fields[1], true
}

type systemdPayloadSection uint8

const (
	systemdSectionNone systemdPayloadSection = iota
	systemdSectionUnit
	systemdSectionService
	systemdSectionInstall
)

type systemdPayloadDirectiveIdentity struct {
	section systemdPayloadSection
	key     string
}

// The complete-unit grammar owns exactly [Unit], [Service], and [Install] in
// that order. Only inert directives from the explicit allowlist are accepted;
// ExecStart must be a direct normalized path with no arguments or wrapper.
func exactStagedPayloadSystemdTarget(payload string) (string, bool) {
	if exactStagedPayloadPOSIXPath(payload) {
		return payload, true
	}
	lines := strings.Split(payload, "\n")
	if len(lines) < 6 || len(lines) > stagedPayloadMaxScriptLines {
		return "", false
	}
	section := systemdSectionNone
	sections := make(map[systemdPayloadSection]bool, 3)
	directives := make(map[systemdPayloadDirectiveIdentity]bool, 8)
	target := ""
	for _, line := range lines {
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if next, header := exactSystemdSection(line); header {
			if sections[next] || next != section+1 {
				return "", false
			}
			section = next
			sections[next] = true
			continue
		}
		key, value, directiveOK := exactStagedPayloadSystemdDirective(section, line)
		identity := systemdPayloadDirectiveIdentity{section: section, key: key}
		if !directiveOK || directives[identity] {
			return "", false
		}
		directives[identity] = true
		if key == "ExecStart" {
			if target != "" {
				return "", false
			}
			target = value
		}
	}
	if section != systemdSectionInstall || target == "" || len(sections) != 3 {
		return "", false
	}
	return target, true
}

func exactSystemdSection(line string) (systemdPayloadSection, bool) {
	switch line {
	case "[Unit]":
		return systemdSectionUnit, true
	case "[Service]":
		return systemdSectionService, true
	case "[Install]":
		return systemdSectionInstall, true
	default:
		return systemdSectionNone, false
	}
}

func exactStagedPayloadSystemdDirective(
	section systemdPayloadSection,
	line string,
) (key, value string, ok bool) {
	key, value, ok = strings.Cut(line, "=")
	if !ok || key == "" || value == "" || strings.TrimSpace(key) != key ||
		strings.TrimSpace(value) != value {
		return "", "", false
	}
	switch section {
	case systemdSectionUnit:
		switch key {
		case "Description":
			return key, value, exactInertSystemdDescription(value)
		case "After":
			return key, value, exactSystemdUnitList(value)
		}
	case systemdSectionService:
		switch key {
		case "ExecStart":
			return key, value, exactStagedPayloadPOSIXPath(value)
		case "Type":
			return key, value, value == "simple" || value == "exec" || value == "oneshot"
		case "Restart":
			switch value {
			case "no", "on-success", "on-failure", "on-abnormal", "on-abort", "on-watchdog", "always":
				return key, value, true
			}
		case "RestartSec":
			return key, value, exactSystemdDuration(value)
		}
	case systemdSectionInstall:
		if key == "WantedBy" {
			return key, value, exactSystemdUnitList(value)
		}
	}
	return "", "", false
}

func exactInertSystemdDescription(value string) bool {
	if value == "" || len(value) > maxScalarBytes {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func exactSystemdUnitList(value string) bool {
	fields := strings.Fields(value)
	if len(fields) == 0 || len(fields) > 16 || strings.Join(fields, " ") != value {
		return false
	}
	for _, field := range fields {
		if !exactSystemdUnitName(field) {
			return false
		}
	}
	return true
}

func exactSystemdUnitName(value string) bool {
	if value == "" || len(value) > 255 || !strings.Contains(value, ".") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("_.@:-", character) {
			continue
		}
		return false
	}
	return true
}

func exactSystemdDuration(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	number := value
	for _, suffix := range []string{"min", "ms", "s", "m", "h"} {
		if strings.HasSuffix(number, suffix) {
			number = strings.TrimSuffix(number, suffix)
			break
		}
	}
	if number == "" {
		return false
	}
	for _, character := range number {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// The PAM grammar accepts either one module path or one exact three-field PAM
// stack rule. Module options are excluded because they can name more targets.
func exactStagedPayloadPAMTarget(payload string) (string, bool) {
	if exactStagedPayloadPOSIXPath(payload) && strings.HasSuffix(payload, ".so") {
		return payload, true
	}
	fields := strings.Fields(payload)
	if len(fields) != 3 || strings.Join(fields, " ") != payload ||
		!exactPAMManagementGroup(fields[0]) || !exactPAMControl(fields[1]) ||
		!exactStagedPayloadPOSIXPath(fields[2]) || !strings.HasSuffix(fields[2], ".so") {
		return "", false
	}
	return fields[2], true
}

func exactPAMManagementGroup(value string) bool {
	switch value {
	case "auth", "account", "password", "session":
		return true
	default:
		return false
	}
}

func exactPAMControl(value string) bool {
	switch value {
	case "required", "requisite", "sufficient", "optional":
		return true
	default:
		return false
	}
}

func exactStagedPayloadPOSIXPath(value string) bool {
	if value == "" || value == "/" || len(value) > maxScalarBytes ||
		validateScalar(value, maxScalarBytes) != "" || strings.TrimSpace(value) != value ||
		!path.IsAbs(value) || path.Clean(value) != value ||
		pathFlavor(value) != PathFlavorPOSIX || hasUnresolvedPathSyntax(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func safeStagedPayloadSystemPath(value string) bool {
	for _, root := range []string{
		"/bin", "/sbin", "/lib", "/lib64", "/usr/bin", "/usr/sbin",
		"/usr/lib", "/usr/lib64", "/usr/libexec",
	} {
		if value == root || strings.HasPrefix(value, root+"/") {
			return true
		}
	}
	return false
}
