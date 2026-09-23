// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const endpointProcessIdentityDomain = "defenseclaw/actionfacts/endpoint-process/v1"

var endpointSecurityEventKeys = map[string]bool{
	"audit_policy_changes": true, "category_id": true, "client_process_id": true,
	"details": true, "event_id": true, "host": true, "new_value": true,
	"logon_id": true, "old_value": true, "operation": true,
	"parent_image": true, "parent_process_guid": true, "parent_process_id": true,
	"process_guid": true, "process_id": true,
	"process_image": true, "provider": true, "record_id": true,
	"profile": true, "resource": true, "rule_id": true, "rule_name": true,
	"subcategory_guid": true, "subcategory_id": true,
	"timestamp": true, "user": true, "user_domain": true,
}

func ExactEndpointSecurityControlMutations(facts Facts) []EndpointSecurityControlMutationFact {
	result := make([]EndpointSecurityControlMutationFact, 0, len(facts.EndpointSecurityControlMutations))
	for _, fact := range facts.EndpointSecurityControlMutations {
		if fact.Platform != "windows" || !fact.Exact {
			return nil
		}
		switch fact.Operation {
		case EndpointDefenderExclusionRequested, EndpointDefenderLoggingDisableRequested:
			if !validPrivateDigest(fact.ProcessIdentityDigest) {
				return nil
			}
		case EndpointDefenderExclusionAdded, EndpointDefenderLoggingDisabled:
			if fact.ProcessIdentityDigest != "" && !validPrivateDigest(fact.ProcessIdentityDigest) {
				return nil
			}
		default:
			return nil
		}
		result = append(result, fact)
	}
	return result
}

func projectEndpointSecurityControlMutations(input Input) []EndpointSecurityControlMutationFact {
	if strings.EqualFold(input.Tool, "shell") {
		return projectEndpointSecurityControlRequest(input)
	}
	if input.Tool != "windows.event" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	operation, ok := exactEndpointSecurityControlMutationInput(input.Args)
	if !ok {
		return nil
	}
	processGUID := exactProcessGUID(input.Args)
	digest := ""
	if processGUID != "" {
		digest = framedPrivateDigest(endpointProcessIdentityDomain, processGUID)
	}
	return []EndpointSecurityControlMutationFact{{
		Platform: "windows", Operation: operation,
		ProcessIdentityDigest: digest, Exact: true,
	}}
}

func projectEndpointSecurityControlRequest(input Input) []EndpointSecurityControlMutationFact {
	processGUID := exactEndpointProcessMetadataInput(input.Args)
	if processGUID == "" || input.Command == "" || len(input.Argv) != 0 {
		return nil
	}
	facts := Analyze(Input{Tool: input.Tool, Command: input.Command, DialectHint: input.DialectHint})
	if !facts.Authoritative() || !facts.EnforcementEligible() || len(facts.Commands) != 1 {
		return nil
	}
	operation, ok := exactEndpointSecurityRequestArgv(facts.Commands[0].Argv)
	if !ok {
		return nil
	}
	return []EndpointSecurityControlMutationFact{{
		Platform: "windows", Operation: operation,
		ProcessIdentityDigest: framedPrivateDigest(endpointProcessIdentityDomain, processGUID), Exact: true,
	}}
}

func exactEndpointProcessMetadataInput(raw []byte) string {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || !exactObjectKeys(object, endpointSecurityEventKeys) ||
		exactString(object["provider"]) != "Microsoft-Windows-Sysmon" || exactString(object["event_id"]) != "1" {
		return ""
	}
	image := strings.ToLower(exactString(object["process_image"]))
	if image != "reg.exe" && !strings.HasSuffix(image, `\reg.exe`) {
		return ""
	}
	return exactProcessGUID(raw)
}

func exactProcessGUID(raw []byte) string {
	object, problem := exactJSONObject(raw)
	if problem.status != "" {
		return ""
	}
	value := strings.ToLower(exactString(object["process_guid"]))
	if len(value) != 38 || value[0] != '{' || value[37] != '}' {
		return ""
	}
	for index, character := range value[1:37] {
		position := index + 1
		if position == 9 || position == 14 || position == 19 || position == 24 {
			if character != '-' {
				return ""
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return ""
		}
	}
	return value
}

func exactEndpointSecurityRequestArgv(argv []string) (EndpointSecurityControlMutation, bool) {
	if len(argv) != 10 || !strings.EqualFold(argv[0], "reg") || !strings.EqualFold(argv[1], "add") ||
		!strings.EqualFold(argv[3], "/v") || !strings.EqualFold(argv[5], "/t") ||
		!strings.EqualFold(argv[6], "REG_DWORD") || !strings.EqualFold(argv[7], "/d") || argv[8] != "0" ||
		!strings.EqualFold(argv[9], "/f") {
		return "", false
	}
	path, value := strings.ToLower(argv[2]), strings.ToLower(argv[4])
	if strings.HasPrefix(path, strings.ToLower(`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`)) {
		return EndpointDefenderExclusionRequested, true
	}
	if (strings.HasSuffix(path, `\defenderapilogger`) || strings.HasSuffix(path, `\defenderauditlogger`)) && value == "start" {
		return EndpointDefenderLoggingDisableRequested, true
	}
	return "", false
}

// ExactEndpointSecurityControlLineageOperation returns a request/completion
// role only when an exact process identity is available for a bounded join.
func ExactEndpointSecurityControlLineageOperation(facts Facts) (EndpointSecurityControlMutation, string, bool) {
	items := ExactEndpointSecurityControlMutations(facts)
	if len(items) != 1 || !validPrivateDigest(items[0].ProcessIdentityDigest) {
		return "", "", false
	}
	return items[0].Operation, items[0].ProcessIdentityDigest, true
}

func exactEndpointSecurityControlMutationInput(raw []byte) (EndpointSecurityControlMutation, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || !exactObjectKeys(object, endpointSecurityEventKeys) {
		return "", false
	}
	provider, eventID := exactString(object["provider"]), exactString(object["event_id"])
	if provider == "Microsoft-Windows-Windows Defender" && eventID == "5007" {
		value := exactString(object["new_value"])
		prefix := `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\`
		if strings.HasPrefix(value, prefix) && len(value) > len(prefix)+len(" = 0x0") && strings.HasSuffix(value, " = 0x0") {
			return EndpointDefenderExclusionAdded, true
		}
	}
	if provider != "Microsoft-Windows-Sysmon" || eventID != "13" || exactString(object["operation"]) != "SetValue" {
		return "", false
	}
	resource, details := exactString(object["resource"]), exactString(object["details"])
	exclusionPrefix := `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths\`
	if strings.HasPrefix(resource, exclusionPrefix) && len(resource) > len(exclusionPrefix) && (details == "0" || details == "DWORD (0x00000000)") {
		return EndpointDefenderExclusionAdded, true
	}
	for _, logger := range []string{"DefenderApiLogger", "DefenderAuditLogger"} {
		prefix := `HKLM\System\CurrentControlSet\Control\WMI\Autologger\` + logger + `\`
		if strings.HasPrefix(resource, prefix) && (strings.HasSuffix(resource, `\Start`) || strings.HasSuffix(resource, `\Enabled`)) &&
			details == "DWORD (0x00000000)" {
			return EndpointDefenderLoggingDisabled, true
		}
	}
	return "", false
}
