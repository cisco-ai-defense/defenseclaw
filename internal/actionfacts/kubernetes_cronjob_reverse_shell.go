// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"path"
	"strings"
)

const kubernetesCronJobReverseShellDomain = "defenseclaw/actionfacts/kubernetes-cronjob-reverse-shell/v1"

// ExactKubernetesCronJobReverseShell returns one value-free exact operation.
func ExactKubernetesCronJobReverseShell(
	facts Facts,
) (KubernetesCronJobReverseShellFact, bool) {
	if len(facts.KubernetesCronJobReverseShells) != 1 {
		return KubernetesCronJobReverseShellFact{}, false
	}
	fact := facts.KubernetesCronJobReverseShells[0]
	if !validPrivateDigest(fact.CronJobIdentityDigest) {
		return KubernetesCronJobReverseShellFact{}, false
	}
	return fact, true
}

func projectKubernetesCronJobReverseShells(
	input Input,
	_ Facts,
) []KubernetesCronJobReverseShellFact {
	if !strings.EqualFold(input.Tool, "kubectl") {
		return nil
	}
	argv, namespace, ok := exactKubernetesCronJobReverseShellArgv(input.Args)
	if !ok {
		return nil
	}
	name, ok := exactKubernetesCronJobReverseShellCreate(argv)
	if !ok {
		return nil
	}
	if namespace == "" {
		namespace = "default"
	}
	return []KubernetesCronJobReverseShellFact{{
		CronJobIdentityDigest: framedPrivateDigest(
			kubernetesCronJobReverseShellDomain,
			namespace,
			name,
		),
	}}
}

func exactKubernetesCronJobReverseShellInputSchema(raw json.RawMessage) bool {
	argv, _, ok := exactKubernetesCronJobReverseShellArgv(raw)
	if !ok {
		return false
	}
	_, ok = exactKubernetesCronJobReverseShellCreate(argv)
	return ok
}

func exactKubernetesCronJobReverseShellArgv(
	raw json.RawMessage,
) ([]string, string, bool) {
	command, schemaNamespace, ok := exactStructuredKubectlInput(raw)
	if !ok {
		return nil, "", false
	}
	parsed := parsePOSIX("kubectl "+command, 1, 0)
	projected := parsed.factsWithContext("kubectl", "", "")
	// A bare sh/bash after `--` may be projected as a child command by the
	// generic classifier. The root kubectl argv remains the authority boundary;
	// the payload is independently required to contain exactly one proved
	// reverse-shell statement below.
	if !projected.Authoritative() || len(projected.Commands) == 0 ||
		!exactDirectKubectlCommand(projected.Commands[0]) {
		return nil, "", false
	}
	return stripExactKubectlNamespace(projected.Commands[0].Argv, schemaNamespace)
}

func exactKubernetesCronJobReverseShellCreate(argv []string) (string, bool) {
	if len(argv) < 10 || path.Base(argv[0]) != "kubectl" ||
		argv[1] != "create" || argv[2] != "cronjob" ||
		!exactKubernetesCronJobName(argv[3]) {
		return "", false
	}
	separator := -1
	imageSeen := false
	scheduleSeen := false
	for index := 4; index < len(argv); index++ {
		argument := argv[index]
		if argument == "--" {
			separator = index
			break
		}
		key, value, inline := strings.Cut(argument, "=")
		switch key {
		case "--image":
			if imageSeen || !inline || !exactKubernetesCronJobImage(value) {
				return "", false
			}
			imageSeen = true
		case "--schedule":
			if scheduleSeen || !inline || !exactKubernetesCronJobSchedule(value) {
				return "", false
			}
			scheduleSeen = true
		default:
			// This excludes dry-run, interactive/attach flags, wrappers, output
			// transformations, and every unreviewed create option.
			return "", false
		}
	}
	if !imageSeen || !scheduleSeen || separator < 0 || len(argv) != separator+4 {
		return "", false
	}
	shell := argv[separator+1]
	if shell != "sh" && shell != "bash" && shell != "/bin/sh" && shell != "/bin/bash" {
		return "", false
	}
	if argv[separator+2] != "-c" ||
		!exactAuthoritativePOSIXReverseShellCommand(argv[separator+3]) {
		return "", false
	}
	return argv[3], true
}

func exactKubernetesCronJobImage(value string) bool {
	return value != "" && len(value) <= maxScalarBytes &&
		strings.TrimSpace(value) == value && !hasUnresolvedPathSyntax(value) &&
		!strings.ContainsAny(value, "'\"`;|&<>(){}[]")
}

func exactKubernetesCronJobSchedule(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value ||
		hasUnresolvedPathSyntax(value) || strings.ContainsAny(value, "\r\n;|&`<>(){}") {
		return false
	}
	fields := strings.Fields(value)
	return len(fields) == 5 && strings.Join(fields, " ") == value
}
