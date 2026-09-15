// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const (
	kubernetesSecretResource        = "secrets"
	kubernetesWorkloadTokenResource = "workload_identity_token"
)

// ExactKubernetesSensitiveAccess returns one closed, value-free Kubernetes
// access fact. Cluster-wide Secret enumeration is intentionally an alert-only
// capability signal; authorization requires deployment policy or a later
// exact source/sink proof.
func ExactKubernetesSensitiveAccess(
	facts Facts,
) (KubernetesSensitiveAccessFact, bool) {
	if len(facts.KubernetesSensitiveAccesses) != 1 {
		return KubernetesSensitiveAccessFact{}, false
	}
	fact := facts.KubernetesSensitiveAccesses[0]
	if fact.Resource != kubernetesSecretResource || !fact.AllNamespaces {
		return KubernetesSensitiveAccessFact{}, false
	}
	return fact, true
}

// ExactKubernetesWorkloadIdentityTokenRead proves a direct structured
// `kubectl exec` whose remote command is exactly `cat` of the canonical
// Kubernetes service-account token. It retains no namespace, pod, or token
// value and is advisory because administrators may legitimately inspect it.
func ExactKubernetesWorkloadIdentityTokenRead(facts Facts) bool {
	return len(facts.KubernetesSensitiveAccesses) == 1 &&
		facts.KubernetesSensitiveAccesses[0].Resource == kubernetesWorkloadTokenResource &&
		!facts.KubernetesSensitiveAccesses[0].AllNamespaces &&
		!facts.KubernetesSensitiveAccesses[0].TokenProvided
}

func projectKubernetesSensitiveAccesses(
	input Input,
	facts Facts,
) []KubernetesSensitiveAccessFact {
	argv, schemaNamespace, ok := exactKubectlArgv(input, facts)
	if !ok {
		return nil
	}
	argv, _, ok = stripExactKubectlNamespace(argv, schemaNamespace)
	if !ok {
		return nil
	}
	if fact, matched := exactKubectlClusterWideSecretEnumeration(argv); matched {
		return []KubernetesSensitiveAccessFact{fact}
	}
	if exactKubectlWorkloadIdentityTokenRead(argv) {
		return []KubernetesSensitiveAccessFact{{Resource: kubernetesWorkloadTokenResource}}
	}
	return nil
}

func exactKubectlWorkloadIdentityTokenRead(argv []string) bool {
	if len(argv) != 6 || argv[0] != "kubectl" || argv[1] != "exec" ||
		!exactKubernetesIdentity(argv[2]) || argv[3] != "--" || argv[4] != "cat" {
		return false
	}
	switch argv[5] {
	case "/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token":
		return true
	default:
		return false
	}
}

func exactKubectlClusterWideSecretEnumeration(
	argv []string,
) (KubernetesSensitiveAccessFact, bool) {
	if len(argv) < 4 || argv[0] != "kubectl" || argv[1] != "get" ||
		(argv[2] != "secret" && argv[2] != "secrets") {
		return KubernetesSensitiveAccessFact{}, false
	}
	fact := KubernetesSensitiveAccessFact{Resource: kubernetesSecretResource}
	seen := map[string]bool{}
	for index := 3; index < len(argv); index++ {
		argument := argv[index]
		key, value, joined := strings.Cut(argument, "=")
		switch key {
		case "-A", "--all-namespaces":
			if seen["all-namespaces"] || joined && value != "true" {
				return KubernetesSensitiveAccessFact{}, false
			}
			seen["all-namespaces"] = true
			fact.AllNamespaces = true
		case "-o", "--output":
			if seen["output"] || !joined && !takeKubernetesOptionValue(argv, &index, &value) ||
				!exactKubernetesOutputFormat(value) {
				return KubernetesSensitiveAccessFact{}, false
			}
			seen["output"] = true
		case "--field-selector", "--selector", "-l":
			if seen["selector"] || !joined && !takeKubernetesOptionValue(argv, &index, &value) ||
				!exactKubernetesOptionValue(value) {
				return KubernetesSensitiveAccessFact{}, false
			}
			seen["selector"] = true
		case "--context":
			if seen["context"] || !joined && !takeKubernetesOptionValue(argv, &index, &value) ||
				!exactKubernetesOptionValue(value) {
				return KubernetesSensitiveAccessFact{}, false
			}
			seen["context"] = true
		case "--token":
			if seen["token"] || !joined && !takeKubernetesOptionValue(argv, &index, &value) ||
				!exactKubernetesOptionValue(value) {
				return KubernetesSensitiveAccessFact{}, false
			}
			seen["token"] = true
			fact.TokenProvided = true
		default:
			return KubernetesSensitiveAccessFact{}, false
		}
	}
	return fact, fact.AllNamespaces
}

func takeKubernetesOptionValue(argv []string, index *int, value *string) bool {
	if index == nil || value == nil || *index+1 >= len(argv) {
		return false
	}
	(*index)++
	*value = argv[*index]
	return true
}

func exactKubernetesOptionValue(value string) bool {
	return value != "" && len(value) <= maxScalarBytes &&
		strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\x00\r\n") &&
		!hasUnresolvedPathSyntax(value)
}

func exactKubernetesOutputFormat(value string) bool {
	switch strings.ToLower(value) {
	case "json", "yaml", "name", "wide":
		return true
	default:
		return false
	}
}
