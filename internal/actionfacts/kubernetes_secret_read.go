// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

const kubernetesSecretReadIdentityDomain = "defenseclaw/actionfacts/kubernetes-secret-read/v1"

// KubernetesSecretContentReadFact is the value-safe result of an exact,
// content-revealing read of one named Kubernetes Secret. The digest binds the
// literal kubeconfig context (when supplied), namespace (when supplied), and
// Secret name. Raw identities and output selectors are deliberately discarded.
type KubernetesSecretContentReadFact struct {
	SecretIdentityDigest string `json:"-"`
}

// ExactKubernetesSecretContentRead proves that an authoritative direct kubectl
// action reads the content of exactly one statically named Secret. Callers must
// pass the Facts produced by Analyze for the same input. The grammar is closed:
// unsupported flags, wrappers, selectors, dynamic values, or ambiguous sources
// cause the extractor to abstain.
func ExactKubernetesSecretContentRead(
	input Input,
	facts Facts,
) (KubernetesSecretContentReadFact, bool) {
	if !facts.Authoritative() {
		return KubernetesSecretContentReadFact{}, false
	}
	argv, schemaNamespace, ok := exactKubectlArgv(input, facts)
	if !ok {
		return KubernetesSecretContentReadFact{}, false
	}
	context, namespace, secret, ok := exactNamedKubernetesSecretRead(
		argv,
		schemaNamespace,
	)
	if !ok {
		return KubernetesSecretContentReadFact{}, false
	}
	digest := framedPrivateDigest(
		kubernetesSecretReadIdentityDomain,
		context,
		namespace,
		secret,
	)
	if !validPrivateDigest(digest) {
		return KubernetesSecretContentReadFact{}, false
	}
	return KubernetesSecretContentReadFact{SecretIdentityDigest: digest}, true
}

func exactNamedKubernetesSecretRead(
	argv []string,
	schemaNamespace string,
) (context, namespace, secret string, ok bool) {
	if len(argv) < 5 || path.Base(argv[0]) != "kubectl" ||
		(schemaNamespace != "" && !exactKubernetesIdentity(schemaNamespace)) {
		return "", "", "", false
	}

	namespace = schemaNamespace
	namespaceFlagSeen := false
	contextSeen := false
	outputSeen := false
	positionals := make([]string, 0, 3)
	for index := 1; index < len(argv); index++ {
		argument := argv[index]
		key, value, joined := strings.Cut(argument, "=")
		switch key {
		case "-n", "--namespace":
			if namespaceFlagSeen ||
				(!joined && !takeKubernetesOptionValue(argv, &index, &value)) ||
				!exactKubernetesIdentity(value) ||
				(namespace != "" && namespace != value) {
				return "", "", "", false
			}
			namespaceFlagSeen = true
			namespace = value
		case "--context":
			if contextSeen ||
				(!joined && !takeKubernetesOptionValue(argv, &index, &value)) ||
				!exactKubernetesSecretContext(value) {
				return "", "", "", false
			}
			contextSeen = true
			context = value
		case "-o", "--output":
			if outputSeen ||
				(!joined && !takeKubernetesOptionValue(argv, &index, &value)) ||
				!exactKubernetesSecretRevealingOutput(value) {
				return "", "", "", false
			}
			outputSeen = true
		default:
			if argument == "" || strings.HasPrefix(argument, "-") {
				return "", "", "", false
			}
			positionals = append(positionals, argument)
			if len(positionals) > 3 {
				return "", "", "", false
			}
		}
	}
	if !outputSeen || len(positionals) != 3 || positionals[0] != "get" ||
		(positionals[1] != "secret" && positionals[1] != "secrets") ||
		!exactKubernetesIdentity(positionals[2]) {
		return "", "", "", false
	}
	return context, namespace, positionals[2], true
}

func exactKubernetesSecretContext(value string) bool {
	if !exactKubernetesOptionValue(value) ||
		strings.HasPrefix(value, "-") ||
		len(value) > kubernetesIdentityMaxScalar {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("._-:/@+", character) {
			continue
		}
		return false
	}
	return true
}

func exactKubernetesSecretRevealingOutput(value string) bool {
	switch value {
	case "json", "yaml":
		return true
	}
	format, selector, found := strings.Cut(value, "=")
	if !found || selector == "" {
		return false
	}
	switch format {
	case "jsonpath":
		return exactKubernetesSecretJSONPath(selector)
	case "go-template":
		return exactKubernetesSecretGoTemplate(selector)
	default:
		return false
	}
}

func exactKubernetesSecretJSONPath(selector string) bool {
	if len(selector) < 3 || selector[0] != '{' ||
		selector[len(selector)-1] != '}' {
		return false
	}
	body := selector[1 : len(selector)-1]
	return strings.TrimSpace(body) == body &&
		exactKubernetesSecretDataPath(body)
}

func exactKubernetesSecretGoTemplate(selector string) bool {
	if len(selector) < 5 || !strings.HasPrefix(selector, "{{") ||
		!strings.HasSuffix(selector, "}}") {
		return false
	}
	body := strings.TrimSpace(selector[2 : len(selector)-2])
	return body != "" && exactKubernetesSecretDataPath(body)
}

func exactKubernetesSecretDataPath(value string) bool {
	for _, root := range []string{".data", ".stringData"} {
		if value == root {
			return true
		}
		if !strings.HasPrefix(value, root+".") {
			continue
		}
		key := strings.TrimPrefix(value, root+".")
		if key == "" || len(key) > kubernetesIdentityMaxScalar {
			return false
		}
		for _, character := range key {
			if character >= 'a' && character <= 'z' ||
				character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' ||
				character == '-' || character == '_' {
				continue
			}
			return false
		}
		return true
	}
	return false
}
