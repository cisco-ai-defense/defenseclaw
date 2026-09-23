// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// projectCloudMetadataCredentialReads recognizes only the closed
// cloud_metadata(provider,path) contract observed in the public agentic
// red-team corpus. General instance metadata remains outside this proof.
func projectCloudMetadataCredentialReads(input Input) []CloudMetadataCredentialReadFact {
	if input.Tool != "cloud_metadata" || input.Command != "" || len(input.Argv) != 0 {
		return nil
	}
	provider, rawPath, ok := exactCloudMetadataInput(input.Args)
	if !ok {
		return nil
	}
	if !exactCloudMetadataCredentialPath(provider, rawPath) {
		return nil
	}
	return []CloudMetadataCredentialReadFact{{Provider: provider}}
}

func exactCloudMetadataInput(raw []byte) (string, string, bool) {
	object, problem := exactJSONObject(raw)
	if problem.status != "" || len(object) != 2 {
		return "", "", false
	}
	provider, providerOK := object["provider"].(string)
	rawPath, pathOK := object["path"].(string)
	if !providerOK || !pathOK || strings.TrimSpace(provider) != provider ||
		strings.TrimSpace(rawPath) != rawPath || rawPath == "" ||
		validateScalar(rawPath, maxScalarBytes) != "" ||
		strings.ContainsAny(rawPath, "\\#\r\n\x00") {
		return "", "", false
	}
	if provider != "aws" && provider != "gcp" && provider != "azure" {
		return "", "", false
	}
	for key := range object {
		if key != "provider" && key != "path" {
			return "", "", false
		}
	}
	return provider, rawPath, true
}

func exactCloudMetadataCredentialPath(provider, rawPath string) bool {
	pathPart, _, _ := strings.Cut(rawPath, "?")
	pathPart = strings.TrimPrefix(pathPart, "/")
	if pathPart == "" || strings.Contains(pathPart, "//") || strings.Contains(pathPart, "..") {
		return false
	}
	switch provider {
	case "aws":
		return exactMetadataPathPrefix(pathPart, "latest/meta-data/iam/security-credentials") ||
			exactMetadataPathPrefix(pathPart, "iam/security-credentials")
	case "gcp":
		return exactMetadataTokenSuffix(pathPart, "computeMetadata/v1/instance/service-accounts/") ||
			exactMetadataTokenSuffix(pathPart, "instance/service-accounts/")
	case "azure":
		return pathPart == "metadata/identity/oauth2/token" ||
			pathPart == "identity/oauth2/token"
	default:
		return false
	}
}

func exactMetadataPathPrefix(pathPart, prefix string) bool {
	if !strings.HasPrefix(pathPart, prefix+"/") {
		return false
	}
	role := strings.TrimPrefix(pathPart, prefix+"/")
	return exactMetadataIdentity(role)
}

func exactMetadataTokenSuffix(pathPart, prefix string) bool {
	if !strings.HasPrefix(pathPart, prefix) || !strings.HasSuffix(pathPart, "/token") {
		return false
	}
	identity := strings.TrimSuffix(strings.TrimPrefix(pathPart, prefix), "/token")
	return exactMetadataIdentity(identity)
}

func exactMetadataIdentity(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("._@-", character) {
			continue
		}
		return false
	}
	return true
}

// ExactCloudMetadataCredentialRead returns the provider class only when one
// exact structured metadata-token read was projected.
func ExactCloudMetadataCredentialRead(facts Facts) (string, bool) {
	if facts.Parse.Status != StatusComplete || len(facts.CloudMetadataCredentialReads) != 1 {
		return "", false
	}
	provider := facts.CloudMetadataCredentialReads[0].Provider
	return provider, provider == "aws" || provider == "gcp" || provider == "azure"
}
