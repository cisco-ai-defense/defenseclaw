// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

const (
	CredentialFileUploadStrong          = "strong_credential_file"
	CredentialFileUploadKubeAdminConfig = "kubernetes_admin_config"
)

// ExactCredentialFileUploads returns a defensive copy of value-free facts.
func ExactCredentialFileUploads(facts Facts) []CredentialFileUploadFact {
	return append([]CredentialFileUploadFact(nil), facts.CredentialFileUploads...)
}

func projectCredentialFileUploads(facts Facts) []CredentialFileUploadFact {
	if !facts.Authoritative() {
		return nil
	}
	seen := make(map[CredentialFileUploadFact]struct{})
	result := make([]CredentialFileUploadFact, 0, 1)
	for _, command := range facts.Commands {
		if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
			command.ControlFlowUncertain || command.Program != "curl" {
			continue
		}
		for _, source := range StaticCurlDirectUploadFileSources(command) {
			class := credentialFileUploadClass(source.Path)
			if class == "" {
				continue
			}
			fact := CredentialFileUploadFact{CommandID: command.ID, Class: class}
			if _, duplicate := seen[fact]; duplicate {
				continue
			}
			seen[fact] = struct{}{}
			result = append(result, fact)
		}
	}
	return result
}

func credentialFileUploadClass(value string) string {
	if value == "" || !strings.HasPrefix(value, "/") || hasUnresolvedPathSyntax(value) {
		return ""
	}
	canonical := strings.ToLower(path.Clean(value))
	base := path.Base(canonical)
	if base == "jenkins.cookies" || base == "sa.token" ||
		canonical == "/var/run/secrets/kubernetes.io/serviceaccount/token" ||
		strings.HasSuffix(canonical, "/.aws/credentials") ||
		strings.HasSuffix(canonical, "/.git-credentials") ||
		strings.HasSuffix(canonical, "/.netrc") ||
		strings.HasSuffix(canonical, "/.npmrc") ||
		strings.HasSuffix(canonical, "/.pypirc") ||
		strings.HasSuffix(canonical, "/.kube/config") ||
		strings.Contains(canonical, "/.ssh/") && strings.HasPrefix(base, "id_") &&
			!strings.HasSuffix(base, ".pub") {
		return CredentialFileUploadStrong
	}
	if base == "admin.conf" {
		return CredentialFileUploadKubeAdminConfig
	}
	return ""
}
