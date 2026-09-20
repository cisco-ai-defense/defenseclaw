// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	kubernetesBatchSecretCollectionMin  = 3
	kubernetesBatchSecretCollectionMax  = 16
	kubernetesBatchSecretNamespaceMax   = 8
	kubernetesBatchSecretResourceDomain = "defenseclaw/actionfacts/kubernetes-batch-secret-resource/v1"
	kubernetesBatchSecretTool           = "k8s.get_secrets_batch"
)

// KubernetesBatchSecretCollectionFact retains no Secret, namespace, cluster,
// or tool-resource value. It proves only bounded cardinalities and an opaque
// authenticated resource/cluster identity.
type KubernetesBatchSecretCollectionFact struct {
	DistinctSecretCount        int    `json:"-"`
	DistinctNamespaceCount     int    `json:"-"`
	ToolResourceIdentityDigest string `json:"-"`
}

// ExactKubernetesBatchSecretCollection accepts only k8s.get_secrets_batch with
// the audited four-key schema {cluster, namespaces, secret_names,
// decode_base64}. All identities must be canonical literals and decode_base64
// must be the boolean true.
func ExactKubernetesBatchSecretCollection(input Input) (KubernetesBatchSecretCollectionFact, bool) {
	if input.Tool != kubernetesBatchSecretTool || input.Command != "" || len(input.Argv) != 0 ||
		!validTrustedToolResourceIdentity(input.ToolResourceIdentity) {
		return KubernetesBatchSecretCollectionFact{}, false
	}
	parsed, ok := exactKubernetesBatchSecretCollectionArgs(input.Args)
	if !ok {
		return KubernetesBatchSecretCollectionFact{}, false
	}
	digest := framedPrivateDigest(
		kubernetesBatchSecretResourceDomain,
		input.ToolResourceIdentity,
		parsed.cluster,
	)
	if !validPrivateDigest(digest) {
		return KubernetesBatchSecretCollectionFact{}, false
	}
	return KubernetesBatchSecretCollectionFact{
		DistinctSecretCount:        parsed.secretCount,
		DistinctNamespaceCount:     parsed.namespaceCount,
		ToolResourceIdentityDigest: digest,
	}, true
}

type exactKubernetesBatchSecretCollectionInput struct {
	cluster        string
	secretCount    int
	namespaceCount int
}

func exactKubernetesBatchSecretCollectionArgs(
	raw json.RawMessage,
) (exactKubernetesBatchSecretCollectionInput, bool) {
	empty := exactKubernetesBatchSecretCollectionInput{}
	if len(raw) == 0 || len(raw) > maxArgsJSONBytes || !utf8.Valid(raw) ||
		validateJSONWithStringLimit(raw, kubernetesIdentityMaxScalar) != "" {
		return empty, false
	}
	var object map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&object); err != nil || len(object) != 4 {
		return empty, false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return empty, false
	}
	cluster, clusterOK := object["cluster"].(string)
	decode, decodeOK := object["decode_base64"].(bool)
	rawNames, namesOK := object["secret_names"].([]any)
	rawNamespaces, namespacesOK := object["namespaces"].([]any)
	if !clusterOK || !exactCanonicalKubernetesSecretName(cluster) ||
		!decodeOK || !decode || !namesOK || !namespacesOK ||
		len(rawNames) < kubernetesBatchSecretCollectionMin ||
		len(rawNames) > kubernetesBatchSecretCollectionMax ||
		len(rawNamespaces) == 0 || len(rawNamespaces) > kubernetesBatchSecretNamespaceMax {
		return empty, false
	}
	for key := range object {
		if key != "cluster" && key != "namespaces" &&
			key != "decode_base64" && key != "secret_names" {
			return empty, false
		}
	}
	distinctNames := make(map[string]struct{}, len(rawNames))
	for _, rawName := range rawNames {
		name, literal := rawName.(string)
		if !literal || !exactCanonicalKubernetesSecretName(name) {
			return empty, false
		}
		if _, duplicate := distinctNames[name]; duplicate {
			return empty, false
		}
		distinctNames[name] = struct{}{}
	}
	distinctNamespaces := make(map[string]struct{}, len(rawNamespaces))
	for _, rawNamespace := range rawNamespaces {
		namespace, literal := rawNamespace.(string)
		if !literal || !exactCanonicalKubernetesNamespace(namespace) {
			return empty, false
		}
		if _, duplicate := distinctNamespaces[namespace]; duplicate {
			return empty, false
		}
		distinctNamespaces[namespace] = struct{}{}
	}
	return exactKubernetesBatchSecretCollectionInput{
		cluster:        cluster,
		secretCount:    len(distinctNames),
		namespaceCount: len(distinctNamespaces),
	}, true
}

func exactCanonicalKubernetesSecretName(value string) bool {
	if !exactKubernetesIdentity(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !kubernetesDNSLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func exactCanonicalKubernetesNamespace(value string) bool {
	return value != "" && len(value) <= 63 && strings.ToLower(value) == value &&
		kubernetesDNSLabelPattern.MatchString(value)
}
