// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestCloudMetadataCredentialReadClosedSchema(t *testing.T) {
	positives := []struct {
		provider string
		path     string
	}{
		{"aws", "/latest/meta-data/iam/security-credentials/production-role"},
		{"gcp", "/computeMetadata/v1/instance/service-accounts/default/token"},
		{"gcp", "instance/service-accounts/agent@example.test/token?scopes=cloud-platform"},
		{"azure", "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"},
	}
	for _, test := range positives {
		raw, err := json.Marshal(map[string]string{"provider": test.provider, "path": test.path})
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "cloud_metadata", Args: raw})
		provider, ok := ExactCloudMetadataCredentialRead(facts)
		if !ok || provider != test.provider || !facts.Authoritative() || len(facts.Commands) != 0 {
			t.Fatalf("provider=%s path=%q facts=%+v", test.provider, test.path, facts)
		}
	}
}

func TestCloudMetadataCredentialReadHardNegatives(t *testing.T) {
	tests := []map[string]any{
		{"provider": "aws", "path": "/latest/meta-data/instance-id"},
		{"provider": "aws", "path": "/latest/meta-data/iam/security-credentials/"},
		{"provider": "gcp", "path": "/computeMetadata/v1/project/project-id"},
		{"provider": "azure", "path": "/metadata/instance?api-version=2021-02-01"},
		{"provider": "AWS", "path": "/latest/meta-data/iam/security-credentials/role"},
		{"provider": "aws", "path": "/latest/meta-data/iam/security-credentials/../role"},
		{"provider": "gcp", "path": "/computeMetadata/v1/instance/service-accounts/default/email"},
		{"provider": "azure", "path": "/metadata/identity/oauth2/token", "future": true},
	}
	for _, object := range tests {
		raw, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		facts := Analyze(Input{Tool: "cloud_metadata", Args: raw})
		if provider, ok := ExactCloudMetadataCredentialRead(facts); ok || provider != "" ||
			len(facts.CloudMetadataCredentialReads) != 0 {
			t.Fatalf("object=%v projected=%+v", object, facts.CloudMetadataCredentialReads)
		}
	}
}
