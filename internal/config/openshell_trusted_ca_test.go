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

package config

import (
	"strings"
	"testing"
)

// openshell.trusted_ca_bundle (#1296): an absolute or ~/ path in a per-user
// configuration, an absolute one in a managed configuration.
func TestOpenShellTrustedCABundleValidation(t *testing.T) {
	for _, p := range []string{"", "/etc/defenseclaw/corp.pem", "~/certs/corp.pem"} {
		o := OpenShellConfig{TrustedCABundle: p}
		if err := o.Validate(); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"corp.pem", "~alice/corp.pem", " /etc/corp.pem", "/etc/corp.pem\n", "/" + strings.Repeat("a", 4096)} {
		o := OpenShellConfig{TrustedCABundle: p}
		if err := o.Validate(); err == nil || !strings.Contains(err.Error(), "trusted_ca_bundle") {
			t.Errorf("%q: %v", p, err)
		}
	}
	c := &Config{DeploymentMode: string(DeploymentModeManagedEnterprise)}
	c.OpenShell.TrustedCABundle = "~/corp.pem"
	if err := c.ValidateOpenShell(); err == nil || !strings.Contains(err.Error(), "administrator-owned") {
		t.Fatalf("managed ~ path: %v", err)
	}
	c.OpenShell.TrustedCABundle = "/etc/defenseclaw/corp.pem"
	if err := c.validateManagedTrustedCABundle(); err != nil {
		t.Fatalf("managed absolute path: %v", err)
	}
	c.DeploymentMode = ""
	c.OpenShell.TrustedCABundle = "~/corp.pem"
	if err := c.validateManagedTrustedCABundle(); err != nil {
		t.Fatalf("per-user ~ path: %v", err)
	}
}
