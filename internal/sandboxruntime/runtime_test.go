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

package sandboxruntime

import "testing"

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"": OpenShell, "openshell": OpenShell, " OpenShell ": OpenShell,
		"substrate": Substrate, "SUBSTRATE": Substrate,
		"docker": "", "kata": "", "openshell2": "",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

// The OpenShell default stays host.openshell.internal; Substrate has none.
func TestDefaultIngressHost(t *testing.T) {
	if got := DefaultIngressHost(""); got != "host.openshell.internal" {
		t.Errorf("default = %q", got)
	}
	if got := DefaultIngressHost(OpenShell); got != OpenShellHostAlias {
		t.Errorf("openshell = %q", got)
	}
	if got := DefaultIngressHost(Substrate); got != "" {
		t.Errorf("substrate = %q, want none", got)
	}
	if got := DefaultIngressHost("other"); got != "" {
		t.Errorf("unknown = %q, want none", got)
	}
}

func TestIsOpenShellHostAlias(t *testing.T) {
	for host, want := range map[string]bool{
		"host.openshell.internal": true, "HOST.OpenShell.Internal": true, "host.openshell.internal.": true,
		"host.openshell.internal.example": false, "openshell.internal": false, "": false,
		"defenseclaw-actor.defenseclaw-system.svc": false,
	} {
		if got := IsOpenShellHostAlias(host); got != want {
			t.Errorf("IsOpenShellHostAlias(%q) = %t", host, got)
		}
	}
}
