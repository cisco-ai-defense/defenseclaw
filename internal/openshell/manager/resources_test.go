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

package manager

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestStartRefusesLimitsAboveALowerMaximum pins that a sandbox whose
// template limits (fixed at create) exceed the organization's lowered or
// newly set max_resources is reported and refused a start, and one within
// the cap starts.
func TestStartRefusesLimitsAboveALowerMaximum(t *testing.T) {
	for _, tc := range []struct {
		name   string
		memory string
		max    config.OpenShellResourcesConfig
		refuse bool
	}{
		{"lowered below the limit", "4Gi", config.OpenShellResourcesConfig{Memory: "2Gi"}, true},
		{"set over an unlimited sandbox", "", config.OpenShellResourcesConfig{CPU: "2"}, true},
		{"within the cap", "1Gi", config.OpenShellResourcesConfig{Memory: "2Gi"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			sb := e.create(sandboxapi.CreateRequest{Name: "resbox", Memory: tc.memory})
			if _, err := e.m.Stop(ctx, sb.Name); err != nil {
				t.Fatal(err)
			}
			e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MaxResources = tc.max })
			got, err := e.m.Get(ctx, sb.Name)
			if err != nil {
				t.Fatal(err)
			}
			warned := findWarning(got.Warnings, "your organization now caps sandbox") != ""
			_, err = e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{})
			if !tc.refuse {
				if err != nil || warned {
					t.Fatalf("start = %v, warned %v; want it started", err, warned)
				}
				return
			}
			if !warned {
				t.Fatalf("no drift warning: %q", got.Warnings)
			}
			apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
			if apiErr.Violation == nil || !strings.HasPrefix(apiErr.Violation.Key, "resources.") {
				t.Fatalf("violation = %+v", apiErr.Violation)
			}
		})
	}
}

func TestResourceViolation(t *testing.T) {
	if v := resourceViolation(nil, config.OpenShellResourcesConfig{CPU: "1"}); v != nil {
		t.Fatalf("a record without limits was judged: %+v", v)
	}
	if v := resourceViolation(&packs.Resources{CPU: "500m"}, config.OpenShellResourcesConfig{CPU: "1"}); v != nil {
		t.Fatalf("a limit within the cap = %+v", v)
	}
	if v := resourceViolation(&packs.Resources{CPU: "2"}, config.OpenShellResourcesConfig{CPU: "1"}); v == nil || v.Key != "resources.cpu" || !v.Admin() {
		t.Fatalf("a limit over the cap = %+v", v)
	}
}
