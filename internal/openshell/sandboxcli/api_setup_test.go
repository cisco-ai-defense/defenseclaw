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

package sandboxcli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1918: before the gateway is set up there is no gateway token. The
// refusal is a DisabledError, so --json still prints JSON, and it names the
// next step in product terms.
func TestAPIBeforeGatewaySetupNamesNextStep(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	cfg := &config.Config{}
	cfg.OpenShell.Enabled = true
	_, err := (&App{Cfg: cfg}).api()
	var disabled *DisabledError
	if !errors.As(err, &disabled) {
		t.Fatalf("api() = %v, want a DisabledError", err)
	}
	if !disabled.Enabled {
		t.Fatalf("Enabled = false, want the configured openshell.enabled")
	}
	for _, want := range []string{"defenseclaw setup gateway", "defenseclaw-gateway start"} {
		if !strings.Contains(disabled.Message, want) {
			t.Fatalf("message %q does not name %q", disabled.Message, want)
		}
	}
	if strings.Contains(disabled.Message, "sandboxapi") || strings.Contains(disabled.Message, "daemon") {
		t.Fatalf("message %q uses internal terms", disabled.Message)
	}
}
