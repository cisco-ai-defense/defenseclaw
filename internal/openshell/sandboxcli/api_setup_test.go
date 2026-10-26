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
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
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

func TestAPIErrorKeepsUnreachableTransportCause(t *testing.T) {
	previous := onManagedHost
	t.Cleanup(func() { onManagedHost = previous })
	transport := &sandboxapi.Error{Code: sandboxapi.CodeUnavailable,
		Message: "the DefenseClaw daemon is not reachable",
		Detail:  "connected gateway socket belongs to another account"}
	for _, managed := range []bool{false, true} {
		onManagedHost = func() bool { return managed }
		got := apiError(transport).Error()
		if !strings.Contains(got, transport.Detail) {
			t.Errorf("managed=%t: lost transport cause: %q", managed, got)
		}
		if strings.Contains(got, "daemon is not running") {
			t.Errorf("managed=%t: guessed a stopped daemon despite peer error: %q", managed, got)
		}
		if managed && strings.Contains(got, "defenseclaw-gateway start") {
			t.Errorf("managed host offered a per-user gateway command: %q", got)
		}
	}
}

// GAP-1693: a sandbox command the gateway's caller limit refused (429) says
// so in its own words: a limit on this account's requests in a short time,
// to retry in a few seconds, never the hook-request words of the limiter.
func TestAPIErrorWordsTheCallerLimitForTheCLI(t *testing.T) {
	limited := &sandboxapi.Error{Code: "rate_limited", Status: http.StatusTooManyRequests,
		Message: "DefenseClaw is limiting the hook requests of this account; retry shortly"}
	got := apiError(limited).Error()
	if strings.Contains(got, "hook") || !strings.Contains(got, "a burst of sandbox commands") || !strings.Contains(got, "in a few seconds") {
		t.Fatalf("limited sandbox command = %q", got)
	}
	// As the managed daemon relays it: the limiter's word is the reason.
	relayed := &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusTooManyRequests,
		Message: "DefenseClaw is limiting the hook requests of this account; retry shortly", Detail: "rate_limited"}
	if got := apiError(relayed).Error(); strings.Contains(got, "hook") || !strings.Contains(got, "a burst of sandbox commands") {
		t.Fatalf("relayed caller limit = %q", got)
	}
	// GAP-1808: the daemon's own 429 keeps its words, which name the cause.
	streams := &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Status: http.StatusTooManyRequests, Message: "too many activity streams are open"}
	if got := apiError(streams).Error(); !strings.Contains(got, "too many activity streams are open") || strings.Contains(got, "a burst of sandbox commands") {
		t.Fatalf("too many activity streams = %q", got)
	}
}

// r103 GAP-0332: on a Linux computer without Docker or KVM, `sandbox run`
// said only that sandboxes are off and to run setup; the doctor alone named
// the missing Docker. The refusal names it too.
func TestDisabledRefusalNamesAMissingSandboxRuntime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the hint is for Linux computers")
	}
	prevManaged, prevRuntime := onManagedHost, hostHasSandboxRuntime
	t.Cleanup(func() { onManagedHost, hostHasSandboxRuntime = prevManaged, prevRuntime })
	onManagedHost = func() bool { return false }
	off := &sandboxapi.Error{Code: sandboxapi.CodeDisabled, Message: sandboxapi.DisabledMessage}
	for _, has := range []bool{false, true} {
		hostHasSandboxRuntime = func() bool { return has }
		var disabled *DisabledError
		if err := apiError(off); !errors.As(err, &disabled) {
			t.Fatalf("apiError = %v, want a DisabledError", err)
		}
		named := strings.Contains(disabled.Message, "lacks Docker") && strings.Contains(disabled.Message, "sandbox doctor")
		if !strings.HasPrefix(disabled.Message, sandboxapi.DisabledMessage) || named == has {
			t.Fatalf("runtime present %t: message %q", has, disabled.Message)
		}
	}
}
