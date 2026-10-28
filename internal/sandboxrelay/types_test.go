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

package sandboxrelay

import (
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

var snakeCase = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// wireTypes are every JSON body and nested type the relay defines.
var wireTypes = []any{
	ResolveRequest{}, RunFlags{}, Resources{}, MCPServerClaim{}, OpenShellFacts{},
	ResolveResponse{}, RegistrationView{}, MCPSkip{}, BannerView{}, Refusal{},
	OperationalSettings{}, ImageSettings{}, ApprovalsSettings{}, MCPSettings{},
	DaemonSettings{}, EnterpriseOpenShell{}, HookDecision{}, BindRequest{},
	CurrentPolicy{}, DecisionRequest{}, DecisionResult{}, Decision{},
	EventBatch{}, Event{}, ExplainRequest{}, PackView{}, ErrorBody{},
}

func TestWireTagsAreSnakeCase(t *testing.T) {
	for _, v := range wireTypes {
		typ := reflect.TypeOf(v)
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag := f.Tag.Get("json")
			if tag == "" {
				t.Errorf("%s.%s has no json tag", typ.Name(), f.Name)
				continue
			}
			name := strings.Split(tag, ",")[0]
			if !snakeCase.MatchString(name) {
				t.Errorf("%s.%s json name %q is not snake_case", typ.Name(), f.Name, name)
			}
		}
	}
}

func TestTopLevelBodiesCarryVersion(t *testing.T) {
	for _, v := range []any{
		ResolveRequest{V: WireVersion}, ResolveResponse{V: WireVersion}, DaemonSettings{V: WireVersion},
		HookDecision{V: WireVersion}, BindRequest{V: WireVersion}, CurrentPolicy{V: WireVersion},
		DecisionRequest{V: WireVersion}, DecisionResult{V: WireVersion}, EventBatch{V: WireVersion},
		ExplainRequest{V: WireVersion}, RegistrationView{V: WireVersion},
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("%T: %v", v, err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("%T: %v", v, err)
		}
		if string(m["v"]) != "1" {
			t.Errorf("%T: \"v\" = %s, want 1", v, m["v"])
		}
	}
}

func TestHeaderContract(t *testing.T) {
	for name, got := range map[string]string{
		"X-DefenseClaw-Sandbox-Registration":    RegistrationHeader,
		"X-DefenseClaw-Sandbox-Profile":         ProfileHeader,
		"X-DefenseClaw-Policy-Generation":       GenerationHeader,
		"X-DefenseClaw-Sandbox-Decision":        DecisionTrailer,
		"X-DefenseClaw-Sandbox-Files":           FilesHeader,
		"X-DefenseClaw-Sandbox-Daemon-Contract": DaemonContractHeader,
		"X-DefenseClaw-Client":                  ClientHeader,
		"X-DefenseClaw-Connector":               ConnectorHeader,
		hookexec.AgentSurfaceHeader:             AgentSurfaceHeader,
	} {
		if got != name {
			t.Errorf("header constant %q, want %q", got, name)
		}
	}
	if ClientHeaderValue != "sandbox-relay" || AgentSurfaceValue != "cli" {
		t.Errorf("relay header values %q %q", ClientHeaderValue, AgentSurfaceValue)
	}
	forwarded := map[string]bool{}
	for _, h := range ForwardHeaders {
		if h != http.CanonicalHeaderKey(h) {
			t.Errorf("ForwardHeaders entry %q is not canonical", h)
		}
		if strings.HasPrefix(h, http.CanonicalHeaderKey(SandboxHeaderPrefix)) {
			t.Errorf("ForwardHeaders entry %q is under the sandbox prefix", h)
		}
		forwarded[h] = true
	}
	for _, h := range DroppedHeaders {
		if h != http.CanonicalHeaderKey(h) {
			t.Errorf("DroppedHeaders entry %q is not canonical", h)
		}
		if forwarded[h] {
			t.Errorf("%q is both forwarded and dropped", h)
		}
	}
	for _, h := range []string{RegistrationHeader, FilesHeader, ClientHeader, AgentSurfaceHeader, ConnectorHeader, DaemonContractHeader} {
		if forwarded[http.CanonicalHeaderKey(h)] {
			t.Errorf("%q must not be copied from the sandbox", h)
		}
	}
	for _, h := range ResponseHeaders {
		if h != http.CanonicalHeaderKey(h) {
			t.Errorf("ResponseHeaders entry %q is not canonical", h)
		}
	}
}

func TestReasonStatus(t *testing.T) {
	for reason, want := range map[string]int{
		ReasonRegistrationUnknown:   http.StatusNotFound,
		ReasonRegistrationRevoked:   http.StatusGone,
		ReasonRegistrationExpired:   http.StatusGone,
		ReasonConnectorMismatch:     http.StatusForbidden,
		ReasonSubjectChanged:        http.StatusConflict,
		ReasonNotAllowed:            http.StatusForbidden,
		ReasonUnavailable:           http.StatusServiceUnavailable,
		ReasonPolicyUnloadable:      http.StatusServiceUnavailable,
		ReasonRelayFilesUnsupported: http.StatusBadRequest,
		ReasonDecisionRefused:       http.StatusForbidden,
		// 403, never 404/409/410: an older daemon treats those as the end of
		// its registration (GAP-0182).
		ReasonDaemonOutdated:              http.StatusForbidden,
		DetailSetupChanging:               http.StatusServiceUnavailable,
		"enterprise_managed_rate_limited": 0,
	} {
		if got := ReasonStatus(reason); got != want {
			t.Errorf("ReasonStatus(%q) = %d, want %d", reason, got, want)
		}
	}
}

// A trailer with every string at its truncation bound fits the trailer
// budget.
func TestHookDecisionBound(t *testing.T) {
	s := strings.Repeat("a", MaxHookDecisionStringBytes)
	d := HookDecision{
		V: WireVersion, Event: s, Tool: s, ToolUseID: s, SessionID: s, CallRef: s,
		ResultStatus: s, Action: s, WouldBlock: true, Severity: s,
		Reason: strings.Repeat("r", MaxHookDecisionReasonBytes), ModelError: s, ModelStatus: 599,
	}
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxHookDecisionBytes {
		t.Fatalf("bounded HookDecision is %d bytes, over %d", len(raw), MaxHookDecisionBytes)
	}
}

func TestErrorText(t *testing.T) {
	err := &Error{Status: http.StatusGone, Reason: ReasonRegistrationRevoked, Message: "user text"}
	if got := err.Error(); !strings.Contains(got, ReasonRegistrationRevoked) || strings.Contains(got, "user text") {
		t.Fatalf("Error() = %q", got)
	}
}
