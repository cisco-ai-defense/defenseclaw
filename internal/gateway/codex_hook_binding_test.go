// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const defaultTestCodexHookContract = "codex-hooks-v4"

func setTestCodexHookBinding(
	req *http.Request,
	event string,
	contractID string,
) {
	req.Header.Set("X-DefenseClaw-Hook-Event", event)
	req.Header.Set("X-DefenseClaw-Hook-Contract", contractID)
}

func TestHandleAgentHookRequiresCodexRuntimeBinding(t *testing.T) {
	tests := []struct {
		name       string
		bodyEvent  string
		boundEvent string
		contractID string
		wantStatus int
		wantError  string
	}{
		{
			name:       "valid",
			bodyEvent:  "PreToolUse",
			boundEvent: "PreToolUse",
			contractID: defaultTestCodexHookContract,
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing bound event",
			bodyEvent:  "PreToolUse",
			contractID: defaultTestCodexHookContract,
			wantStatus: http.StatusBadRequest,
			wantError:  "installer-bound Codex hook event is required",
		},
		{
			name:       "stdin event mismatch",
			bodyEvent:  "PreToolUse",
			boundEvent: "SessionEnd",
			contractID: defaultTestCodexHookContract,
			wantStatus: http.StatusBadRequest,
			wantError:  "Codex stdin event does not match installer-bound event",
		},
		{
			name:       "missing bound contract",
			bodyEvent:  "PreToolUse",
			boundEvent: "PreToolUse",
			wantStatus: http.StatusBadRequest,
			wantError:  "installer-bound Codex hook contract is required",
		},
		{
			name:       "contract lock mismatch",
			bodyEvent:  "PreToolUse",
			boundEvent: "PreToolUse",
			contractID: "codex-hooks-v1",
			wantStatus: http.StatusConflict,
			wantError:  "Codex hook contract does not match protected runtime lock",
		},
		{
			name:       "event outside contract",
			bodyEvent:  "FutureEvent",
			boundEvent: "FutureEvent",
			contractID: defaultTestCodexHookContract,
			wantStatus: http.StatusBadRequest,
			wantError:  "Codex hook event is not registered by protected runtime contract",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			api := &APIServer{scannerCfg: &config.Config{}}
			req := httptest.NewRequest(
				http.MethodPost,
				"/api/v1/codex/hook",
				strings.NewReader(`{"hook_event_name":"`+test.bodyEvent+`"}`),
			)
			if test.boundEvent != "" {
				req.Header.Set("X-DefenseClaw-Hook-Event", test.boundEvent)
			}
			if test.contractID != "" {
				req.Header.Set("X-DefenseClaw-Hook-Contract", test.contractID)
			}
			recorder := httptest.NewRecorder()
			api.handleAgentHook("codex").ServeHTTP(recorder, req)
			if recorder.Code != test.wantStatus {
				t.Fatalf(
					"status=%d want=%d body=%s",
					recorder.Code,
					test.wantStatus,
					recorder.Body.String(),
				)
			}
			if test.wantError != "" &&
				!strings.Contains(recorder.Body.String(), test.wantError) {
				t.Fatalf("body=%q want error %q", recorder.Body.String(), test.wantError)
			}
		})
	}
}
