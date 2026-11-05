// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestCiscoInspectAPIKeyRetryIgnoresToolUseID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   string
		action string
	}{
		{name: "protected", args: `{"topic":"policy-review"}`, action: "block"},
		{name: "benign", args: `{"topic":"team-update"}`, action: "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var formats []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Messages []struct {
						Content   string `json:"content"`
						ToolCalls []struct {
							ID string `json:"id"`
						} `json:"tool_calls"`
					} `json:"messages"`
				}
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if len(body.Messages) == 2 && len(body.Messages[0].ToolCalls) == 1 {
					mu.Lock()
					formats = append(formats, "structured:"+body.Messages[0].ToolCalls[0].ID)
					mu.Unlock()
					w.WriteHeader(http.StatusUnprocessableEntity)
					return
				}
				if len(body.Messages) != 1 || body.Messages[0].Content != tc.args {
					t.Errorf("unexpected text request: %+v", body.Messages)
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				mu.Lock()
				formats = append(formats, "text")
				mu.Unlock()
				if tc.action == "block" {
					_, _ = io.WriteString(w, `{"is_safe":false,"action":"Block","rules":[]}`)
					return
				}
				_, _ = io.WriteString(w, `{"is_safe":true,"action":"Allow","rules":[]}`)
			}))
			t.Cleanup(srv.Close)

			client := &CiscoInspectClient{apiKey: "test-key", endpoint: srv.URL, timeout: time.Second, client: srv.Client()}
			api := testAPIServerWithConfig(t, "action")
			api.SetCiscoInspector(client)
			args := json.RawMessage(tc.args)
			for _, id := range []string{"event-one", "event-two"} {
				verdict := api.hookAIDInspectToolCall(t.Context(), aidToolCall{Name: "message", ID: id, Args: args}, tc.args)
				if verdict == nil || verdict.Action != tc.action {
					t.Fatalf("id %s verdict = %+v, want %s", id, verdict, tc.action)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if want := []string{"structured:event-one", "text", "text"}; !reflect.DeepEqual(formats, want) {
				t.Fatalf("request formats = %v, want %v", formats, want)
			}
		})
	}
}
