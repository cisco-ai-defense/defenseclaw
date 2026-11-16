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
	"sort"
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
			var secondCalls, textCalls int
			bothSecondStarted := make(chan struct{})
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
					id := body.Messages[0].ToolCalls[0].ID
					formats = append(formats, "structured:"+id)
					second := tc.action == "block" && id == "event-two"
					if second {
						secondCalls++
						if secondCalls == 2 {
							close(bothSecondStarted)
						}
					}
					mu.Unlock()
					if second {
						select {
						case <-bothSecondStarted:
						case <-r.Context().Done():
							return
						}
					}
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
				textCalls++
				second := tc.action == "block" && textCalls == 2
				if second {
					secondCalls++
					if secondCalls == 2 {
						close(bothSecondStarted)
					}
				}
				mu.Unlock()
				if second {
					select {
					case <-bothSecondStarted:
					case <-r.Context().Done():
						return
					}
				}
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
			// A non-blocking text result is not cached. A cached block
			// launches both forms, with no ordering between their arrivals.
			want := []string{"structured:event-one", "text", "structured:event-two", "text"}
			if tc.action == "block" && len(formats) == 4 {
				last := append([]string(nil), formats[2:]...)
				sort.Strings(last)
				formats = append(append([]string(nil), formats[:2]...), last...)
			}
			if !reflect.DeepEqual(formats, want) {
				t.Fatalf("request formats = %v, want %v", formats, want)
			}
		})
	}
}
