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

package sandboxapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type recorded struct {
	method, path, query string
	header              http.Header
	body                string
}

func testServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) (*Client, *[]recorded) {
	t.Helper()
	var calls []recorded
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		calls = append(calls, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
		r.Body = io.NopCloser(bytes.NewReader(body))
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.URL+"/", "master-token"), &calls
}

func TestClientRequests(t *testing.T) {
	c, calls := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == PathSandboxes && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"sandboxes": []Sandbox{{Name: "a"}, {Name: "b"}}})
		case r.URL.Path == PathSandboxes && r.Method == http.MethodPost:
			var req CreateRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			_ = json.NewEncoder(w).Encode(Sandbox{Name: req.Name, Harness: req.Harness, Phase: "ready"})
		case strings.HasPrefix(r.URL.Path, PathApprovals):
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(map[string]any{"approvals": []Approval{{ID: "ap_1"}}})
				return
			}
			_ = json.NewEncoder(w).Encode(ApprovalResult{Approval: Approval{ID: "ap_1", Status: ApprovalQueued}})
		default:
			_, _ = io.WriteString(w, `{"name":"x","deleted":true}`)
		}
	})
	ctx := context.Background()
	list, err := c.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %v, %v", list, err)
	}
	sb, err := c.Create(ctx, CreateRequest{Name: "box", Harness: "claudecode", Project: "/p"})
	if err != nil || sb.Name != "box" || sb.Phase != "ready" {
		t.Fatalf("create = %+v, %v", sb, err)
	}
	if _, err := c.Delete(ctx, "box", DeleteRequest{KeepSnapshot: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Stop(ctx, "box"); err != nil {
		t.Fatal(err)
	}
	asks, err := c.Approvals(ctx, "box")
	if err != nil || len(asks) != 1 {
		t.Fatalf("approvals = %v, %v", asks, err)
	}
	res, err := c.Decide(ctx, "ap_1", ApprovalDecision{Decision: DecisionApprove, Always: true})
	if err != nil || res.Approval.Status != ApprovalQueued {
		t.Fatalf("decide = %+v, %v", res, err)
	}

	for _, call := range *calls {
		if call.header.Get("Authorization") != "Bearer master-token" || call.header.Get(ClientHeader) != ClientName {
			t.Fatalf("%s %s headers = %v", call.method, call.path, call.header)
		}
		if call.method != http.MethodGet && !strings.Contains(call.header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s %s content type = %q", call.method, call.path, call.header.Get("Content-Type"))
		}
	}
	want := []struct{ method, path, query string }{
		{"GET", PathSandboxes, ""}, {"POST", PathSandboxes, ""}, {"DELETE", PathSandboxes + "/box", ""},
		{"POST", PathSandboxes + "/box/stop", ""}, {"GET", PathApprovals, "sandbox=box"}, {"POST", PathApprovals + "/ap_1", ""},
	}
	for i, w := range want {
		got := (*calls)[i]
		if got.method != w.method || got.path != w.path || got.query != w.query {
			t.Fatalf("call %d = %s %s?%s, want %s %s?%s", i, got.method, got.path, got.query, w.method, w.path, w.query)
		}
	}
	if !strings.Contains((*calls)[2].body, `"keep_snapshot":true`) || !strings.Contains((*calls)[5].body, `"always":true`) {
		t.Fatalf("bodies = %q %q", (*calls)[2].body, (*calls)[5].body)
	}
}

func TestClientErrors(t *testing.T) {
	c, _ := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case PathStatus:
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(Error{Code: CodeAdminViolation, Message: AdminMessage,
				Violation: &Violation{Key: "egress.unblock", Admin: true}})
		case PathSandboxes:
			http.Error(w, "plain failure", http.StatusBadGateway)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized"}`)
		}
	})
	_, err := c.Status(context.Background())
	var e *Error
	if !errors.As(err, &e) || e.Code != CodeAdminViolation || e.Status != http.StatusForbidden || e.Violation == nil || !e.Violation.Admin {
		t.Fatalf("admin error = %#v", err)
	}
	_, err = c.List(context.Background())
	if !IsCode(err, CodeUpstream) || !strings.Contains(err.Error(), "plain failure") {
		t.Fatalf("plain error = %v", err)
	}
	_, err = c.Get(context.Background(), "x")
	if !errors.As(err, &e) || e.Status != http.StatusUnauthorized || e.Message != "unauthorized" {
		t.Fatalf("auth error = %#v", err)
	}

	down := NewClient("http://127.0.0.1:1", "t")
	down.HTTP = &http.Client{Timeout: time.Second}
	if _, err := down.Status(context.Background()); !IsCode(err, CodeUnavailable) {
		t.Fatalf("unreachable = %v", err)
	}
}

func TestClientActivity(t *testing.T) {
	c, calls := testServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("follow") != "true" {
			_ = json.NewEncoder(w).Encode(map[string]any{"events": []ActivityEvent{{Seq: 1, Kind: ActivityEgressBlocked}}})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, Heartbeat)
		for i := uint64(5); i < 8; i++ {
			_ = WriteEvent(w, ActivityEvent{Seq: i, Kind: ActivityEgressAllowed, Host: "h"})
		}
	})
	var got []uint64
	if err := c.Activity(context.Background(), ActivityQuery{Sandbox: "box"}, func(ev ActivityEvent) error {
		got = append(got, ev.Seq)
		return nil
	}); err != nil || len(got) != 1 {
		t.Fatalf("buffered = %v, %v", got, err)
	}
	got = nil
	stop := errors.New("stop")
	err := c.Activity(context.Background(), ActivityQuery{Sandbox: "box", Since: 4, Follow: true}, func(ev ActivityEvent) error {
		got = append(got, ev.Seq)
		if ev.Seq == 6 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || len(got) != 2 {
		t.Fatalf("stream = %v, %v", got, err)
	}
	last := (*calls)[len(*calls)-1]
	if last.header.Get("Accept") != "text/event-stream" || last.query != "follow=true&sandbox=box&since=4" {
		t.Fatalf("stream request = %+v", last)
	}
}

func TestQueryRoundTrips(t *testing.T) {
	req := ExplainRequest{Harness: "claudecode", Pack: "balanced", Project: "/p", Copy: true, Unmask: []string{".env.local", "a"}}
	if got := ParseExplainQuery(req.Query()); got.Harness != req.Harness || got.Pack != req.Pack || !got.Copy || len(got.Unmask) != 2 {
		t.Fatalf("explain = %+v", got)
	}
	q, err := ParseActivityQuery(url.Values{"since": {"3"}, "follow": {"1"}, "sandbox": {"b"}}, "")
	if err != nil || q.Since != 3 || !q.Follow || q.Sandbox != "b" {
		t.Fatalf("activity = %+v, %v", q, err)
	}
	if q, _ := ParseActivityQuery(url.Values{"since": {"3"}}, " 9 "); q.Since != 9 {
		t.Fatalf("Last-Event-ID ignored: %+v", q)
	}
	if _, err := ParseActivityQuery(url.Values{"since": {"x"}}, ""); !IsCode(err, CodeInvalid) {
		t.Fatalf("bad since: %v", err)
	}
}

func TestReadEventsMultiline(t *testing.T) {
	stream := ": hello\n\nid: 1\nevent: activity\ndata: {\"seq\":1,\ndata: \"kind\":\"k\"}\n\n"
	var got []ActivityEvent
	if err := ReadEvents(strings.NewReader(stream), func(ev ActivityEvent) error { got = append(got, ev); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Seq != 1 || got[0].Kind != "k" {
		t.Fatalf("events = %+v", got)
	}
	if err := ReadEvents(strings.NewReader("data: {bad\n\n"), func(ActivityEvent) error { return nil }); err == nil {
		t.Fatal("malformed event accepted")
	}
}

func TestErrorStatus(t *testing.T) {
	for code, status := range map[string]int{
		CodeDisabled: 503, CodeUnavailable: 503, CodeInvalid: 400, CodeNotFound: 404, CodeConflict: 409,
		CodeAdminViolation: 403, CodePolicyViolation: 403, CodePolicyRejected: 422, CodeUpstream: 502, CodeInternal: 500,
		CodeImageUnavailable: 409, CodePackInvalid: 400,
	} {
		if got := (&Error{Code: code}).HTTPStatus(); got != status {
			t.Errorf("%s = %d, want %d", code, got, status)
		}
	}
	if got := (&Error{Code: CodeInvalid, Status: 413}).HTTPStatus(); got != 413 {
		t.Fatalf("explicit status = %d", got)
	}
	if AsError(nil) != nil || AsError(errors.New("x")).Code != CodeInternal {
		t.Fatal("AsError")
	}
}

func TestClientForConfig(t *testing.T) {
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
	cfg := &config.Config{}
	cfg.Gateway.Token = "tok"
	cfg.Gateway.APIPort = 19000
	c, err := ClientForConfig(cfg)
	if err != nil || c.Token != "tok" || !strings.HasSuffix(c.BaseURL, ":19000") || !strings.HasPrefix(c.BaseURL, "http://") {
		t.Fatalf("client = %+v, %v", c, err)
	}
	if _, err := ClientForConfig(&config.Config{}); err == nil {
		t.Fatal("client without a token")
	}
}
