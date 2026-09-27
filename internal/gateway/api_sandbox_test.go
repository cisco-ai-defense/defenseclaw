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

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// fakeSandboxController records calls and answers with canned values.
type fakeSandboxController struct {
	mu        sync.Mutex
	calls     []string
	createReq sandboxapi.CreateRequest
	decision  sandboxapi.ApprovalDecision
	unblock   sandboxapi.UnblockRequest
	explain   sandboxapi.ExplainRequest
	undo      sandboxapi.UndoRequest
	err       error
	feed      chan sandboxapi.ActivityEvent
	backlog   []sandboxapi.ActivityEvent
	cancelled bool
}

func (f *fakeSandboxController) record(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return f.err
}

func (f *fakeSandboxController) Status(context.Context) (*sandboxapi.Status, error) {
	if err := f.record("status"); err != nil {
		return nil, err
	}
	return &sandboxapi.Status{Enabled: true, Available: true, Sandboxes: 1}, nil
}

func (f *fakeSandboxController) List(context.Context) ([]sandboxapi.Sandbox, error) {
	if err := f.record("list"); err != nil {
		return nil, err
	}
	return []sandboxapi.Sandbox{{Name: "box", Phase: "ready"}}, nil
}

func (f *fakeSandboxController) Get(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	if err := f.record("get " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.Sandbox{Name: name, Phase: "ready"}, nil
}

func (f *fakeSandboxController) Create(_ context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error) {
	f.mu.Lock()
	f.createReq = req
	f.mu.Unlock()
	if err := f.record("create"); err != nil {
		return nil, err
	}
	return &sandboxapi.Sandbox{Name: req.Name, Harness: req.Harness, Phase: "ready"}, nil
}

func (f *fakeSandboxController) Delete(_ context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	if err := f.record("delete " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.DeleteResponse{Name: name, Deleted: true}, nil
}

func (f *fakeSandboxController) Stop(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	if err := f.record("stop " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.Sandbox{Name: name, Phase: "stopped"}, nil
}

func (f *fakeSandboxController) Start(_ context.Context, name string, _ sandboxapi.StartRequest) (*sandboxapi.Sandbox, error) {
	if err := f.record("start " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.Sandbox{Name: name, Phase: "ready"}, nil
}

func (f *fakeSandboxController) Undo(_ context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error) {
	f.mu.Lock()
	f.undo = req
	f.mu.Unlock()
	if err := f.record("undo " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.UndoResponse{Name: name, Stopped: req.Stop}, nil
}

func (f *fakeSandboxController) Review(_ context.Context, name string, _ sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error) {
	if err := f.record("review " + name); err != nil {
		return nil, err
	}
	return &sandboxapi.ReviewResponse{Name: name, Summary: "1 file changed (+1 −0)"}, nil
}

func (f *fakeSandboxController) ReportWorkspace(_ context.Context, name string, r sandboxapi.WorkspaceReport) error {
	return f.record("workspace " + name + " " + r.Operation)
}

func (f *fakeSandboxController) Approvals(_ context.Context, sandbox string) ([]sandboxapi.Approval, error) {
	if err := f.record("approvals " + sandbox); err != nil {
		return nil, err
	}
	return nil, nil
}

func (f *fakeSandboxController) DecideApproval(_ context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error) {
	f.mu.Lock()
	f.decision = d
	f.mu.Unlock()
	if err := f.record("decide " + id); err != nil {
		return nil, err
	}
	return &sandboxapi.ApprovalResult{Approval: sandboxapi.Approval{ID: id, Status: sandboxapi.ApprovalQueued}}, nil
}

func (f *fakeSandboxController) Unblock(_ context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error) {
	f.mu.Lock()
	f.unblock = req
	f.mu.Unlock()
	if err := f.record("unblock"); err != nil {
		return nil, err
	}
	return &sandboxapi.UnblockResponse{Host: req.Host, Scope: "sandbox"}, nil
}

func (f *fakeSandboxController) Explain(_ context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	f.mu.Lock()
	f.explain = req
	f.mu.Unlock()
	if err := f.record("explain"); err != nil {
		return nil, err
	}
	return &sandboxapi.Explain{Pack: "open", Profile: "open"}, nil
}

func (f *fakeSandboxController) ActivitySince(since uint64, _ string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range f.backlog {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	return out
}

func (f *fakeSandboxController) SubscribeActivity(since uint64, sandbox string) ([]sandboxapi.ActivityEvent, <-chan sandboxapi.ActivityEvent, func(), bool) {
	return f.ActivitySince(since, sandbox), f.feed, func() {
		f.mu.Lock()
		f.cancelled = true
		f.mu.Unlock()
	}, true
}

func sandboxTestAPI(t *testing.T, ctl SandboxController, enabled bool) (*APIServer, http.Handler) {
	t.Helper()
	store, logger := testStoreAndLogger(t)
	cfg := &config.Config{}
	cfg.Gateway.Token = "test-token"
	cfg.OpenShell.Enabled = enabled
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	if ctl != nil {
		api.SetSandboxController(ctl)
	}
	mux := http.NewServeMux()
	api.registerSandboxRoutes(mux)
	return api, api.tokenAuth(api.apiCSRFProtect(mux))
}

func sandboxRequest(method, path, body string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	req.Header.Set("Authorization", "Bearer test-token")
	req.Header.Set(sandboxapi.ClientHeader, sandboxapi.ClientName)
	if method != http.MethodGet {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decodeSandboxError(t *testing.T, w *httptest.ResponseRecorder) sandboxapi.Error {
	t.Helper()
	var e sandboxapi.Error
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("error body %q: %v", w.Body.String(), err)
	}
	return e
}

func TestSandboxAPIAuthAndCSRF(t *testing.T) {
	ctl := &fakeSandboxController{}
	_, h := sandboxTestAPI(t, ctl, true)

	noToken := sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, "")
	noToken.Header.Del("Authorization")
	if w := serve(h, noToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d", w.Code)
	}
	wrong := sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, "")
	wrong.Header.Set("Authorization", "Bearer nope")
	if w := serve(h, wrong); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token = %d", w.Code)
	}
	noCSRF := sandboxRequest(http.MethodPost, sandboxapi.PathSandboxes, `{"harness":"claudecode","project":"/p"}`)
	noCSRF.Header.Del(sandboxapi.ClientHeader)
	if w := serve(h, noCSRF); w.Code != http.StatusForbidden {
		t.Fatalf("no CSRF header = %d", w.Code)
	}
	del := sandboxRequest(http.MethodDelete, sandboxapi.PathSandboxes+"/box", "")
	del.Header.Del("Content-Type")
	if w := serve(h, del); w.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("delete without JSON = %d", w.Code)
	}
	cross := sandboxRequest(http.MethodPost, sandboxapi.PathEgressUnblock, `{"host":"a.example","sandbox":"box"}`)
	cross.Header.Set("Sec-Fetch-Site", "cross-site")
	if w := serve(h, cross); w.Code != http.StatusForbidden {
		t.Fatalf("cross-site = %d", w.Code)
	}
	if len(ctl.calls) != 0 {
		t.Fatalf("refused requests reached the controller: %v", ctl.calls)
	}
}

func TestSandboxAPIRoutes(t *testing.T) {
	ctl := &fakeSandboxController{}
	_, h := sandboxTestAPI(t, ctl, true)
	for _, tc := range []struct {
		method, path, body string
		status             int
		call               string
	}{
		{"GET", sandboxapi.PathStatus, "", 200, "status"},
		{"GET", sandboxapi.PathSandboxes, "", 200, "list"},
		{"POST", sandboxapi.PathSandboxes, `{"name":"box","harness":"claudecode","project":"/p","host_ports":[5432]}`, 200, "create"},
		{"GET", sandboxapi.PathSandboxes + "/box", "", 200, "get box"},
		{"DELETE", sandboxapi.PathSandboxes + "/box", "", 200, "delete box"},
		{"POST", sandboxapi.PathSandboxes + "/box/stop", "", 200, "stop box"},
		{"POST", sandboxapi.PathSandboxes + "/box/start", `{}`, 200, "start box"},
		{"POST", sandboxapi.PathSandboxes + "/box/undo", `{"stop":true}`, 200, "undo box"},
		{"POST", sandboxapi.PathSandboxes + "/box/review", "", 200, "review box"},
		{"POST", sandboxapi.PathSandboxes + "/box/workspace", `{"operation":"pull","pull_mode":"branch"}`, 200, "workspace box pull"},
		{"POST", sandboxapi.PathSandboxes + "/box/workspace", "", 400, ""},
		{"POST", sandboxapi.PathSandboxes + "/box/explode", "", 404, ""},
		{"GET", sandboxapi.PathApprovals + "?sandbox=box", "", 200, "approvals box"},
		{"POST", sandboxapi.PathApprovals + "/ap_1", `{"decision":"approve","always":true}`, 200, "decide ap_1"},
		{"POST", sandboxapi.PathEgressUnblock, `{"host":"webhook.site","sandbox":"box"}`, 200, "unblock"},
		{"GET", sandboxapi.PathPolicyExplain + "?harness=codex&copy=true", "", 200, "explain"},
		{"GET", sandboxapi.PathPrefix + "nope", "", 404, ""},
		{"PUT", sandboxapi.PathSandboxes, `{}`, 404, ""},
	} {
		ctl.calls = nil
		w := serve(h, sandboxRequest(tc.method, tc.path, tc.body))
		if w.Code != tc.status {
			t.Fatalf("%s %s = %d %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		if tc.call != "" && (len(ctl.calls) != 1 || ctl.calls[0] != tc.call) {
			t.Fatalf("%s %s calls = %v, want %s", tc.method, tc.path, ctl.calls, tc.call)
		}
		if tc.status != 200 && len(ctl.calls) != 0 {
			t.Fatalf("%s %s reached the controller", tc.method, tc.path)
		}
	}
	if ctl.createReq.Name != "box" || len(ctl.createReq.HostPorts) != 1 || !ctl.decision.Always || ctl.unblock.Host != "webhook.site" ||
		ctl.explain.Harness != "codex" || !ctl.explain.Copy || !ctl.undo.Stop {
		t.Fatalf("decoded requests: create %+v decision %+v unblock %+v explain %+v undo %+v",
			ctl.createReq, ctl.decision, ctl.unblock, ctl.explain, ctl.undo)
	}
}

func TestSandboxAPIStrictBodies(t *testing.T) {
	ctl := &fakeSandboxController{}
	_, h := sandboxTestAPI(t, ctl, true)
	for _, body := range []string{`{"harness":"claudecode","surprise":1}`, `{"harness":`, `{} {}`, ``} {
		w := serve(h, sandboxRequest(http.MethodPost, sandboxapi.PathSandboxes, body))
		if w.Code != http.StatusBadRequest || decodeSandboxError(t, w).Code != sandboxapi.CodeInvalid {
			t.Fatalf("body %q = %d %s", body, w.Code, w.Body.String())
		}
	}
	big := `{"harness":"` + strings.Repeat("a", sandboxRequestBodyMaxBytes) + `"}`
	if w := serve(h, sandboxRequest(http.MethodPost, sandboxapi.PathSandboxes, big)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d", w.Code)
	}
}

func TestSandboxAPIErrors(t *testing.T) {
	ctl := &fakeSandboxController{err: &sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: sandboxapi.AdminMessage,
		Violation: &sandboxapi.Violation{Key: "egress.unblock", Constraint: "openshell.admin.allow_unblock", Admin: true}}}
	_, h := sandboxTestAPI(t, ctl, true)
	w := serve(h, sandboxRequest(http.MethodPost, sandboxapi.PathEgressUnblock, `{"host":"webhook.site","always":true}`))
	e := decodeSandboxError(t, w)
	if w.Code != http.StatusForbidden || e.Code != sandboxapi.CodeAdminViolation || e.Violation == nil || !e.Violation.Admin ||
		!strings.Contains(e.Message, "blocked by your organization's DefenseClaw policy") {
		t.Fatalf("admin refusal = %d %+v", w.Code, e)
	}
	ctl.err = errors.New("plain failure")
	if w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, "")); w.Code != 500 || decodeSandboxError(t, w).Code != sandboxapi.CodeInternal {
		t.Fatalf("plain error = %d", w.Code)
	}
	ctl.err = context.DeadlineExceeded
	if w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, "")); w.Code != http.StatusGatewayTimeout {
		t.Fatalf("timeout = %d", w.Code)
	}
}

func TestSandboxAPIDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		_, h := sandboxTestAPI(t, nil, enabled)
		w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathStatus, ""))
		var st sandboxapi.Status
		_ = json.Unmarshal(w.Body.Bytes(), &st)
		if w.Code != 200 || st.Enabled != enabled || st.Available {
			t.Fatalf("status (enabled=%v) = %d %+v", enabled, w.Code, st)
		}
		w = serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, ""))
		want := sandboxapi.CodeDisabled
		if enabled {
			want = sandboxapi.CodeUnavailable
		}
		if w.Code != http.StatusServiceUnavailable || decodeSandboxError(t, w).Code != want {
			t.Fatalf("list (enabled=%v) = %d %s", enabled, w.Code, w.Body.String())
		}
	}
}

func TestSandboxAPIActivity(t *testing.T) {
	ctl := &fakeSandboxController{
		feed:    make(chan sandboxapi.ActivityEvent, 4),
		backlog: []sandboxapi.ActivityEvent{{Seq: 1, Kind: "a"}, {Seq: 2, Kind: "b"}},
	}
	_, h := sandboxTestAPI(t, ctl, true)
	w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathActivity+"?since=1", ""))
	var got struct {
		Events []sandboxapi.ActivityEvent `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Events) != 1 || got.Events[0].Seq != 2 {
		t.Fatalf("buffered = %s", w.Body.String())
	}
	if w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathActivity+"?since=x", "")); w.Code != 400 {
		t.Fatalf("bad since = %d", w.Code)
	}

	// The SSE stream through a real server, driven by the typed client.
	srv := httptest.NewServer(h)
	defer srv.Close()
	client := sandboxapi.NewClient(srv.URL, "test-token")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctl.feed <- sandboxapi.ActivityEvent{Seq: 3, Kind: sandboxapi.ActivityEgressBlocked, Host: "webhook.site"}
	var seen []uint64
	stop := errors.New("done")
	err := client.Activity(ctx, sandboxapi.ActivityQuery{Follow: true}, func(ev sandboxapi.ActivityEvent) error {
		seen = append(seen, ev.Seq)
		if ev.Seq == 3 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || len(seen) != 3 {
		t.Fatalf("stream = %v, %v", seen, err)
	}
	eventuallyTrue(t, func() bool { ctl.mu.Lock(); defer ctl.mu.Unlock(); return ctl.cancelled })
}

func TestSandboxAPIClientRoundTrip(t *testing.T) {
	ctl := &fakeSandboxController{}
	_, h := sandboxTestAPI(t, ctl, true)
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := sandboxapi.NewClient(srv.URL, "test-token")
	ctx := context.Background()
	if _, err := c.Create(ctx, sandboxapi.CreateRequest{Name: "box", Harness: "claudecode", Project: "/p"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Delete(ctx, "box", sandboxapi.DeleteRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Undo(ctx, "box", sandboxapi.UndoRequest{Preview: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Review(ctx, "box", sandboxapi.ReviewRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Start(ctx, "box", sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	if list, err := c.Approvals(ctx, ""); err != nil || list == nil {
		t.Fatalf("approvals = %v, %v", list, err)
	}
	if _, err := c.Explain(ctx, sandboxapi.ExplainRequest{Sandbox: "box"}); err != nil {
		t.Fatal(err)
	}
	if st, err := c.Status(ctx); err != nil || !st.Available {
		t.Fatalf("status = %+v, %v", st, err)
	}
	bad := sandboxapi.NewClient(srv.URL, "wrong")
	if _, err := bad.List(ctx); err == nil {
		t.Fatal("wrong token accepted")
	}
}

func eventuallyTrue(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
