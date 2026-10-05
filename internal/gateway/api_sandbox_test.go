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
	"os"
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
	accept    sandboxapi.AcceptRequest
	lines     int
	err       error
	feed      chan sandboxapi.ActivityEvent
	backlog   []sandboxapi.ActivityEvent
	cancelled bool
}

// answer records call (keeping what keep saves) and returns v, or the
// controller's error.
func answer[T any](f *fakeSandboxController, call string, v T, keep ...func()) (T, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range keep {
		k()
	}
	f.calls = append(f.calls, call)
	if f.err != nil {
		var zero T
		return zero, f.err
	}
	return v, nil
}

func (f *fakeSandboxController) Status(context.Context) (*sandboxapi.Status, error) {
	return answer(f, "status", &sandboxapi.Status{Enabled: true, Available: true, Sandboxes: 1})
}

func (f *fakeSandboxController) List(context.Context) ([]sandboxapi.Sandbox, error) {
	return answer(f, "list", []sandboxapi.Sandbox{{Name: "box", Phase: "ready"}})
}

func (f *fakeSandboxController) Get(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	return answer(f, "get "+name, &sandboxapi.Sandbox{Name: name, Phase: "ready"})
}

func (f *fakeSandboxController) Create(_ context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error) {
	return answer(f, "create", &sandboxapi.Sandbox{Name: req.Name, Harness: req.Harness, Phase: "ready"}, func() { f.createReq = req })
}

func (f *fakeSandboxController) Delete(_ context.Context, name string, _ sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error) {
	return answer(f, "delete "+name, &sandboxapi.DeleteResponse{Name: name, Deleted: true})
}

func (f *fakeSandboxController) Stop(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	return answer(f, "stop "+name, &sandboxapi.Sandbox{Name: name, Phase: "stopped"})
}

func (f *fakeSandboxController) Start(_ context.Context, name string, _ sandboxapi.StartRequest) (*sandboxapi.Sandbox, error) {
	return answer(f, "start "+name, &sandboxapi.Sandbox{Name: name, Phase: "ready"})
}

func (f *fakeSandboxController) Undo(_ context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error) {
	return answer(f, "undo "+name, &sandboxapi.UndoResponse{Name: name, Stopped: req.Stop}, func() { f.undo = req })
}

func (f *fakeSandboxController) Review(_ context.Context, name string, _ sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error) {
	return answer(f, "review "+name, &sandboxapi.ReviewResponse{Name: name, Summary: "1 file changed (+1 −0)"})
}

func (f *fakeSandboxController) Accept(_ context.Context, name string, req sandboxapi.AcceptRequest) (*sandboxapi.Sandbox, error) {
	return answer(f, "accept "+name, &sandboxapi.Sandbox{Name: name, Phase: "stopped"}, func() { f.accept = req })
}

func (f *fakeSandboxController) RunLog(_ context.Context, name string, lines int) (*sandboxapi.RunLog, error) {
	return answer(f, "logs "+name, &sandboxapi.RunLog{Name: name, State: sandboxapi.RunInterrupted, Log: "partial\n"},
		func() { f.lines = lines })
}

func (f *fakeSandboxController) ReportWorkspace(_ context.Context, name string, r sandboxapi.WorkspaceReport) error {
	_, err := answer(f, "workspace "+name+" "+r.Operation, struct{}{})
	return err
}

func (f *fakeSandboxController) Approvals(_ context.Context, sandbox string) ([]sandboxapi.Approval, error) {
	return answer[[]sandboxapi.Approval](f, "approvals "+sandbox, nil)
}

func (f *fakeSandboxController) DecideApproval(_ context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error) {
	return answer(f, "decide "+id, &sandboxapi.ApprovalResult{Approval: sandboxapi.Approval{ID: id, Status: sandboxapi.ApprovalQueued}},
		func() { f.decision = d })
}

func (f *fakeSandboxController) Unblock(_ context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error) {
	return answer(f, "unblock", &sandboxapi.UnblockResponse{Host: req.Host, Scope: "sandbox"}, func() { f.unblock = req })
}

func (f *fakeSandboxController) Explain(_ context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error) {
	return answer(f, "explain", &sandboxapi.Explain{Pack: "open", Profile: "open"}, func() { f.explain = req })
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
		{"POST", sandboxapi.PathSandboxes + "/box/accept", `{"snapshot_created_at":"2026-09-30T10:00:00Z","session":3}`, 200, "accept box"},
		{"POST", sandboxapi.PathSandboxes + "/box/accept", `{"surprise":1}`, 400, ""},
		{"GET", sandboxapi.PathSandboxes + "/box/logs?lines=5", "", 200, "logs box"},
		{"GET", sandboxapi.PathSandboxes + "/box/logs?lines=-1", "", 400, ""},
		{"GET", sandboxapi.PathSandboxes + "/box/explode", "", 404, ""},
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
		ctl.explain.Harness != "codex" || !ctl.explain.Copy || !ctl.undo.Stop ||
		!ctl.accept.Snapshot.Equal(time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)) || ctl.accept.Session != 3 || ctl.lines != 5 {
		t.Fatalf("decoded requests: create %+v decision %+v unblock %+v explain %+v undo %+v accept %+v lines %d",
			ctl.createReq, ctl.decision, ctl.unblock, ctl.explain, ctl.undo, ctl.accept, ctl.lines)
	}
}

// The status names the uid the daemon runs as, for the doctor's same-user
// check, whether or not the sandbox subsystem runs; while it does not, the
// other routes say whether it is disabled or unavailable.
func TestSandboxAPIStatusNamesTheDaemonUID(t *testing.T) {
	for _, tc := range []struct {
		name             string
		ctl              SandboxController
		enabled, running bool
		listCode         string
	}{
		{"running", &fakeSandboxController{}, true, true, ""},
		{"disabled", nil, false, false, sandboxapi.CodeDisabled},
		{"unavailable", nil, true, false, sandboxapi.CodeUnavailable},
	} {
		_, h := sandboxTestAPI(t, tc.ctl, tc.enabled)
		w := serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathStatus, ""))
		var st sandboxapi.Status
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil || w.Code != 200 || st.Enabled != tc.enabled || st.Available != tc.running {
			t.Fatalf("%s: status = %d %s", tc.name, w.Code, w.Body.String())
		}
		if want := os.Getuid(); (want < 0) != (st.DaemonUID == nil) || (want >= 0 && *st.DaemonUID != want) {
			t.Fatalf("%s: daemon uid = %v, want %d", tc.name, st.DaemonUID, want)
		}
		if tc.running {
			continue
		}
		w = serve(h, sandboxRequest(http.MethodGet, sandboxapi.PathSandboxes, ""))
		if w.Code != http.StatusServiceUnavailable || decodeSandboxError(t, w).Code != tc.listCode {
			t.Fatalf("%s: list = %d %s", tc.name, w.Code, w.Body.String())
		}
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
	if _, err := c.Accept(ctx, "box", sandboxapi.AcceptRequest{}); err != nil {
		t.Fatal(err)
	}
	if log, err := c.RunLog(ctx, "box", 0); err != nil || log.State != sandboxapi.RunInterrupted || log.Log != "partial\n" || ctl.lines != 0 {
		t.Fatalf("run log = %+v, %v (lines %d)", log, err, ctl.lines)
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
