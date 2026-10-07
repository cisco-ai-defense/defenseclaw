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
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// SandboxController is the OpenShell sandbox manager behind the sandbox REST
// API (/api/v1/sandbox/...). internal/openshell/manager implements it.
// Errors are *sandboxapi.Error; anything else is reported as internal.
type SandboxController interface {
	Status(ctx context.Context) (*sandboxapi.Status, error)
	List(ctx context.Context) ([]sandboxapi.Sandbox, error)
	Get(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Create(ctx context.Context, req sandboxapi.CreateRequest) (*sandboxapi.Sandbox, error)
	Delete(ctx context.Context, name string, req sandboxapi.DeleteRequest) (*sandboxapi.DeleteResponse, error)
	Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error)
	Start(ctx context.Context, name string, req sandboxapi.StartRequest) (*sandboxapi.Sandbox, error)
	Undo(ctx context.Context, name string, req sandboxapi.UndoRequest) (*sandboxapi.UndoResponse, error)
	Review(ctx context.Context, name string, req sandboxapi.ReviewRequest) (*sandboxapi.ReviewResponse, error)
	// Accept records that the user kept the changes on top of a stopped
	// mounted sandbox's snapshot, so its next start takes a new one.
	Accept(ctx context.Context, name string, req sandboxapi.AcceptRequest) (*sandboxapi.Sandbox, error)
	// RunLog returns the log of the latest detached run the daemon kept
	// when it stopped the sandbox (its last lines lines; 0: all of it).
	RunLog(ctx context.Context, name string, lines int) (*sandboxapi.RunLog, error)
	// Destinations returns what the sandbox reached or tried to reach, by
	// host and kind (model provider, shadow AI, ...).
	Destinations(ctx context.Context, name string) (*sandboxapi.Destinations, error)
	// ReportWorkspace records a copy-mode workspace step the CLI ran.
	ReportWorkspace(ctx context.Context, name string, report sandboxapi.WorkspaceReport) error
	Approvals(ctx context.Context, sandbox string) ([]sandboxapi.Approval, error)
	DecideApproval(ctx context.Context, id string, d sandboxapi.ApprovalDecision) (*sandboxapi.ApprovalResult, error)
	Unblock(ctx context.Context, req sandboxapi.UnblockRequest) (*sandboxapi.UnblockResponse, error)
	Explain(ctx context.Context, req sandboxapi.ExplainRequest) (*sandboxapi.Explain, error)
	// PolicyTest judges destinations with a sandbox's egress policy.
	PolicyTest(ctx context.Context, req sandboxapi.PolicyTestRequest) (*sandboxapi.PolicyTestResult, error)
	// ActivitySince returns buffered activity after since.
	ActivitySince(since uint64, sandbox string) []sandboxapi.ActivityEvent
	// SubscribeActivity returns buffered activity after since and a
	// channel of later events; cancel ends the subscription. ok is false
	// when too many streams are open.
	SubscribeActivity(since uint64, sandbox string) (backlog []sandboxapi.ActivityEvent, events <-chan sandboxapi.ActivityEvent, cancel func(), ok bool)
}

// SetSandboxController wires (or, with nil, detaches) the sandbox manager.
// Replacing it waits for handlers still using the previous one.
func (a *APIServer) SetSandboxController(c SandboxController) {
	if a == nil {
		return
	}
	a.sandboxCtlMu.Lock()
	a.sandboxCtl = c
	a.sandboxCtlMu.Unlock()
}

// leaseSandboxController pins the current controller for one handler.
func (a *APIServer) leaseSandboxController() (SandboxController, func()) {
	if a == nil {
		return nil, func() {}
	}
	a.sandboxCtlMu.RLock()
	return a.sandboxCtl, a.sandboxCtlMu.RUnlock
}

// sandboxRequestBodyMaxBytes bounds sandbox API request bodies.
const sandboxRequestBodyMaxBytes = 256 << 10

// registerSandboxRoutes mounts the sandbox REST API on the main mux. It
// sits behind the same master-token and CSRF middleware as every other
// route.
func (a *APIServer) registerSandboxRoutes(mux *http.ServeMux) {
	mux.Handle(sandboxapi.PathPrefix, a.sandboxAPIHandler())
}

// sandboxAPIHandler is the sandbox API's own router.
func (a *APIServer) sandboxAPIHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+sandboxapi.PathStatus, a.handleSandboxStatus)
	mux.HandleFunc("GET "+sandboxapi.PathSandboxes, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		list, err := c.List(ctx)
		if list == nil {
			list = []sandboxapi.Sandbox{}
		}
		return map[string]any{"sandboxes": list}, err
	}))
	mux.HandleFunc("POST "+sandboxapi.PathSandboxes, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		var req sandboxapi.CreateRequest
		if err := decodeSandboxBody(r, &req, false); err != nil {
			return nil, err
		}
		return c.Create(ctx, req)
	}))
	mux.HandleFunc("GET "+sandboxapi.PathSandboxes+"/{name}", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		return c.Get(ctx, r.PathValue("name"))
	}))
	mux.HandleFunc("GET "+sandboxapi.PathSandboxes+"/{name}/logs", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		lines, err := sandboxapi.ParseRunLogLines(r.URL.Query())
		if err != nil {
			return nil, err
		}
		return c.RunLog(ctx, r.PathValue("name"), lines)
	}))
	mux.HandleFunc("GET "+sandboxapi.PathSandboxes+"/{name}/destinations", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		return c.Destinations(ctx, r.PathValue("name"))
	}))
	mux.HandleFunc("DELETE "+sandboxapi.PathSandboxes+"/{name}", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		var req sandboxapi.DeleteRequest
		if err := decodeSandboxBody(r, &req, true); err != nil {
			return nil, err
		}
		return c.Delete(ctx, r.PathValue("name"), req)
	}))
	mux.HandleFunc("POST "+sandboxapi.PathSandboxes+"/{name}/{verb}", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		name := r.PathValue("name")
		switch r.PathValue("verb") {
		case "stop":
			var req struct{}
			if err := decodeSandboxBody(r, &req, true); err != nil {
				return nil, err
			}
			return c.Stop(ctx, name)
		case "start":
			var req sandboxapi.StartRequest
			if err := decodeSandboxBody(r, &req, true); err != nil {
				return nil, err
			}
			return c.Start(ctx, name, req)
		case "undo":
			var req sandboxapi.UndoRequest
			if err := decodeSandboxBody(r, &req, true); err != nil {
				return nil, err
			}
			return c.Undo(ctx, name, req)
		case "accept":
			var req sandboxapi.AcceptRequest
			if err := decodeSandboxBody(r, &req, true); err != nil {
				return nil, err
			}
			return c.Accept(ctx, name, req)
		case "review":
			var req sandboxapi.ReviewRequest
			if err := decodeSandboxBody(r, &req, true); err != nil {
				return nil, err
			}
			return c.Review(ctx, name, req)
		case "workspace":
			var req sandboxapi.WorkspaceReport
			if err := decodeSandboxBody(r, &req, false); err != nil {
				return nil, err
			}
			if err := c.ReportWorkspace(ctx, name, req); err != nil {
				return nil, err
			}
			return map[string]string{"status": "recorded"}, nil
		default:
			return nil, sandboxapi.Errorf(sandboxapi.CodeNotFound, "unknown sandbox action %q", r.PathValue("verb"))
		}
	}))
	mux.HandleFunc("GET "+sandboxapi.PathApprovals, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		list, err := c.Approvals(ctx, r.URL.Query().Get("sandbox"))
		if list == nil {
			list = []sandboxapi.Approval{}
		}
		return map[string]any{"approvals": list}, err
	}))
	mux.HandleFunc("POST "+sandboxapi.PathApprovals+"/{id}", a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		var d sandboxapi.ApprovalDecision
		if err := decodeSandboxBody(r, &d, false); err != nil {
			return nil, err
		}
		return c.DecideApproval(ctx, r.PathValue("id"), d)
	}))
	mux.HandleFunc("POST "+sandboxapi.PathEgressUnblock, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		var req sandboxapi.UnblockRequest
		if err := decodeSandboxBody(r, &req, false); err != nil {
			return nil, err
		}
		return c.Unblock(ctx, req)
	}))
	mux.HandleFunc("GET "+sandboxapi.PathPolicyExplain, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		return c.Explain(ctx, sandboxapi.ParseExplainQuery(r.URL.Query()))
	}))
	mux.HandleFunc("POST "+sandboxapi.PathPolicyTest, a.sandboxCall(func(ctx context.Context, c SandboxController, r *http.Request) (any, error) {
		var req sandboxapi.PolicyTestRequest
		if err := decodeSandboxBody(r, &req, false); err != nil {
			return nil, err
		}
		return c.PolicyTest(ctx, req)
	}))
	mux.HandleFunc("GET "+sandboxapi.PathActivity, a.handleSandboxActivity)
	mux.HandleFunc(sandboxapi.PathPrefix, func(w http.ResponseWriter, r *http.Request) {
		writeSandboxError(w, sandboxapi.Errorf(sandboxapi.CodeNotFound, "no sandbox API route %s %s", r.Method, r.URL.Path))
	})
	return mux
}

// sandboxCall adapts one controller call to a JSON handler.
func (a *APIServer) sandboxCall(fn func(context.Context, SandboxController, *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, release := a.leaseSandboxController()
		defer release()
		if c == nil {
			writeSandboxError(w, a.sandboxDisabledError())
			return
		}
		out, err := fn(r.Context(), c, r)
		if err != nil {
			writeSandboxError(w, err)
			return
		}
		a.writeJSON(w, http.StatusOK, out)
	}
}

func (a *APIServer) sandboxDisabledError() *sandboxapi.Error {
	if cfg := a.runtimeConfigSnapshot(); cfg != nil && cfg.OpenShell.Enabled {
		return sandboxapi.Errorf(sandboxapi.CodeUnavailable, "the sandbox subsystem is not running; see `defenseclaw sandbox doctor`")
	}
	return sandboxapi.Errorf(sandboxapi.CodeDisabled, sandboxapi.DisabledMessage)
}

func (a *APIServer) handleSandboxStatus(w http.ResponseWriter, r *http.Request) {
	c, release := a.leaseSandboxController()
	defer release()
	if c == nil {
		cfg := a.runtimeConfigSnapshot()
		st := &sandboxapi.Status{Reason: a.sandboxDisabledError().Message}
		if cfg != nil {
			st.Enabled = cfg.OpenShell.Enabled
		}
		st.IngressAddr = a.SandboxIngressAddr()
		st.DaemonUID = daemonUID()
		a.writeJSON(w, http.StatusOK, st)
		return
	}
	st, err := c.Status(r.Context())
	if err != nil {
		writeSandboxError(w, err)
		return
	}
	st.DaemonUID = daemonUID()
	st.DockerGroupMissing = openshell.DockerGroupMissingInProcess()
	a.writeJSON(w, http.StatusOK, st)
}

// daemonUID is the uid this process runs as, for the sandbox doctor's
// same-user check; nil where there is none (Windows).
func daemonUID() *int {
	uid := os.Getuid()
	if uid < 0 {
		return nil
	}
	return &uid
}

// handleSandboxActivity serves the activity feed: buffered events as JSON,
// or with ?follow=true (or Accept: text/event-stream) a server-sent event
// stream that first replays what is buffered after ?since / Last-Event-ID.
func (a *APIServer) handleSandboxActivity(w http.ResponseWriter, r *http.Request) {
	q, err := sandboxapi.ParseActivityQuery(r.URL.Query(), r.Header.Get("Last-Event-ID"))
	if err != nil {
		writeSandboxError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		q.Follow = true
	}
	c, release := a.leaseSandboxController()
	if c == nil {
		release()
		writeSandboxError(w, a.sandboxDisabledError())
		return
	}
	if !q.Follow {
		events := c.ActivitySince(q.Since, q.Sandbox)
		release()
		if events == nil {
			events = []sandboxapi.ActivityEvent{}
		}
		a.writeJSON(w, http.StatusOK, map[string]any{"events": events})
		return
	}
	backlog, events, cancel, ok := c.SubscribeActivity(q.Since, q.Sandbox)
	// The subscription outlives the lease: holding it for the whole stream
	// would block a controller swap until every client disconnects.
	release()
	if !ok {
		writeSandboxError(w, &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "too many activity streams are open", Status: http.StatusTooManyRequests})
		return
	}
	defer cancel()
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	for _, ev := range backlog {
		if sandboxapi.WriteEvent(w, ev) != nil {
			return
		}
	}
	if _, err := io.WriteString(w, sandboxapi.Heartbeat); err != nil {
		return
	}
	_ = rc.Flush()
	ticker := time.NewTicker(sandboxapi.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, open := <-events:
			if !open {
				return
			}
			if sandboxapi.WriteEvent(w, ev) != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		case <-ticker.C:
			if _, err := io.WriteString(w, sandboxapi.Heartbeat); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

// decodeSandboxBody decodes a JSON body strictly. optional accepts an empty
// body (the zero value).
func decodeSandboxBody(r *http.Request, out any, optional bool) error {
	body := http.MaxBytesReader(nil, r.Body, sandboxRequestBodyMaxBytes)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) && optional {
			return nil
		}
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return &sandboxapi.Error{Code: sandboxapi.CodeInvalid, Message: "request body too large", Status: http.StatusRequestEntityTooLarge}
		}
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "invalid JSON body: %v", err)
	}
	if dec.More() {
		return sandboxapi.Errorf(sandboxapi.CodeInvalid, "invalid JSON body: trailing data")
	}
	return nil
}

func writeSandboxError(w http.ResponseWriter, err error) {
	e := sandboxapi.AsError(err)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		e = &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "the request was cancelled or timed out", Detail: err.Error(),
			Status: http.StatusGatewayTimeout}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.HTTPStatus())
	_ = json.NewEncoder(w).Encode(e)
}
