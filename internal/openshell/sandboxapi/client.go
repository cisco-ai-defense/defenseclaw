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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Client is a typed client of the daemon's sandbox API.
type Client struct {
	// BaseURL is http://<api host>:<api port>.
	BaseURL string
	// Token is the gateway master token.
	Token string
	// HTTP defaults to a client without an overall timeout (create may
	// build an image, activity streams); per-call deadlines come from ctx.
	HTTP *http.Client
	// UserAgent defaults to ClientName.
	UserAgent string
}

// NewClient returns a client for baseURL authenticated with token.
func NewClient(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token}
}

// ErrNoGatewayToken is returned by ClientForConfig before the gateway is set
// up (no gateway token is configured yet).
var ErrNoGatewayToken = errors.New("the DefenseClaw gateway is not set up yet; run `defenseclaw setup gateway`, then `defenseclaw-gateway start`")

// ClientForConfig returns a client for the daemon cfg describes: its API
// bind host and port and the resolved gateway token.
func ClientForConfig(cfg *config.Config) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("sandboxapi: no configuration")
	}
	token := cfg.Gateway.ResolvedToken()
	if token == "" {
		return nil, ErrNoGatewayToken
	}
	port := cfg.Gateway.APIPort
	if port <= 0 {
		port = config.DefaultGatewayAPIPort
	}
	host := config.APIBindHost(cfg)
	return NewClient("http://"+net.JoinHostPort(host, strconv.Itoa(port)), token), nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// do sends one JSON request and decodes a JSON answer into out (nil skips).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sandboxapi: encode request: %w", err)
		}
		rdr = bytes.NewReader(buf)
	} else if method != http.MethodGet {
		rdr = strings.NewReader("{}")
	}
	req, err := c.newRequest(ctx, method, path, query, rdr)
	if err != nil {
		return err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return &Error{Code: CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil {
		return fmt.Errorf("sandboxapi: decode %s %s: %w", method, path, err)
	}
	return nil
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Request, error) {
	u := c.BaseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("sandboxapi: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set(ClientHeader, ClientName)
	ua := c.UserAgent
	if ua == "" {
		ua = ClientName
	}
	req.Header.Set("User-Agent", ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func decodeError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	e := &Error{}
	if err := json.Unmarshal(raw, e); err != nil || (e.Code == "" && e.Message == "") {
		msg := strings.TrimSpace(string(raw))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		e = &Error{Code: codeForStatus(resp.StatusCode), Message: msg}
	}
	if e.Code == "" {
		e.Code = codeForStatus(resp.StatusCode)
	}
	e.Status = resp.StatusCode
	return e
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalid
	case http.StatusUnauthorized, http.StatusForbidden:
		return CodePolicyViolation
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	case http.StatusBadGateway:
		return CodeUpstream
	default:
		return CodeInternal
	}
}

func sandboxPath(name string, verb ...string) string {
	p := PathSandboxes + "/" + url.PathEscape(name)
	for _, v := range verb {
		p += "/" + v
	}
	return p
}

// Status returns the subsystem status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	var out Status
	if err := c.do(ctx, http.MethodGet, PathStatus, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// List returns every DefenseClaw sandbox.
func (c *Client) List(ctx context.Context) ([]Sandbox, error) {
	var out struct {
		Sandboxes []Sandbox `json:"sandboxes"`
	}
	if err := c.do(ctx, http.MethodGet, PathSandboxes, nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Sandboxes, nil
}

// Get returns one sandbox.
func (c *Client) Get(ctx context.Context, name string) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodGet, sandboxPath(name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Create creates and starts a sandbox and returns it once it is ready.
func (c *Client) Create(ctx context.Context, req CreateRequest) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodPost, PathSandboxes, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Delete deletes a sandbox, its providers and its binding.
func (c *Client) Delete(ctx context.Context, name string, req DeleteRequest) (*DeleteResponse, error) {
	var out DeleteResponse
	if err := c.do(ctx, http.MethodDelete, sandboxPath(name), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Stop stops a sandbox and keeps it for a later start.
func (c *Client) Stop(ctx context.Context, name string) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "stop"), nil, struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Start starts a stopped sandbox with a freshly rotated binding.
func (c *Client) Start(ctx context.Context, name string, req StartRequest) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "start"), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Undo restores the project to its pre-session snapshot.
func (c *Client) Undo(ctx context.Context, name string, req UndoRequest) (*UndoResponse, error) {
	var out UndoResponse
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "undo"), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Accept records that the user kept the changes on top of a stopped
// mounted sandbox's snapshot: its next start takes a new one.
func (c *Client) Accept(ctx context.Context, name string, req AcceptRequest) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "accept"), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RunLog returns the log of the sandbox's latest detached run that the
// daemon kept when it stopped the sandbox: its last lines lines (all of it
// when lines is 0).
func (c *Client) RunLog(ctx context.Context, name string, lines int) (*RunLog, error) {
	var q url.Values
	if lines > 0 {
		q = url.Values{"lines": {strconv.Itoa(lines)}}
	}
	var out RunLog
	if err := c.do(ctx, http.MethodGet, sandboxPath(name, "logs"), q, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ParseRunLogLines reads the ?lines query of GET /sandboxes/{name}/logs
// (0: the whole kept log).
func ParseRunLogLines(v url.Values) (int, error) {
	s := strings.TrimSpace(v.Get("lines"))
	if s == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, Errorf(CodeInvalid, "lines must be a number of lines (0 for the whole log)")
	}
	return n, nil
}

// Review returns the end-of-session review of a mounted project.
func (c *Client) Review(ctx context.Context, name string, req ReviewRequest) (*ReviewResponse, error) {
	var out ReviewResponse
	if err := c.do(ctx, http.MethodPost, sandboxPath(name, "review"), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ReportWorkspace records a copy-mode workspace step the CLI ran.
func (c *Client) ReportWorkspace(ctx context.Context, name string, r WorkspaceReport) error {
	return c.do(ctx, http.MethodPost, sandboxPath(name, "workspace"), nil, r, nil)
}

// Approvals lists pending asks, optionally for one sandbox.
func (c *Client) Approvals(ctx context.Context, sandbox string) ([]Approval, error) {
	q := url.Values{}
	if sandbox != "" {
		q.Set("sandbox", sandbox)
	}
	var out struct {
		Approvals []Approval `json:"approvals"`
	}
	if err := c.do(ctx, http.MethodGet, PathApprovals, q, nil, &out); err != nil {
		return nil, err
	}
	return out.Approvals, nil
}

// Decide approves or rejects one ask.
func (c *Client) Decide(ctx context.Context, id string, d ApprovalDecision) (*ApprovalResult, error) {
	var out ApprovalResult
	if err := c.do(ctx, http.MethodPost, PathApprovals+"/"+url.PathEscape(id), nil, d, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Unblock lifts an egress block for one sandbox or always.
func (c *Client) Unblock(ctx context.Context, req UnblockRequest) (*UnblockResponse, error) {
	var out UnblockResponse
	if err := c.do(ctx, http.MethodPost, PathEgressUnblock, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Explain resolves the sandbox posture with provenance.
func (c *Client) Explain(ctx context.Context, req ExplainRequest) (*Explain, error) {
	var out Explain
	if err := c.do(ctx, http.MethodGet, PathPolicyExplain, req.Query(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Query encodes the request as URL query parameters.
func (r ExplainRequest) Query() url.Values {
	q := url.Values{}
	set := func(k, v string) {
		if v != "" {
			q.Set(k, v)
		}
	}
	set("sandbox", r.Sandbox)
	set("harness", r.Harness)
	set("pack", r.Pack)
	set("profile", r.Profile)
	set("project", r.Project)
	if r.Copy {
		q.Set("copy", "true")
	}
	if r.Safe {
		q.Set("safe", "true")
	}
	if r.Yolo {
		q.Set("yolo", "true")
	}
	for _, u := range r.Unmask {
		q.Add("unmask", u)
	}
	if run := r.Run; run != nil {
		q.Set("run", "true")
		keys := make([]string, 0, len(run.Env))
		for k := range run.Env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			q.Add("run_env", k+"="+run.Env[k])
		}
		for _, k := range run.EnvWithheld {
			q.Add("run_env_withheld", k)
		}
		for _, name := range run.Credentials {
			q.Add("run_credential", name)
		}
		set("run_llm_profile", run.LLMProfile)
		set("run_bedrock_region", run.BedrockRegion)
	}
	return q
}

// ParseExplainQuery is the inverse of ExplainRequest.Query.
func ParseExplainQuery(q url.Values) ExplainRequest {
	b := func(k string) bool { v, _ := strconv.ParseBool(q.Get(k)); return v }
	req := ExplainRequest{
		Sandbox: q.Get("sandbox"), Harness: q.Get("harness"), Pack: q.Get("pack"),
		Profile: q.Get("profile"), Project: q.Get("project"),
		Copy: b("copy"), Safe: b("safe"), Yolo: b("yolo"), Unmask: q["unmask"],
	}
	if b("run") {
		run := &ExplainRun{EnvWithheld: q["run_env_withheld"], Credentials: q["run_credential"],
			LLMProfile: q.Get("run_llm_profile"), BedrockRegion: q.Get("run_bedrock_region")}
		for _, kv := range q["run_env"] {
			if k, v, ok := strings.Cut(kv, "="); ok && k != "" {
				if run.Env == nil {
					run.Env = map[string]string{}
				}
				run.Env[k] = v
			}
		}
		req.Run = run
	}
	return req
}

// Query encodes the activity query.
func (q ActivityQuery) Query() url.Values {
	v := url.Values{}
	if q.Sandbox != "" {
		v.Set("sandbox", q.Sandbox)
	}
	if q.Since > 0 {
		v.Set("since", strconv.FormatUint(q.Since, 10))
	}
	if q.Follow {
		v.Set("follow", "true")
	}
	return v
}

// ParseActivityQuery is the inverse of ActivityQuery.Query. A Last-Event-ID
// header value, when given, wins over ?since.
func ParseActivityQuery(v url.Values, lastEventID string) (ActivityQuery, error) {
	q := ActivityQuery{Sandbox: v.Get("sandbox")}
	since := v.Get("since")
	if strings.TrimSpace(lastEventID) != "" {
		since = strings.TrimSpace(lastEventID)
	}
	if since != "" {
		n, err := strconv.ParseUint(since, 10, 64)
		if err != nil {
			return q, Errorf(CodeInvalid, "since must be an event sequence number")
		}
		q.Since = n
	}
	if f := v.Get("follow"); f != "" {
		b, err := strconv.ParseBool(f)
		if err != nil {
			return q, Errorf(CodeInvalid, "follow must be true or false")
		}
		q.Follow = b
	}
	return q, nil
}

// Activity returns buffered activity (Follow false) or streams it until ctx
// ends or fn returns an error (Follow true). fn runs for every event.
func (c *Client) Activity(ctx context.Context, q ActivityQuery, fn func(ActivityEvent) error) error {
	if !q.Follow {
		var out struct {
			Events []ActivityEvent `json:"events"`
		}
		if err := c.do(ctx, http.MethodGet, PathActivity, q.Query(), nil, &out); err != nil {
			return err
		}
		for _, ev := range out.Events {
			if err := fn(ev); err != nil {
				return err
			}
		}
		return nil
	}
	req, err := c.newRequest(ctx, http.MethodGet, PathActivity, q.Query(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return &Error{Code: CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return decodeError(resp)
	}
	return ReadEvents(resp.Body, fn)
}

// ReadEvents parses a text/event-stream of activity events.
func ReadEvents(r io.Reader, fn func(ActivityEvent) error) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	var data strings.Builder
	dispatch := func() error {
		if data.Len() == 0 {
			return nil
		}
		var ev ActivityEvent
		err := json.Unmarshal([]byte(data.String()), &ev)
		data.Reset()
		if err != nil {
			return fmt.Errorf("sandboxapi: decode activity event: %w", err)
		}
		return fn(ev)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if err := dispatch(); err != nil {
				return err
			}
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return dispatch()
}

// WriteEvent writes ev as one SSE message.
func WriteEvent(w io.Writer, ev ActivityEvent) error {
	buf, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: activity\ndata: %s\n\n", ev.Seq, buf)
	return err
}

// Heartbeat is the SSE comment the server sends to keep idle streams open.
const Heartbeat = ": keepalive\n\n"

// HeartbeatInterval paces heartbeats.
const HeartbeatInterval = 15 * time.Second
