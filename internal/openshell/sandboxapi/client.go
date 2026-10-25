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
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var sandboxPeerClientFactory = hookexec.NewPerUserGatewayHTTPClient

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
	// Only per-user CLI reads retry a transient verified connection failure.
	retryReadTransport bool
}

// NewClient returns a client for baseURL authenticated with token.
func NewClient(baseURL, token string) *Client {
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token}
}

// ErrNoGatewayToken is returned by ClientForConfig while no gateway token
// exists: the daemon writes one at its first start (EnsureGatewayToken), so
// a configured daemon that never started has none, and starting it is the
// fix (GAP-0145; it said to set the gateway up first, which init had done).
// Setting it up stays the step for an account init did not set up (GAP-1918).
var ErrNoGatewayToken = errors.New("the DefenseClaw gateway has not started on this account yet; start it with `defenseclaw-gateway start` " +
	"(first `defenseclaw setup gateway` if `defenseclaw init` did not set it up)")

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
	host := strings.Trim(config.APIBindHost(cfg), "[]")
	if host == "" || host == "*" {
		host = "127.0.0.1"
	} else if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	// The sandbox CLI carries the gateway master token and may send a full
	// sandbox request body. Prove the connected peer before sending either.
	// A zero client timeout preserves context-bound image and create calls.
	httpClient, err := sandboxPeerClientFactory(0, address)
	if err != nil {
		return nil, fmt.Errorf("sandboxapi: verify per-user gateway target: %w", err)
	}
	client := NewClient("http://"+address, token)
	client.HTTP = httpClient
	client.retryReadTransport = true
	return client, nil
}

// ErrNotManagedHost is returned by ClientForHost on a computer without a
// standalone managed DefenseClaw deployment: the caller uses
// ClientForConfig there.
var ErrNotManagedHost = errors.New("sandboxapi: this computer has no standalone managed DefenseClaw deployment")

// managedDaemonBaseURL is the base URL of requests to the per-user sandbox
// daemon; the host part is never resolved (the transport dials the socket).
const managedDaemonBaseURL = "http://sandbox-daemon"

// managedHostDescriptor and managedRuntimeDir are seams for tests.
var (
	managedHostDescriptor = managed.LoadRuntimeDescriptor
	managedRuntimeDir     = func() string { return os.Getenv("XDG_RUNTIME_DIR") }
)

// ManagedSocketPath is the per-user sandbox daemon's socket for the account
// uid with home directory home: on Linux $XDG_RUNTIME_DIR/defenseclaw/
// sandbox.sock (the systemd user socket unit's %t), falling back to
// /run/user/<uid>/defenseclaw/sandbox.sock; on macOS
// ~/Library/Application Support/DefenseClaw Sandbox/sandbox.sock. It is
// "" where no daemon runs (other systems, a macOS account without a home,
// root).
func ManagedSocketPath(goos string, uid int, home string) string {
	if uid <= 0 {
		return ""
	}
	switch goos {
	case "linux":
		dir := managedRuntimeDir()
		if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			dir = "/run/user/" + strconv.Itoa(uid)
		}
		return filepath.Join(dir, "defenseclaw", "sandbox.sock")
	case "darwin":
		if home == "" || !filepath.IsAbs(home) {
			return ""
		}
		return filepath.Join(ManagedStateDir(goos, home), "sandbox.sock")
	}
	return ""
}

// ManagedStateDir is the per-user sandbox daemon's state directory for the
// account with home directory home: where it keeps the harness images it
// builds, its registrations and its sandboxes' records. On Linux
// ~/.local/state/defenseclaw-sandbox, on macOS
// ~/Library/Application Support/DefenseClaw Sandbox; "" elsewhere or without
// an absolute home. The user's own commands read the images from here too: the
// daemon builds them, and the user's DefenseClaw data directory holds none
// (GAP-0548).
func ManagedStateDir(goos, home string) string {
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	switch goos {
	case "linux":
		return filepath.Join(filepath.Clean(home), ".local", "state", "defenseclaw-sandbox")
	case "darwin":
		return filepath.Join(filepath.Clean(home), "Library", "Application Support", "DefenseClaw Sandbox")
	}
	return ""
}

// NewUnixClient returns a client of the per-user sandbox daemon listening
// on the unix socket at path. It sends no token: before every dial it
// checks that the socket is a socket owned by the caller in a directory
// nobody else can write, and the daemon checks the caller's uid in turn.
func NewUnixClient(path string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := checkDaemonSocket(path); err != nil {
				return nil, err
			}
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	}
	return &Client{BaseURL: managedDaemonBaseURL, HTTP: &http.Client{Transport: transport}}
}

// ClientForHost returns the client of the caller's own sandbox daemon when
// this computer's runtime descriptor (managed/runtime_descriptor.go) says it
// is a standalone managed deployment, and ErrNotManagedHost otherwise. An
// untrusted descriptor is an error: a managed host never falls back to a
// per-user gateway.
func ClientForHost(goos string) (*Client, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return nil, ErrNotManagedHost
	}
	if _, err := managedHostDescriptor(layout.DescriptorPath); err != nil {
		if errors.Is(err, managed.ErrNoRuntimeDescriptor) {
			return nil, ErrNotManagedHost
		}
		return nil, fmt.Errorf("sandboxapi: the managed runtime descriptor is not trusted: %w", err)
	}
	uid := os.Getuid()
	home := ""
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		home = u.HomeDir
	}
	if home == "" {
		// A directory account the pure-Go account lookup cannot see
		// (CGO_ENABLED=0 release builds read only the local files).
		home, _ = os.UserHomeDir()
	}
	path := ManagedSocketPath(goos, uid, home)
	if path == "" {
		return nil, errors.New("sandboxapi: sandboxes run under your own account, which has no sandbox daemon here")
	}
	return NewUnixClient(path), nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// do sends a JSON request and decodes its answer into out (nil skips).
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	var payload []byte
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("sandboxapi: encode request: %w", err)
		}
		payload = buf
	} else if method != http.MethodGet {
		payload = []byte("{}")
	}
	attempts := 1
	if c.retryReadTransport && method == http.MethodGet {
		attempts = 3
	}
	var resp *http.Response
	for attempt := range attempts {
		var rdr io.Reader
		if payload != nil {
			rdr = bytes.NewReader(payload)
		}
		req, err := c.newRequest(ctx, method, path, query, rdr)
		if err != nil {
			return err
		}
		resp, err = c.httpClient().Do(req)
		if err == nil {
			break
		}
		if attempt == attempts-1 || ctx.Err() != nil {
			return &Error{Code: CodeUnavailable, Message: "the DefenseClaw daemon is not reachable", Detail: err.Error()}
		}
		// The verified transport checks the connected peer again on every
		// attempt. A response or a write request is never retried here.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
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
	if c.Token != "" {
		// The managed host's per-user daemon takes no token: its socket is
		// 0600 and checks the peer's uid instead (NewUnixClient).
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
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

// Ready asks a managed computer's sandbox daemon to ready the account's
// OpenShell for a run and returns the status after it (PathReady). A daemon
// of DefenseClaw 1.0.3 or older, whose decoder refuses any field it does
// not know, refuses ReadyRequest.Harness: the request then goes again as
// the empty object that daemon takes, which judges no agent there (the
// run's create still does). Kept while a managed computer can run a 1.0.3
// daemon under a 1.0.4 CLI, through the 1.0.4 upgrade window.
func (c *Client) Ready(ctx context.Context, req ReadyRequest) (*Status, error) {
	var out Status
	err := c.do(ctx, http.MethodPost, PathReady, nil, req, &out)
	if err != nil && req.Harness != "" && unknownFieldRefused(err, "harness") {
		out = Status{}
		err = c.do(ctx, http.MethodPost, PathReady, nil, struct{}{}, &out)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// unknownFieldRefused reports an older daemon's refusal of a request field
// its strict decoder does not know (field, as JSON names it): a daemon of
// DefenseClaw 1.0.3 or older answers "invalid JSON body: json: unknown
// field" for every field 1.0.4 added.
func unknownFieldRefused(err error, field string) bool {
	e := AsError(err)
	return e.Code == CodeInvalid && strings.Contains(e.Message, `unknown field "`+field+`"`)
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
	return c.get(ctx, name, nil)
}

// QueryConfirm, with the value ConfirmPolicy, asks a managed computer's
// sandbox daemon to confirm a running sandbox's policy with the
// organization's gateway before it answers a Get (GetConfirmed). Other
// daemons ignore it.
const (
	QueryConfirm  = "confirm"
	ConfirmPolicy = "policy"
)

// GetConfirmed is Get for `sandbox status NAME`: on a managed computer the
// daemon first asks the organization's gateway for the running sandbox's
// current policy, so the status names the profile a regroup moved it to
// as `sandbox policy explain` does, or shows the stop the new profile asked
// for (GAP-0080). The daemon's 60 s poll otherwise decides when it learns.
func (c *Client) GetConfirmed(ctx context.Context, name string) (*Sandbox, error) {
	return c.get(ctx, name, url.Values{QueryConfirm: {ConfirmPolicy}})
}

func (c *Client) get(ctx context.Context, name string, query url.Values) (*Sandbox, error) {
	var out Sandbox
	if err := c.do(ctx, http.MethodGet, sandboxPath(name), query, nil, &out); err != nil {
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

// StopAcceptingUnsynced is Stop that accepts the loss of what a failed
// MicroVM disk sync did not save, once a stop was held for it
// (StopRequest.AcceptUnsynced). A daemon of DefenseClaw 1.0.4 or older,
// whose strict decoder refuses the field, holds no stop: the stop goes
// again as the empty object it takes.
func (c *Client) StopAcceptingUnsynced(ctx context.Context, name string) (*Sandbox, error) {
	var out Sandbox
	err := c.do(ctx, http.MethodPost, sandboxPath(name, "stop"), nil, StopRequest{AcceptUnsynced: true}, &out)
	if err != nil && unknownFieldRefused(err, "accept_unsynced") {
		return c.Stop(ctx, name)
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// Start starts a stopped sandbox with a freshly rotated binding.
// A daemon of DefenseClaw 1.0.3 or older refuses StartRequest.EndVM, a
// field its strict decoder does not know; it refuses no start of an ended
// MicroVM either, so the start the user asked to end the VM goes again
// without the field. Kept, like Ready's, through the 1.0.4 upgrade window.
func (c *Client) Start(ctx context.Context, name string, req StartRequest) (*Sandbox, error) {
	var out Sandbox
	err := c.do(ctx, http.MethodPost, sandboxPath(name, "start"), nil, req, &out)
	if err != nil && req.EndVM && unknownFieldRefused(err, "end_vm") {
		req.EndVM = false
		out = Sandbox{}
		err = c.do(ctx, http.MethodPost, sandboxPath(name, "start"), nil, req, &out)
	}
	if err != nil {
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

// Destinations returns what the sandbox reached or tried to reach.
func (c *Client) Destinations(ctx context.Context, name string) (*Destinations, error) {
	var out Destinations
	if err := c.do(ctx, http.MethodGet, sandboxPath(name, "destinations"), nil, nil, &out); err != nil {
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

// PolicyDecision records an allow or block in the managed decisions store.
func (c *Client) PolicyDecision(ctx context.Context, req PolicyDecisionRequest) (*PolicyDecisionResponse, error) {
	var out PolicyDecisionResponse
	if err := c.do(ctx, http.MethodPost, PathPolicyDecision, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PolicyTest judges destinations with a sandbox's egress policy.
func (c *Client) PolicyTest(ctx context.Context, req PolicyTestRequest) (*PolicyTestResult, error) {
	var out PolicyTestResult
	if err := c.do(ctx, http.MethodPost, PathPolicyTest, nil, req, &out); err != nil {
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
	if r.Sources {
		q.Set("sources", "true")
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
		Copy: b("copy"), Safe: b("safe"), Yolo: b("yolo"), Unmask: q["unmask"], Sources: b("sources"),
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
