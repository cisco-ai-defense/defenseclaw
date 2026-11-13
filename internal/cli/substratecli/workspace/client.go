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

// Package workspace is the launcher's copy-mode glue for an actor on Agent
// Substrate: a workspace.Transport over the relay's file routes, and the
// start, pull, apply, checkpoint and undo steps built on the OpenShell
// copy-mode pipeline (internal/openshell/workspace). The project is copied
// into the actor with the secrets held back, the agent's work comes back as
// a verified git bundle, and nothing lands in the project until the person
// has seen the review and accepted it.
package workspace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const (
	// DefaultRemoteRoot is where copies go when the actor does not say
	// where its working directory is.
	DefaultRemoteRoot = "/work"
	// DefaultMaxDownloadBytes caps what Download writes locally.
	DefaultMaxDownloadBytes int64 = 1 << 30

	defaultExecTimeout = 2 * time.Minute
	maxCapturedStdout  = 16 << 20
	maxCapturedStderr  = 1 << 20
	maxReplyFrame      = 64 << 20
	maxErrorBody       = 4 << 10
)

// TokenFunc returns the relay session token for one request. The token is
// sent only in the Authorization header and is never logged or put in an
// error.
type TokenFunc func(ctx context.Context) (string, error)

// Client is a workspace.Transport over the file routes of one actor's relay
// (POST /dcrelay/1/exec, PUT and GET /dcrelay/1/files). It knows nothing of
// the router: the http.Client it is given already reaches the actor, and the
// sandbox argument of every method is ignored (one actor per client).
type Client struct {
	HTTP    *http.Client
	BaseURL string
	Token   TokenFunc
	// RemoteRoot is the actor directory copies are placed in. It is empty
	// until DetectRoot (or the caller) sets it.
	RemoteRoot string
	// MaxDownloadBytes caps the content Download extracts
	// (DefaultMaxDownloadBytes when 0).
	MaxDownloadBytes int64
}

var _ osw.Transport = (*Client)(nil)

// NewClient builds a Client. hc carries the connection to the actor (already
// tunnelled), baseURL is the relay's origin, token supplies the session
// token.
func NewClient(hc *http.Client, baseURL string, token func(context.Context) (string, error)) *Client {
	if hc == nil {
		hc = &http.Client{}
	}
	return &Client{HTTP: hc, BaseURL: strings.TrimRight(baseURL, "/"), Token: token}
}

// HTTPError is a refusal by the relay, or by the cluster gateway in front of
// it (Reason set: the gateway answers JSON with a reason).
type HTTPError struct {
	Op      string
	Status  int
	Message string
	// Reason is the gateway refusal reason, such as attach_unavailable.
	Reason string
}

func (e *HTTPError) Error() string {
	if e.Reason != "" {
		return e.gatewayError()
	}
	msg := fmt.Sprintf("the actor refused %s (HTTP %d)", e.Op, e.Status)
	switch {
	case e.Status == http.StatusUnauthorized:
		msg += ": the session token was not accepted; sign in again"
	case safetext.Line(e.Message) != "":
		// The relay (inside the actor) wrote this: one clean line.
		msg += ": " + safetext.Line(e.Message)
	}
	return msg
}

// gatewayError says in plain words what the gateway answered, with what to do.
func (e *HTTPError) gatewayError() string {
	switch e.Reason {
	case "attach_unavailable":
		return "the cluster cannot connect you to agents yet: its gateway has no route to them (attach is not set up). Ask your administrator; defenseclaw substrate doctor shows the check"
	case "relay_unreachable":
		return "the cluster could not reach the agent; it may still be starting. Try again in a moment, or check it with: defenseclaw substrate status"
	case "no_actor", "not_found":
		return "the cluster has no such agent of yours; list yours with: defenseclaw substrate list"
	case "client_tag_required", "origin_blocked":
		return "the cluster refused " + e.Op + " (" + e.Reason + "); this launcher may be too old for the cluster, update DefenseClaw"
	}
	return fmt.Sprintf("the cluster refused %s (HTTP %d: %s)", e.Op, e.Status, strings.ReplaceAll(safetext.Line(e.Reason), "_", " "))
}

// request sends one request and returns the response when its status is
// ok. A refusal comes back as *HTTPError, a failure to reach the actor as a
// plain error.
func (c *Client) request(ctx context.Context, op, method, route string, q url.Values, body io.Reader, contentType string, ok ...int) (*http.Response, error) {
	u := c.BaseURL + route
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if c.Token == nil {
		return nil, errors.New("workspace: no session token source")
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("workspace: session token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	for _, s := range ok {
		if resp.StatusCode == s {
			return resp, nil
		}
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	resp.Body.Close()
	msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "relay: "))
	herr := &HTTPError{Op: op, Status: resp.StatusCode, Message: msg}
	// The gateway in front of the relay answers {"error": ..., "reason": ...}.
	var g struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	if json.Unmarshal(b, &g) == nil && g.Reason != "" {
		herr.Reason = g.Reason
	}
	return nil, herr
}

// DetectRoot asks the relay for the actor's working directory (the image
// WORKDIR, "workdir" in GET /dcrelay/1/status), sets RemoteRoot to it, and
// returns it. A relay that does not say gets DefaultRemoteRoot.
func (c *Client) DetectRoot(ctx context.Context) (string, error) {
	resp, err := c.request(ctx, "the status request", http.MethodGet, "/dcrelay/1/status", nil, nil, "", http.StatusOK)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var st struct {
		Workdir string `json:"workdir"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil {
		return "", fmt.Errorf("workspace: the actor's status is unreadable: %w", err)
	}
	root := st.Workdir
	if !strings.HasPrefix(root, "/") || root == "/" {
		root = DefaultRemoteRoot
	}
	c.RemoteRoot = root
	return root, nil
}

// Root returns RemoteRoot, asking the relay for it first when it is not set.
func (c *Client) Root(ctx context.Context) (string, error) {
	if c.RemoteRoot != "" {
		return c.RemoteRoot, nil
	}
	return c.DetectRoot(ctx)
}

// capBuf keeps the first limit bytes written to it.
type capBuf struct {
	bytes.Buffer
	limit int
}

func (b *capBuf) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// writeErr remembers the first error of the writer it wraps, to tell it
// from a read error of the reply.
type writeErr struct {
	w   io.Writer
	err error
}

func (w *writeErr) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if err == nil && n < len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && w.err == nil {
		w.err = err
	}
	return n, err
}

// Exec implements workspace.Execer. The command runs without a shell and
// with empty stdin; stdout goes to req.Stdout as it arrives (the first write
// error stops the command and is returned), else it is collected, up to
// 16 MiB. A command stopped at its timeout fails with an error wrapping
// openshell.ErrExecTimeout. An Idempotent command is sent again when no
// answer came back at all.
func (c *Client) Exec(ctx context.Context, _ string, req osw.ExecRequest) (*osw.ExecResult, error) {
	if len(req.Argv) == 0 || req.Argv[0] == "" {
		return nil, errors.New("workspace: exec needs a command")
	}
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultExecTimeout
	}
	body, err := json.Marshal(relay.ExecRequest{
		Argv: req.Argv, Workdir: req.Workdir, Env: req.Env,
		TimeoutSeconds: int((timeout + time.Second - 1) / time.Second),
	})
	if err != nil {
		return nil, err
	}
	attempts := 1
	if req.Idempotent {
		attempts = 3
	}
	var resp *http.Response
	for i := 1; ; i++ {
		resp, err = c.request(ctx, "the command", http.MethodPost, "/dcrelay/1/exec", nil, bytes.NewReader(body), "application/json", http.StatusOK)
		var refused *HTTPError
		if err == nil || errors.As(err, &refused) || i >= attempts || ctx.Err() != nil {
			break
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("workspace: exec in the actor: %w", err)
	}
	defer resp.Body.Close()

	stdout := &capBuf{limit: maxCapturedStdout}
	stderr := &capBuf{limit: maxCapturedStderr}
	var lastErr []byte
	out := io.Writer(stdout)
	if req.Stdout != nil {
		out = req.Stdout
	}
	br := bufio.NewReaderSize(resp.Body, 64<<10)
	for {
		var h [5]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, fmt.Errorf("workspace: the actor's reply ended before the command finished: %w", err)
		}
		n := int64(binary.BigEndian.Uint32(h[1:]))
		if n > maxReplyFrame {
			return nil, fmt.Errorf("workspace: the actor sent a %d-byte frame", n)
		}
		switch h[0] {
		case relay.ExecStdout:
			w := &writeErr{w: out}
			if _, err := io.CopyN(w, br, n); err != nil {
				if w.err != nil {
					// The caller's writer refused: stop, as the command is
					// stopped when the connection closes.
					return nil, w.err
				}
				return nil, fmt.Errorf("workspace: the actor's reply ended before the command finished: %w", err)
			}
		case relay.ExecStderr:
			p := make([]byte, n)
			if _, err := io.ReadFull(br, p); err != nil {
				return nil, fmt.Errorf("workspace: the actor's reply ended before the command finished: %w", err)
			}
			stderr.Write(p)
			lastErr = p
		case relay.ExecExit:
			p := make([]byte, n)
			if _, err := io.ReadFull(br, p); err != nil {
				return nil, fmt.Errorf("workspace: the actor's reply ended before the command finished: %w", err)
			}
			code, err := strconv.Atoi(string(p))
			if err != nil {
				return nil, fmt.Errorf("workspace: the actor sent exit status %q", p)
			}
			switch {
			case code == relay.ExitTimedOut && string(lastErr) == "timed out":
				return nil, fmt.Errorf("workspace: exec in the actor: %w: the actor stopped the command after %s", openshell.ErrExecTimeout, timeout)
			case code == relay.ExitOutputLimit && bytes.HasPrefix(lastErr, []byte("output limit of")):
				return nil, fmt.Errorf("workspace: exec in the actor: the command printed more than the actor's output limit (%s)", lastErr)
			}
			res := &osw.ExecResult{ExitCode: code, Stderr: stderr.Bytes()}
			if req.Stdout == nil {
				res.Stdout = stdout.Bytes()
			}
			return res, nil
		default:
			return nil, fmt.Errorf("workspace: the actor sent a frame of type %d", h[0])
		}
	}
}

var errUploadDone = errors.New("upload finished")

// Upload implements workspace.Uploader: localPath (a file or directory) is
// archived as it is read and streamed to the actor, where it lands at
// remoteDir/<basename(localPath)> with its modes and symlinks. remoteDir is
// created when missing. No temporary file is written.
func (c *Client) Upload(ctx context.Context, _, localPath, remoteDir string) error {
	if _, err := os.Lstat(localPath); err != nil {
		return fmt.Errorf("workspace: upload: %w", err)
	}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := relay.WriteTar(pw, localPath)
		pw.CloseWithError(err) // nil closes with EOF
		done <- err
	}()
	resp, err := c.request(ctx, "the upload", http.MethodPut, "/dcrelay/1/files", url.Values{"dir": {remoteDir}}, pr, "application/x-tar", http.StatusNoContent)
	pr.CloseWithError(errUploadDone)
	tarErr := <-done
	if err != nil {
		// A failure to read the local files is the better explanation of a
		// broken request.
		if tarErr != nil && !errors.Is(tarErr, errUploadDone) && !errors.Is(tarErr, io.ErrClosedPipe) {
			return fmt.Errorf("workspace: upload %s: %w", localPath, tarErr)
		}
		var refused *HTTPError
		if errors.As(err, &refused) {
			return fmt.Errorf("workspace: upload to the actor: %w", err)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("workspace: upload to the actor: %w", err)
	}
	resp.Body.Close()
	return nil
}

// Download implements workspace.Downloader: remotePath (a file or
// directory in the actor) is archived there and extracted into the existing
// directory localDir as localDir/<basename(remotePath)>. The extraction
// refuses entries that leave localDir.
func (c *Client) Download(ctx context.Context, _, remotePath, localDir string) error {
	if fi, err := os.Stat(localDir); err != nil || !fi.IsDir() {
		return fmt.Errorf("workspace: download: %s is not a directory", localDir)
	}
	resp, err := c.request(ctx, "the download", http.MethodGet, "/dcrelay/1/files", url.Values{"path": {remotePath}}, nil, "", http.StatusOK)
	if err != nil {
		var refused *HTTPError
		if errors.As(err, &refused) && refused.Status == http.StatusNotFound {
			return fmt.Errorf("workspace: download: %s does not exist in the actor", remotePath)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("workspace: download from the actor: %w", err)
	}
	defer resp.Body.Close()
	limit := c.MaxDownloadBytes
	if limit <= 0 {
		limit = DefaultMaxDownloadBytes
	}
	if _, err := relay.ExtractTar(resp.Body, localDir, relay.ExtractOptions{MaxBytes: limit}); err != nil {
		return fmt.Errorf("workspace: download %s: %w", remotePath, err)
	}
	return nil
}
