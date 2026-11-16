// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testEntry() config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: "notes", Command: "npx", Args: []string{"-y", ".", "--config", `.\srv.json`},
		Env: map[string]string{"NOTES_TOKEN": "x"}, Connector: "claudecode",
		Project: `C:\Users\dcw-std1\proj`, Home: `C:\Users\dcw-std1`,
	}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	request, err := NewRequest("DefenseClawGateway", "s-1-5-21-1-2-3-1001", testEntry())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestRequestArgRoundTripAndValidation(t *testing.T) {
	request := testRequest(t)
	if request.SID != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("SID not normalized: %q", request.SID)
	}
	arg, err := EncodeRequestArg(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequestArg(arg)
	if err != nil || decoded != request {
		t.Fatalf("round trip: %+v, %v", decoded, err)
	}
	bad := []func(*Request){
		func(r *Request) { r.Version = 2 },
		func(r *Request) { r.GatewayService = `x\y` },
		func(r *Request) { r.SID = "S-1-5-18-x" },
		func(r *Request) { r.Connector = "opencode" },
		func(r *Request) { r.Name = "" },
		func(r *Request) { r.Name = "a\nb" },
		func(r *Request) { r.Project = "C:\\p\x00" },
		func(r *Request) { r.Digest = "abc" },
	}
	// Codex servers of an enrolled account are published, so they can be
	// started as their user for the scan (GAP-0686).
	codex := request
	codex.Connector = "codex"
	if _, err := EncodeRequestArg(codex); err != nil {
		t.Fatalf("a published Codex server was refused: %v", err)
	}
	for i, mutate := range bad {
		changed := request
		mutate(&changed)
		if _, err := EncodeRequestArg(changed); !errors.Is(err, ErrProtocol) {
			t.Fatalf("case %d: encoded an invalid request: %v", i, err)
		}
	}
	for _, arg := range []string{"", "!!", strings.Repeat("A", maxRequestArgBytes+1)} {
		if _, err := DecodeRequestArg(arg); !errors.Is(err, ErrProtocol) {
			t.Fatalf("decoded %q: %v", arg, err)
		}
	}
	// A request never carries a command: an extra field is refused.
	if _, err := decodeRequest([]byte(`{"version":1,"gateway_service":"G","sid":"S-1-5-21-1-2-3","connector":"kiro","name":"n","digest":"` +
		strings.Repeat("a", 64) + `","command":"cmd.exe"}`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("accepted a request with a command: %v", err)
	}
	valid, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeRequest(valid); err != nil {
		t.Fatalf("refused a valid request: %v", err)
	}
	for _, trailing := range []string{"}", "]", " {}", "x"} {
		if _, err := decodeRequest(append(append([]byte{}, valid...), trailing...)); !errors.Is(err, ErrProtocol) {
			t.Fatalf("accepted a request followed by %q: %v", trailing, err)
		}
	}
}

func TestDigestFollowsTheLaunchDefinition(t *testing.T) {
	base := testEntry()
	digest := Digest(base)
	same := base
	same.Home, same.Connector, same.Args, same.Env = `D:\elsewhere`, "kiro", append([]string(nil), base.Args...), map[string]string{"NOTES_TOKEN": "x"}
	if Digest(same) != digest {
		t.Fatal("digest depends on fields the launch does not use")
	}
	empty := base
	empty.Args, empty.Env = []string{}, map[string]string{}
	none := base
	none.Args, none.Env = nil, nil
	if Digest(empty) != Digest(none) {
		t.Fatal("empty and absent args or env digest differently")
	}
	for name, change := range map[string]func(*config.MCPServerEntry){
		"command": func(e *config.MCPServerEntry) { e.Command = "uvx" },
		"args":    func(e *config.MCPServerEntry) { e.Args = []string{"-y", "evil"} },
		"env":     func(e *config.MCPServerEntry) { e.Env = map[string]string{"NOTES_TOKEN": "y"} },
		"cwd":     func(e *config.MCPServerEntry) { e.CWD = "sub" },
		"project": func(e *config.MCPServerEntry) { e.Project = `C:\Users\dcw-std2\proj` },
		"name":    func(e *config.MCPServerEntry) { e.Name = "other" },
	} {
		changed := base
		change(&changed)
		if Digest(changed) == digest {
			t.Fatalf("a changed %s keeps the digest", name)
		}
	}
}

func TestFramesRejectOversizedPayloads(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, FrameStdout, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("wrote an oversized frame: %v", err)
	}
	header := []byte{FrameStdout, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := ReadFrame(bytes.NewReader(header)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("read an oversized frame: %v", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{FrameStdout, 0, 0, 0, 4, 'a'})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short frame: %v", err)
	}
	if name, err := PipeName("DefenseClawGateway"); err != nil || name != `\\.\pipe\DefenseClaw-DefenseClawGateway-mcp-as-user` {
		t.Fatalf("pipe name %q, %v", name, err)
	}
	if _, err := PipeName(`..\x`); err == nil {
		t.Fatal("pipe name accepted a path")
	}
}

// echoSession is a server that answers each stdin line on stdout, writes a
// stderr line and exits with code once stdin closes.
type echoSession struct {
	stdinR, stdoutR, stderrR *io.PipeReader
	stdinW, stdoutW, stderrW *io.PipeWriter
	code                     int
	done                     chan struct{}
	killOnce                 sync.Once
	killed                   chan struct{}
}

func newEchoSession(code int, hang bool) *echoSession {
	s := &echoSession{code: code, done: make(chan struct{}), killed: make(chan struct{})}
	s.stdinR, s.stdinW = io.Pipe()
	s.stdoutR, s.stdoutW = io.Pipe()
	s.stderrR, s.stderrW = io.Pipe()
	go func() {
		defer close(s.done)
		_, _ = s.stderrW.Write([]byte("server starting\n"))
		scanner := bufio.NewScanner(s.stdinR)
		for scanner.Scan() {
			_, _ = s.stdoutW.Write([]byte("echo:" + scanner.Text() + "\n"))
		}
		if hang {
			<-s.killed
		}
		_ = s.stdoutW.Close()
		_ = s.stderrW.Close()
	}()
	return s
}

func (s *echoSession) Stdin() io.WriteCloser { return s.stdinW }
func (s *echoSession) Stdout() io.Reader     { return s.stdoutR }
func (s *echoSession) Stderr() io.Reader     { return s.stderrR }
func (s *echoSession) Wait() (int, error) {
	<-s.done
	select {
	case <-s.killed:
		return 1, nil
	default:
		return s.code, nil
	}
}
func (s *echoSession) Kill() {
	s.killOnce.Do(func() {
		close(s.killed)
		_ = s.stdinR.CloseWithError(io.ErrClosedPipe)
	})
}
func (s *echoSession) Close() { s.Kill() }

func TestRelayAndServeCarryStdioAndExitCode(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	request := testRequest(t)
	var started Request
	served := make(chan error, 1)
	go func() {
		got, err := ServeConn(context.Background(), serverConn, nil, func(_ context.Context, r Request) (Session, error) {
			started = r
			return newEchoSession(7, false), nil
		}, time.Minute)
		_ = serverConn.Close()
		if got != request {
			err = errors.Join(err, errors.New("served another request"))
		}
		served <- err
	}()
	var stdout, stderr bytes.Buffer
	code, err := RunRelay(relayConn, request, strings.NewReader("one\ntwo\n"), &stdout, &stderr)
	_ = relayConn.Close()
	if err != nil || code != 7 {
		t.Fatalf("relay: code %d, %v", code, err)
	}
	if started != request {
		t.Fatalf("starter got %+v", started)
	}
	if stdout.String() != "echo:one\necho:two\n" || stderr.String() != "server starting\n" {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if err := <-served; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestRelayReportsTheRefusal(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, nil, func(context.Context, Request) (Session, error) {
			return nil, errors.New("dcw-std1 is not signed in")
		}, time.Minute)
		_ = serverConn.Close()
	}()
	_, err := RunRelay(relayConn, testRequest(t), strings.NewReader(""), io.Discard, io.Discard)
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Reason != "dcw-std1 is not signed in" {
		t.Fatalf("refusal: %v", err)
	}
}

func TestServeKillsTheServerWhenTheRelayGoesAway(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	session := newEchoSession(0, true)
	served := make(chan error, 1)
	go func() {
		_, err := ServeConn(context.Background(), serverConn, nil, func(context.Context, Request) (Session, error) {
			return session, nil
		}, time.Minute)
		served <- err
	}()
	if err := writeJSONFrame(relayConn, FrameRequest, testRequest(t)); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := ReadFrame(relayConn); err != nil || kind != FrameAnswer {
		t.Fatalf("answer %q, %v", kind, err)
	}
	go func() { _, _ = io.Copy(io.Discard, relayConn) }()
	_ = relayConn.Close()
	select {
	case <-session.killed:
	case <-time.After(stdinGrace + 5*time.Second):
		t.Fatal("the server outlived its relay")
	}
	_ = serverConn.Close()
	<-served
}

func TestServeKillsTheServerAtTheSessionLimit(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	session := newEchoSession(0, true)
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, nil, func(context.Context, Request) (Session, error) {
			return session, nil
		}, 100*time.Millisecond)
		_ = serverConn.Close()
	}()
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close()
	code, err := RunRelay(relayConn, testRequest(t), stdinR, io.Discard, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("limit: code %d, %v", code, err)
	}
	select {
	case <-session.killed:
	default:
		t.Fatal("the server was not killed at the limit")
	}
}

func TestServeRefusesAMalformedRequest(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, nil, func(context.Context, Request) (Session, error) {
			t.Error("started a server for a malformed request")
			return nil, errors.New("unreachable")
		}, time.Minute)
		_ = serverConn.Close()
	}()
	if err := WriteFrame(relayConn, FrameRequest, []byte(`{"version":1,"command":"cmd.exe"}`)); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := ReadFrame(relayConn)
	if err != nil || kind != FrameAnswer || !strings.Contains(string(payload), `"ok":false`) {
		t.Fatalf("answer %q %s, %v", kind, payload, err)
	}
}

// GAP-0216: the gateway asks the enumerator to publish the enrolled users'
// MCP servers again before it decides a tool call; the answer comes once the
// publish is done, and no server is started for it.
func TestRefreshIsAnsweredOnceThePublishIsDone(t *testing.T) {
	for _, tc := range []struct {
		name    string
		refresh Refresher
		want    string
	}{
		{"published", func(context.Context) error { return nil }, ""},
		{"publish failed", func(context.Context) error { return errors.New("manifest unreadable") }, "manifest unreadable"},
		{"no refresher", nil, "does not publish MCP servers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gatewayConn, serverConn := net.Pipe()
			calls := 0
			refresh := tc.refresh
			if refresh != nil {
				inner := refresh
				refresh = func(ctx context.Context) error { calls++; return inner(ctx) }
			}
			served := make(chan struct{})
			go func() {
				defer close(served)
				_, _ = ServeConn(context.Background(), serverConn, refresh, func(context.Context, Request) (Session, error) {
					t.Error("a refresh started a server")
					return nil, errors.New("no")
				}, time.Minute)
				_ = serverConn.Close()
			}()
			err := RequestRefresh(gatewayConn, "DefenseClawGateway")
			_ = gatewayConn.Close()
			<-served
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("RequestRefresh: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("RequestRefresh = %v, want an error naming %q", err, tc.want)
			}
			if tc.refresh != nil && calls != 1 {
				t.Fatalf("refresh ran %d times, want once", calls)
			}
		})
	}
}

func TestMalformedRefreshIsRefusedWithoutAPublish(t *testing.T) {
	for _, payload := range []string{
		`{"version":2,"gateway_service":"DefenseClawGateway"}`,
		`{"version":1,"gateway_service":"bad name"}`,
		`{"version":1,"gateway_service":"DefenseClawGateway","sid":"S-1-5-18"}`,
		`{"version":1,"gateway_service":"DefenseClawGateway"}}`,
	} {
		gatewayConn, serverConn := net.Pipe()
		published := false
		served := make(chan error, 1)
		go func() {
			_, err := ServeConn(context.Background(), serverConn, func(context.Context) error { published = true; return nil }, nil, time.Minute)
			_ = serverConn.Close()
			served <- err
		}()
		if err := WriteFrame(gatewayConn, FrameRefresh, []byte(payload)); err != nil {
			t.Fatal(err)
		}
		kind, answer, err := ReadFrame(gatewayConn)
		_ = gatewayConn.Close()
		if err != nil || kind != FrameAnswer || !strings.Contains(string(answer), `"ok":false`) {
			t.Fatalf("%s: answer %q %q (%v), want a refusal", payload, kind, answer, err)
		}
		if err := <-served; !errors.Is(err, ErrProtocol) {
			t.Fatalf("%s: ServeConn = %v, want a protocol error", payload, err)
		}
		if published {
			t.Fatalf("%s: a malformed refresh published", payload)
		}
	}
}

// A caller is answered by a publish that started after it asked: callers
// that wait while a publish runs share the next one, and none of them gets
// the result of the publish that was already running.
func TestCoalescerAnswersWithAPublishStartedAfterTheCall(t *testing.T) {
	var c Coalescer
	running := make(chan struct{})
	release := make(chan struct{})
	var publishes atomic.Int32
	first := make(chan error, 1)
	go func() {
		first <- c.Run(context.Background(), func() error {
			publishes.Add(1)
			close(running)
			<-release
			return errors.New("old state")
		})
	}()
	<-running
	waiters := make(chan error, 3)
	for range 3 {
		go func() {
			waiters <- c.Run(context.Background(), func() error { publishes.Add(1); return nil })
		}()
	}
	// The waiters asked while the first publish ran; let them queue.
	time.Sleep(50 * time.Millisecond)
	close(release)
	if err := <-first; err == nil {
		t.Fatal("the first caller lost its own result")
	}
	for range 3 {
		if err := <-waiters; err != nil {
			t.Fatalf("a waiter got the result of the publish that started before it asked: %v", err)
		}
	}
	if got := publishes.Load(); got != 2 {
		t.Fatalf("%d publishes, want 2 (the running one and one shared by the waiters)", got)
	}
}

// A caller stops waiting when its context ends, also while another caller's
// publish runs, and never publishes after that (GAP-0216: the gateway's
// refresh before a tool call must end inside the hook's wait).
func TestCoalescerWaiterStopsAtItsOwnDeadline(t *testing.T) {
	var c Coalescer
	running, release := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- c.Run(context.Background(), func() error { close(running); <-release; return nil })
	}()
	<-running
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var published atomic.Bool
	started := time.Now()
	err := c.Run(ctx, func() error { published.Store(true); return nil })
	if !errors.Is(err, context.DeadlineExceeded) || published.Load() {
		t.Fatalf("waiter = %v (published %v), want its deadline and no publish", err, published.Load())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("waiter waited %s for another caller's publish, want its own deadline", elapsed)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first caller: %v", err)
	}
	if err := c.Run(context.Background(), func() error { published.Store(true); return nil }); err != nil || !published.Load() {
		t.Fatalf("next caller = %v (published %v), want a publish of its own", err, published.Load())
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	published.Store(false)
	if err := c.Run(done, func() error { published.Store(true); return nil }); err == nil || published.Load() {
		t.Fatalf("ended caller = %v (published %v), want no publish", err, published.Load())
	}
}
