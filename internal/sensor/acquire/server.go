// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package acquire

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

// ServerConfig is the helper's own configuration.
//
// It is read from a root-owned file, never from a client. HomeDirs is the
// clearest example of why: if the caller could name the directories to
// watch, a compromised gateway could point a root process at anything on the
// host and read the results back. The helper decides; the client asks.
type ServerConfig struct {
	// HomeDirs are the user homes whose credential and agent-config paths
	// Plane C watches.
	HomeDirs []string
	// AllowedUIDs are the peer uids permitted to connect. Empty means only
	// the uid running the helper, which on a correct install is root and
	// therefore effectively denies everyone.
	AllowedUIDs []int
	// Logger receives refusals and acquisition errors.
	Logger *slog.Logger
	// Tetragon is the managed Linux helper's Tetragon intent. nil
	// everywhere else: the per-user gateway's Local acquirer never builds a
	// Tetragon source, even when it runs as root.
	Tetragon *TetragonConfig
}

// TetragonConfig is the helper's Tetragon intent: the values the enterprise
// lifecycle renders into the helper's root-owned service drop-in (from
// enterprise.tetragon), never anything a client sent.
type TetragonConfig struct {
	// Mode is the effective mode (the Plane C cap applied): off, consume,
	// observe or enforce.
	Mode string
	// BurnIn is the covered agent time a uid needs before it is enforced
	// (0 skips it, with a warning).
	BurnIn time.Duration
	// EnforceAck is the approved kernel_policy digest ("" when none).
	EnforceAck string
	// EnforceConnectors are the enrolled connectors whose effective
	// guardrail mode is action: only they can be anchored for enforcement.
	EnforceConnectors []string
	// Dial opens a Tetragon event session (tetragon.NewDialer). With Mode
	// off, or without Dial, the event stream is the native one.
	Dial plane.KernelDialer
	// OwnObservePolicy reports DefenseClaw's recorded observe policy; it
	// gates the fanotify hand-off (nil: fanotify always runs).
	OwnObservePolicy func(name string) bool
	// KernelStatus answers OpKernelStatus from the reconciler's state. nil:
	// the helper reports no kernel-policy reconciler.
	KernelStatus func(ctx context.Context) (KernelStatus, error)
}

// tetragonMode is the effective Tetragon mode ("" when the helper has none).
func (s *Server) tetragonMode() string {
	if s.config.Tetragon == nil {
		return ""
	}
	return s.config.Tetragon.Mode
}

// Server answers the fixed question set over a local socket.
//
// It exists so a de-privileged gateway can still be told what the kernel
// sees. Everything about it is shaped by that: it holds privilege, so it
// must be small, must not take instruction, and must be able to say no.
type Server struct {
	config   ServerConfig
	acquirer Acquirer

	mu       sync.Mutex
	listener net.Listener
	closed   bool
	wg       sync.WaitGroup
}

// NewServer returns a helper serving from direct reads.
func NewServer(config ServerConfig) *Server {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &Server{config: config, acquirer: NewLocal()}
}

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("acquire: server is closed")
	}
	s.listener = listener
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("acquire: accept: %w", err)
		}
		if err := s.authorize(conn); err != nil {
			// A refused peer is logged and dropped. It is never told why:
			// the reason names uids, and this is the one process on the host
			// with no reason to help anybody enumerate.
			s.config.Logger.Warn("acquire: refused a peer", "error", err)
			_ = conn.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			s.handle(ctx, conn)
		}()
	}
}

// Close stops accepting and waits for in-flight connections.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	return nil
}

// requestDeadline bounds how long a client may take to state its business.
const requestDeadline = 30 * time.Second

// responseDeadline bounds a single write. Generous because a large process
// table on a busy host is a real payload, but finite because a stalled
// client must not pin a privileged goroutine forever.
const responseDeadline = 60 * time.Second

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	var request Request
	if err := readFrame(conn, &request, requestDeadline); err != nil {
		return
	}
	if request.Version != protocolVersion {
		_ = writeFrame(conn, Response{
			Version: protocolVersion, Op: request.Op,
			Error: fmt.Sprintf("protocol version %d, server speaks %d",
				request.Version, protocolVersion),
		}, responseDeadline)
		return
	}
	switch request.Op {
	case OpHealth:
		_ = writeFrame(conn, Response{Version: protocolVersion, Op: request.Op}, responseDeadline)
	case OpProcesses:
		s.serveProcesses(ctx, conn, request)
	case OpConnections:
		s.serveConnections(ctx, conn, request)
	case OpEvents:
		s.serveEvents(ctx, conn, request)
	case OpDNS:
		s.serveDNS(ctx, conn, request)
	case OpKernelStatus:
		s.serveKernelStatus(ctx, conn, request)
	default:
		// An unknown op is a protocol error, not something to guess at.
		_ = writeFrame(conn, Response{
			Version: protocolVersion, Op: request.Op,
			Error: "unsupported operation",
		}, responseDeadline)
	}
}

func (s *Server) serveProcesses(ctx context.Context, conn net.Conn, request Request) {
	rows, skipped, err := s.acquirer.Processes(ctx)
	response := Response{Version: protocolVersion, Op: request.Op}
	if err != nil {
		response.Error = err.Error()
	}
	table := ProcessTable{Rows: make([]wireProcess, 0, len(rows)), Skipped: skipped}
	for _, row := range rows {
		table.Rows = append(table.Rows, encodeProcess(row))
	}
	if body, marshalErr := json.Marshal(table); marshalErr == nil {
		response.Body = body
	} else {
		response.Error = marshalErr.Error()
	}
	_ = writeFrame(conn, response, responseDeadline)
}

func (s *Server) serveConnections(ctx context.Context, conn net.Conn, request Request) {
	rows, unattributed, err := s.acquirer.Connections(ctx)
	response := Response{Version: protocolVersion, Op: request.Op}
	if err != nil {
		response.Error = err.Error()
	}
	table := ConnectionTable{
		Rows: make([]wireConnection, 0, len(rows)), Unattributed: unattributed,
	}
	for _, row := range rows {
		table.Rows = append(table.Rows, encodeConnection(row))
	}
	if body, marshalErr := json.Marshal(table); marshalErr == nil {
		response.Body = body
	} else {
		response.Error = marshalErr.Error()
	}
	_ = writeFrame(conn, response, responseDeadline)
}

// eventStreamFrame is one frame on an OpEvents subscription: either the
// coverage header or a single event.
type eventStreamFrame struct {
	Coverage *wireCoverage `json:"coverage,omitempty"`
	Event    *wireEvent    `json:"event,omitempty"`
	Error    string        `json:"error,omitempty"`
}

// serveEvents streams Plane C.
//
// The watch scope comes from the server's own configuration. The request
// carries no paths and the client is given no way to supply any, which is
// the property that keeps a privileged event source from becoming a general
// purpose file reader for whoever holds the socket.
func (s *Server) serveEvents(ctx context.Context, conn net.Conn, request Request) {
	source := s.planeSource()
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := source.Start(streamCtx); err != nil {
		_ = writeFrame(conn, Response{
			Version: protocolVersion, Op: request.Op, Error: err.Error(),
		}, responseDeadline)
		return
	}
	defer source.Close()

	coverage := encodeCoverage(source.Coverage())
	header, err := json.Marshal(eventStreamFrame{Coverage: &coverage})
	if err != nil {
		return
	}
	if err := writeFrame(conn, Response{
		Version: protocolVersion, Op: request.Op, Body: header,
	}, responseDeadline); err != nil {
		return
	}

	// A closed connection is the only stop signal a subscriber gets, so the
	// read half is watched purely to notice that. Without it a gateway that
	// goes away leaves a privileged event source running until shutdown.
	go func() {
		var scratch [1]byte
		_ = conn.SetReadDeadline(time.Time{})
		_, _ = conn.Read(scratch[:])
		cancel()
	}()

	// Coverage-update frames: a source whose coverage changes mid-stream
	// (the Tetragon backend falling back to cn_proc and back) says so with
	// a coverage-only frame, at most one per coverageUpdateInterval and
	// only when the coverage differs from the last one sent. A gateway that
	// predates them skips a frame without an event. Content-free: coverage
	// only.
	var changes <-chan struct{}
	if watcher, ok := source.(plane.CoverageWatcher); ok {
		changes = watcher.CoverageChanges()
	}
	lastSent, lastCoverage := time.Now(), coverage
	var pending <-chan time.Time
	sendCoverage := func() bool {
		current := encodeCoverage(source.Coverage())
		lastSent = time.Now()
		if reflect.DeepEqual(current, lastCoverage) {
			return true
		}
		lastCoverage = current
		body, err := json.Marshal(eventStreamFrame{Coverage: &current})
		if err != nil {
			return true
		}
		return writeFrame(conn, Response{Version: protocolVersion, Op: request.Op, Body: body}, responseDeadline) == nil
	}

	events := source.Events()
	for {
		select {
		case <-streamCtx.Done():
			return
		case _, ok := <-changes:
			if !ok {
				changes = nil
				continue
			}
			if pending != nil {
				continue
			}
			if wait := coverageUpdateInterval - time.Since(lastSent); wait > 0 {
				pending = time.After(wait)
				continue
			}
			if !sendCoverage() {
				return
			}
		case <-pending:
			pending = nil
			if !sendCoverage() {
				return
			}
		case event, ok := <-events:
			if !ok {
				return
			}
			encoded := encodeEvent(event)
			body, err := json.Marshal(eventStreamFrame{Event: &encoded})
			if err != nil {
				continue
			}
			if err := writeFrame(conn, Response{
				Version: protocolVersion, Op: request.Op, Body: body,
			}, responseDeadline); err != nil {
				return
			}
		}
	}
}

// coverageUpdateInterval bounds coverage-update frames to one per interval.
var coverageUpdateInterval = 10 * time.Second

// planeSource is the event stream's source. The managed Linux helper with a
// Tetragon mode other than off reads Tetragon (falling back to the native
// halves inside the stream); in off it serves the native source and says
// so in the coverage; everything else serves the acquirer's source.
func (s *Server) planeSource() plane.Source {
	tetragon := s.config.Tetragon
	if tetragon == nil {
		return s.acquirer.PlaneSource(s.config.HomeDirs)
	}
	if tetragon.Mode != "" && tetragon.Mode != "off" && tetragon.Dial != nil {
		return plane.NewTetragonSource(s.config.HomeDirs, plane.TetragonOptions{
			Mode: tetragon.Mode, Dial: tetragon.Dial, OwnObservePolicy: tetragon.OwnObservePolicy,
		})
	}
	return nativeBackend{Source: s.acquirer.PlaneSource(s.config.HomeDirs), mode: firstNonEmpty(tetragon.Mode, "off")}
}

// nativeBackend is the native source of a Tetragon-aware helper that does
// not use Tetragon, labelled so the coverage tells "off by intent" from a
// helper that predates Tetragon.
type nativeBackend struct {
	plane.Source
	mode string
}

func (n nativeBackend) Coverage() plane.Coverage {
	coverage := n.Source.Coverage()
	coverage.Backend = &plane.Backend{Kind: plane.BackendNative, Mode: n.mode}
	return coverage
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// serveKernelStatus answers OpKernelStatus from the reconciler's state.
func (s *Server) serveKernelStatus(ctx context.Context, conn net.Conn, request Request) {
	response := Response{Version: protocolVersion, Op: request.Op}
	status := KernelStatus{Mode: s.tetragonMode(), Reason: "this helper runs no kernel-policy reconciler"}
	if tetragon := s.config.Tetragon; tetragon != nil && tetragon.KernelStatus != nil {
		reported, err := tetragon.KernelStatus(ctx)
		if err != nil {
			response.Error = err.Error()
		} else {
			status = reported
		}
	}
	if response.Error == "" {
		if body, err := json.Marshal(status); err == nil {
			response.Body = body
		} else {
			response.Error = err.Error()
		}
	}
	_ = writeFrame(conn, response, responseDeadline)
}
