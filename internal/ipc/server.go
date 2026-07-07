// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"google.golang.org/grpc"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	pb "github.com/defenseclaw/defenseclaw/proto/defenseclaw/secureclient/v1"
)

// ServerOptions configures a Server. All fields except cfg and
// health are optional in dev builds; managed_enterprise refuses to
// start if peer-auth cannot be enforced (see server.go: Start).
type ServerOptions struct {
	Config     *config.Config
	Health     *gateway.SidecarHealth
	Store      *audit.Store
	Dispatcher *notifier.Dispatcher
	Version    string
	// Logf is called for structured startup / accept-time log lines.
	// Defaults to fmt.Fprintln(os.Stderr, …) when nil.
	Logf func(format string, args ...any)
}

// Server owns the UDS listener, the gRPC server, and the
// notification broadcaster. Constructed from a *config.Config; the
// sidecar goroutine calls Run(ctx) which blocks until ctx is done.
type Server struct {
	opts    ServerOptions
	grpcSrv *grpc.Server
	bcast   *broadcast
	svc     *service

	socketPath string
	socketMode os.FileMode
}

// NewServer prepares the IPC server. It does not touch the filesystem
// or bind the listener — that happens in Run so the caller can
// distinguish construction errors from runtime errors.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Config == nil {
		return nil, fmt.Errorf("ipc: new server: nil config")
	}
	if opts.Health == nil {
		return nil, fmt.Errorf("ipc: new server: nil health")
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("ipc: new server: nil store")
	}
	if opts.Logf == nil {
		opts.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "[ipc] "+format+"\n", args...)
		}
	}

	sockPath := ResolveSocketPath(opts.Config)
	if sockPath == "" {
		return nil, fmt.Errorf("ipc: resolve socket path: empty")
	}
	sockMode, err := ResolveSocketMode(opts.Config)
	if err != nil {
		return nil, err
	}

	bcast := newBroadcast()
	svc := &service{
		health:     opts.Health,
		statsSrc:   opts.Store,
		bcast:      bcast,
		version:    opts.Version,
		nowFn:      time.Now,
		statsPoll:  2 * time.Second,
		healthWait: 200 * time.Millisecond,
	}

	// Register the observer on the dispatcher so every user-visible
	// notification (block, would-block, approval, service-state)
	// arrives here as well as at the OS toast surface.
	if opts.Dispatcher != nil {
		opts.Dispatcher.AddObserver(newObserver(bcast))
	}

	return &Server{
		opts:       opts,
		bcast:      bcast,
		svc:        svc,
		socketPath: sockPath,
		socketMode: sockMode,
	}, nil
}

// Run is the sidecar-goroutine entry point. It binds the listener,
// serves gRPC, and blocks until ctx is done, then gracefully stops
// the server and removes the socket file. Returns nil on clean
// shutdown, or an error on bind / permission / peer-auth failure.
func (s *Server) Run(ctx context.Context) error {
	if runtime.GOOS == "windows" {
		s.setHealth(gateway.StateDisabled, "ipc unsupported on windows")
		<-ctx.Done()
		return nil
	}

	s.setHealth(gateway.StateStarting, "")

	// Managed_enterprise requires a peer-cred allowlist when the
	// resolved socket mode is world-writable — otherwise any local
	// user could connect. Refuse to boot rather than fail-open.
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) &&
		s.socketMode&0o066 != 0 &&
		len(s.opts.Config.Managed.AllowedUIDs) == 0 {
		err := fmt.Errorf("ipc: managed_enterprise + socket_mode %#o requires managed.allowed_uids", s.socketMode)
		s.setHealth(gateway.StateError, err.Error())
		return err
	}

	// Directory permissions track the socket's principal-visibility
	// contract: managed_enterprise wants cross-user traverse (0755
	// so AVC can connect(2) from a different UID); everything else
	// keeps the parent owner-only (0700). The installer creates
	// this dir in prod; this MkdirAll is the dev/test fallback.
	dir := filepath.Dir(s.socketPath)
	dirMode := os.FileMode(0o700)
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) {
		dirMode = 0o755
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		wrapped := fmt.Errorf("ipc: mkdir %s: %w", dir, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}

	// Best-effort remove of a stale socket file from a previous run.
	if err := os.Remove(s.socketPath); err != nil && !os.IsNotExist(err) {
		wrapped := fmt.Errorf("ipc: remove stale socket %s: %w", s.socketPath, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}

	lc := &net.ListenConfig{}
	inner, err := lc.Listen(ctx, "unix", s.socketPath)
	if err != nil {
		wrapped := fmt.Errorf("ipc: listen unix %s: %w", s.socketPath, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}

	if err := os.Chmod(s.socketPath, s.socketMode); err != nil {
		_ = inner.Close()
		wrapped := fmt.Errorf("ipc: chmod socket %s: %w", s.socketPath, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}

	lis := newValidatingListener(inner, s.opts.Config.Managed.AllowedUIDs, s.logReject)

	s.grpcSrv = grpc.NewServer()
	pb.RegisterDefenseClawSecureClientServiceServer(s.grpcSrv, s.svc)

	s.opts.Logf("listening on %s (mode=%#o allowed_uids=%v version=%s)",
		s.socketPath, s.socketMode, s.opts.Config.Managed.AllowedUIDs, s.opts.Version)
	s.setHealth(gateway.StateRunning, "")

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- s.grpcSrv.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		s.shutdown()
		<-serveErrCh
		s.setHealth(gateway.StateStopped, "")
		return nil
	case err := <-serveErrCh:
		s.shutdown()
		if err != nil {
			s.setHealth(gateway.StateError, err.Error())
			return fmt.Errorf("ipc: serve: %w", err)
		}
		s.setHealth(gateway.StateStopped, "")
		return nil
	}
}

// shutdown gracefully stops the gRPC server and removes the socket
// file. Idempotent: called from both the ctx-cancel and serve-error
// branches of Run.
func (s *Server) shutdown() {
	if s.grpcSrv != nil {
		// Bound the graceful window so a wedged client cannot delay
		// process exit beyond a reasonable threshold. 2s matches
		// the CLAUDE.md "block must take effect in under 2 seconds"
		// guidance we already apply to enforcement paths.
		stopped := make(chan struct{})
		go func() {
			s.grpcSrv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			s.grpcSrv.Stop()
		}
	}
	if s.socketPath != "" {
		_ = os.Remove(s.socketPath)
	}
}

// SocketPath returns the resolved socket path (for logging / tests).
func (s *Server) SocketPath() string { return s.socketPath }

// SocketMode returns the resolved socket permission bits.
func (s *Server) SocketMode() os.FileMode { return s.socketMode }

// setHealth is a convenience for reporting SidecarHealth.Managed. The
// details map carries the resolved socket path so /health JSON is
// self-describing.
func (s *Server) setHealth(state gateway.SubsystemState, lastErr string) {
	if s.opts.Health == nil {
		return
	}
	details := map[string]interface{}{
		"socket_path":  s.socketPath,
		"socket_mode":  fmt.Sprintf("%#o", s.socketMode),
		"allowed_uids": s.opts.Config.Managed.AllowedUIDs,
	}
	s.opts.Health.SetManaged(state, lastErr, details)
}

// logReject formats a peer-auth rejection for stderr. UID/PID are
// safe to log (they are not secrets); reason is a static short
// string produced by the validator.
func (s *Server) logReject(id peerIdentity, reason string) {
	s.opts.Logf("peer rejected: uid=%d gid=%d pid=%d reason=%s", id.UID, id.GID, id.PID, reason)
}
