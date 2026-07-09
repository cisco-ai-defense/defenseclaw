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
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
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

	// staffGID is the gid of the macOS "staff" group used to narrow
	// the socket ownership in managed_enterprise. Resolved once in
	// NewServer via user.LookupGroup so dev machines that don't
	// have the group can still boot (staffGID stays 0 and the chown
	// path is skipped). On real macOS every host has staff.
	staffGID uint32

	// Effective peer-auth policy. Under managed_enterprise these are
	// seeded from DefaultSecureClientPolicy() when the operator has
	// not overridden them in config.yaml; require-flags are always
	// on. Under non-managed builds the require-flags stay false and
	// the three lists mirror whatever the operator configured
	// (empty by default → wrapper bypassed).
	allowedTeamIDs         []string
	allowedSigningIDs      []string
	allowedBundleIDs       []string
	requireUnixPeer        bool
	requireSigningMetadata bool
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

	// Best-effort staff GID lookup for macOS managed_enterprise
	// socket ownership. On non-macOS or when the group is missing
	// we leave the gid at 0 and skip the chown; the rest of the
	// server continues normally.
	var staffGID uint32
	if g, err := user.LookupGroup("staff"); err == nil {
		if gid, convErr := strconv.ParseUint(g.Gid, 10, 32); convErr == nil {
			staffGID = uint32(gid)
		}
	}

	// Resolve the effective peer-auth policy. In managed_enterprise
	// we seed the strict Secure-Client defaults for any list the
	// operator did not populate in config.yaml, then always require
	// UnixPeer transport + full signing metadata. Non-managed
	// builds keep operator config verbatim and leave the require
	// flags off so a completely-empty config disables the check.
	allowedTeamIDs := opts.Config.Managed.AllowedTeamIDs
	allowedSigningIDs := opts.Config.Managed.AllowedSigningIDs
	allowedBundleIDs := opts.Config.Managed.AllowedBundleIDs
	var requireUnixPeer, requireSigningMetadata bool
	if managed.IsManagedEnterprise(opts.Config.DeploymentMode) {
		def := config.DefaultSecureClientPolicy()
		if len(allowedTeamIDs) == 0 {
			allowedTeamIDs = def.AllowedTeamIDs
		}
		if len(allowedSigningIDs) == 0 {
			allowedSigningIDs = def.AllowedSigningIDs
		}
		if len(allowedBundleIDs) == 0 {
			allowedBundleIDs = def.AllowedBundleIDs
		}
		requireUnixPeer = true
		requireSigningMetadata = true
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
		logf:       opts.Logf,
	}

	// Register the observer on the dispatcher so every user-visible
	// notification (block, would-block, approval, service-state)
	// arrives here as well as at the OS toast surface.
	if opts.Dispatcher != nil {
		opts.Dispatcher.AddObserver(newObserver(bcast))
	}

	return &Server{
		opts:                   opts,
		bcast:                  bcast,
		svc:                    svc,
		staffGID:               staffGID,
		socketPath:             sockPath,
		socketMode:             sockMode,
		allowedTeamIDs:         allowedTeamIDs,
		allowedSigningIDs:      allowedSigningIDs,
		allowedBundleIDs:       allowedBundleIDs,
		requireUnixPeer:        requireUnixPeer,
		requireSigningMetadata: requireSigningMetadata,
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

	// Directory permissions track the socket's principal-visibility
	// contract: managed_enterprise creates the parent as root:staff
	// 0750 (traverse for the console user via the staff group;
	// installer normally creates this, we MkdirAll as fallback).
	// Everything else keeps the parent owner-only.
	dir := filepath.Dir(s.socketPath)
	dirMode := os.FileMode(0o700)
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) {
		dirMode = 0o750
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		wrapped := fmt.Errorf("ipc: mkdir %s: %w", dir, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}
	// MkdirAll respects the process umask (launchd sets 022 or
	// stricter, so a mode-0750 request lands as 0700). Force the
	// intended mode explicitly so the staff group actually gets its
	// traverse bit. Also idempotent when the installer pre-created
	// the dir with a laxer mode.
	if err := os.Chmod(dir, dirMode); err != nil {
		wrapped := fmt.Errorf("ipc: chmod %s: %w", dir, err)
		s.setHealth(gateway.StateError, wrapped.Error())
		return wrapped
	}
	// Best-effort chown to root:staff on darwin managed_enterprise.
	// Fails silently on non-root dev runs; a real install runs as
	// root and the chown succeeds. We rely on os.Chown returning
	// EPERM for the unprivileged case and only treat other errors
	// as fatal.
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) && s.staffGID > 0 {
		if err := os.Chown(dir, 0, int(s.staffGID)); err != nil && !os.IsPermission(err) {
			wrapped := fmt.Errorf("ipc: chown %s to root:staff: %w", dir, err)
			s.setHealth(gateway.StateError, wrapped.Error())
			return wrapped
		}
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
	// Chown the socket itself to root:staff in managed_enterprise so
	// the group-based fs filter is real. Same permission-error
	// tolerance as the dir chown above.
	if managed.IsManagedEnterprise(s.opts.Config.DeploymentMode) && s.staffGID > 0 {
		if err := os.Chown(s.socketPath, 0, int(s.staffGID)); err != nil && !os.IsPermission(err) {
			_ = inner.Close()
			wrapped := fmt.Errorf("ipc: chown %s to root:staff: %w", s.socketPath, err)
			s.setHealth(gateway.StateError, wrapped.Error())
			return wrapped
		}
	}

	lis := newCodesignValidatingListener(inner,
		s.allowedTeamIDs,
		s.allowedSigningIDs,
		s.allowedBundleIDs,
		s.requireUnixPeer,
		s.requireSigningMetadata,
		s.logReject)

	s.grpcSrv = grpc.NewServer()
	pb.RegisterDefenseClawSecureClientServiceServer(s.grpcSrv, s.svc)

	codesignState := "disabled"
	if s.requireUnixPeer || s.requireSigningMetadata ||
		len(s.allowedTeamIDs) > 0 || len(s.allowedSigningIDs) > 0 || len(s.allowedBundleIDs) > 0 {
		codesignState = "enabled"
	}
	s.opts.Logf("listening on %s (mode=%#o codesign_peer_auth=%s team_ids=%v signing_ids=%v bundle_ids=%v require_unix_peer=%v require_signing_metadata=%v version=%s)",
		s.socketPath, s.socketMode, codesignState,
		s.allowedTeamIDs,
		s.allowedSigningIDs,
		s.allowedBundleIDs,
		s.requireUnixPeer,
		s.requireSigningMetadata,
		s.opts.Version)
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

// setHealth is a convenience for reporting SidecarHealth.Managed.
//
// The details map is deliberately empty. GET /health on the admin
// REST API is exempt from bearer-token auth (see APIServer.tokenAuth
// in internal/gateway/api.go) so it can be probed by oncall /
// watchdog / load balancer without a credential. That makes it the
// wrong place to publish the effective peer-auth policy (allowed
// team / signing / bundle ids, require-flags, resolved socket
// path/mode) — an attacker on loopback would learn exactly which
// codesign identity to spoof.
//
// Operators who need to inspect the effective policy read the
// startup log line at /Library/Logs/Cisco/SecureClient/DefenseClaw/
// gateway.err.log (root:wheel 0640, root-only readable), which
// carries the full team_ids / signing_ids / bundle_ids /
// require_unix_peer / require_signing_metadata dump.
//
// Consumers of /health get only the subsystem's lifecycle state:
// starting → running → stopped / error. That's enough for
// liveness checks and matches what every other subsystem
// (gateway, api, watcher) reports.
func (s *Server) setHealth(state gateway.SubsystemState, lastErr string) {
	if s.opts.Health == nil {
		return
	}
	s.opts.Health.SetManaged(state, lastErr, nil)
}

// logReject formats a peer-auth rejection for stderr. UID/PID are
// safe to log (they are not secrets); reason is a static short
// string produced by the validator.
func (s *Server) logReject(id peerIdentity, reason string) {
	s.opts.Logf("peer rejected: uid=%d gid=%d pid=%d reason=%s", id.UID, id.GID, id.PID, reason)
}
