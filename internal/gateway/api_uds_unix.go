//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// inheritedHookListener is replaceable by tests.
var inheritedHookListener = func() (net.Listener, bool, error) { return systemd.Listener("hook") }

// newManagedHookSocketServer builds the standalone hook socket: the same
// hook, notify and inspect handlers as the TCP API, behind kernel-verified
// peer authorization instead of bearer tokens. It returns (nil, nil, nil)
// when the deployment is not standalone.
func (a *APIServer) newManagedHookSocketServer(ctx context.Context, base func(http.Handler) http.Handler) (*http.Server, net.Listener, error) {
	if !managedHookSocketEnabled(a.scannerCfg) {
		return nil, nil, nil
	}
	descriptor, descriptorErr := loadStandaloneRuntimeDescriptor(runtime.GOOS)
	if descriptorErr != nil && !errors.Is(descriptorErr, managed.ErrNoRuntimeDescriptor) {
		// An untrusted descriptor never widens access: fall back to strict
		// per-user enrollment for every connector.
		fmt.Fprintf(os.Stderr, "[sidecar-api] standalone runtime descriptor rejected: %v\n", descriptorErr)
		descriptor = nil
	}
	var machinePolicy []string
	if descriptor != nil {
		machinePolicy = descriptor.MachinePolicyConnectors
	}
	ledger := newManagedHookLedgerLoader(managed.HookGuardianAuthorizationPath(a.configDataDir()))
	authorizer := newManagedHookAuthorizer(a.scannerCfg.Enterprise.Enrollment, machinePolicy, ledger.Load)

	listener, inherited, err := inheritedHookListener()
	if err != nil {
		return nil, nil, err
	}
	if !inherited {
		path := ""
		if descriptor != nil {
			path = descriptor.HookSocket
		}
		if path == "" {
			layout, layoutErr := managed.StandaloneLayoutFor(runtime.GOOS)
			if layoutErr != nil {
				return nil, nil, layoutErr
			}
			path = layout.HookSocketPath
		}
		listener, err = bindManagedHookSocketWhenFree(ctx, path)
		if err != nil {
			return nil, nil, err
		}
	} else if _, ok := listener.Addr().(*net.UnixAddr); !ok {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("api: socket-activated hook listener %s is not a unix socket", listener.Addr())
	}

	handler := base(managedHookSocketHealth(a.handleHealth, a.managedHookPeerAuth(authorizer, a.managedHookSocketMux())))
	server := &http.Server{
		Handler:     managedHookPeerIdentityMiddleware(handler),
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: managedHookConnContext,
	}
	return server, listener, nil
}

// managedHookSocketHealth answers GET /health on the hook socket with the
// same document as the TCP API, where /health needs no credential either.
// The Linux and macOS lifecycle probes readiness here: the socket lives in
// a directory only the service account can write and the kernel names its
// listener, while another local account can hold 127.0.0.1:<port> whenever
// the gateway's own TCP listener is down and answer /health there. Every
// other path keeps peer authorization.
func managedHookSocketHealth(health http.HandlerFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == http.MethodGet {
			health(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hookSocketPeerCredentials reads a hook-socket connection's kernel
// credentials; replaceable by tests.
var hookSocketPeerCredentials = peercred.FromConn

// managedHookConnContext stamps each accepted hook-socket connection with
// the peer's kernel credentials. A connection whose credentials cannot be
// read carries none, and the identity middleware refuses its requests.
//
// net/http calls ConnContext in its single accept loop, before the
// connection gets its own goroutine, so this records only what the kernel
// reported. The account name and home come from the account database
// (getent on Linux), which can be slow for directory users; the identity
// middleware resolves them on the connection's first request, so a slow
// lookup delays only that caller's connection.
func managedHookConnContext(ctx context.Context, conn net.Conn) context.Context {
	credentials, err := hookSocketPeerCredentials(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] hook socket peer credentials unavailable: %v\n", err)
		return ctx
	}
	return withManagedHookConnPeer(ctx, func() managedHookPeer { return managedHookPeerFor(credentials) })
}

// managedHookPeerFor builds the verified caller identity from kernel
// credentials: account name for attribution, home for "~" resolution.
func managedHookPeerFor(credentials peercred.Credentials) managedHookPeer {
	return managedHookPeer{
		UID:  credentials.UID,
		GID:  credentials.GID,
		PID:  credentials.PID,
		Name: managedHookPeerName(credentials.UID),
		Home: managedHookPeerHome(credentials.UID),
	}
}

// errHookSocketInUse reports a hook socket path that another live listener
// still serves.
var errHookSocketInUse = errors.New("hook socket is served by another live listener")

// hookSocketHeldRetryInterval paces bindManagedHookSocketWhenFree; it is
// replaceable by tests.
var hookSocketHeldRetryInterval = 100 * time.Millisecond

// bindManagedHookSocketWhenFree binds the hook socket, waiting up to the API
// bind budget while another live listener still serves the path. That is a
// gateway that is still shutting down during an overlapping restart, which
// releases the path within seconds, or a second gateway under the same
// account, which must be left alone: after the budget this returns the error
// and the caller runs without the socket.
func bindManagedHookSocketWhenFree(ctx context.Context, path string) (net.Listener, error) {
	deadline := time.Now().Add(apiListenRetryBudget)
	for {
		listener, err := bindManagedHookSocket(path)
		if err == nil || !errors.Is(err, errHookSocketInUse) || !time.Now().Before(deadline) {
			return listener, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(hookSocketHeldRetryInterval):
		}
	}
}

// bindManagedHookSocket binds the hook socket when the service manager did
// not pass one (macOS, or Linux without socket activation). The directory
// must already exist, belong to root or this service account and be
// writable by no one else — the lifecycle creates it — so a standard user
// can never have planted a socket there first. A stale socket this account
// owns is replaced; a socket another listener still answers on is left
// alone (errHookSocketInUse), and anything else is refused.
func bindManagedHookSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("api: hook socket path %q is not absolute and clean", path)
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("api: hook socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("api: hook socket directory %s is not a real directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("api: hook socket directory %s is group/other writable (%04o)", dir, info.Mode().Perm())
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && int(owner.Uid) != os.Geteuid()) {
		return nil, fmt.Errorf("api: hook socket directory %s must be owned by root or the service account", dir)
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("api: refusing to replace non-socket %s", path)
		}
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() {
			return nil, fmt.Errorf("api: refusing to replace hook socket %s owned by another account", path)
		}
		// Only this account can create sockets here, so a listener that
		// answers is another gateway under it; removing its socket would
		// cut every user off that gateway while it keeps running. Only a
		// socket that refuses connections is stale.
		if err := hookSocketStale(path); err != nil {
			return nil, fmt.Errorf("api: %s: %w", path, err)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("api: remove stale hook socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("api: inspect hook socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("api: listen %s: %w", path, err)
	}
	owned, err := newOwnedHookSocketListener(listener, path)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	// Every local user may connect; the server authorizes each caller by
	// its kernel-verified uid.
	if err := os.Chmod(path, 0o666); err != nil {
		_ = owned.Close()
		return nil, fmt.Errorf("api: chmod hook socket: %w", err)
	}
	return owned, nil
}

// hookSocketStale returns nil when nothing listens on the socket at path
// (the connection is refused, or the path went away), and an error wrapping
// errHookSocketInUse when a listener answers or staleness cannot be shown.
func hookSocketStale(path string) error {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return errHookSocketInUse
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return fmt.Errorf("%w: %v", errHookSocketInUse, err)
}

// ownedHookSocketListener removes the socket path on Close only while the
// path is still the socket this listener bound. Go's own unlink-on-close
// removes whatever is at the path, which after a takeover is another
// gateway's live socket.
type ownedHookSocketListener struct {
	*net.UnixListener
	path  string
	bound os.FileInfo
	once  sync.Once
}

func newOwnedHookSocketListener(listener net.Listener, path string) (*ownedHookSocketListener, error) {
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return nil, fmt.Errorf("api: hook socket listener %s is not a unix socket", listener.Addr())
	}
	bound, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("api: inspect bound hook socket: %w", err)
	}
	unixListener.SetUnlinkOnClose(false)
	return &ownedHookSocketListener{UnixListener: unixListener, path: path, bound: bound}, nil
}

// Close removes the path while the listener still answers on it, as Go
// does: a gateway starting meanwhile finds the socket live and waits
// instead of replacing it.
func (l *ownedHookSocketListener) Close() error {
	l.once.Do(func() {
		if current, err := os.Lstat(l.path); err == nil && os.SameFile(current, l.bound) {
			_ = os.Remove(l.path)
		}
	})
	return l.UnixListener.Close()
}
