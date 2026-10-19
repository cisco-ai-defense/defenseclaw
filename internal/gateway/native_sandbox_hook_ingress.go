// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

var errNativeHookIngress = errors.New("native sandbox hook ingress is unavailable")

type nativeHookConnectionKey struct{}

// nativeSandboxHookIngress is an owned transport into the existing sandbox
// ingress, not another policy handler. There is no production factory yet.
// Its socket is a session capability; it does not authenticate a particular
// executable or establish model-credential isolation.
type nativeSandboxHookIngress struct {
	api       *APIServer
	state     *sandboxIngressState
	store     *sandboxauth.FileStore
	bindingID string
	bearer    string // host-only; never sent to a guest or another gateway
	ctx       context.Context
	cancel    context.CancelFunc
	listener  *net.UnixListener
	server    *http.Server
	handler   http.Handler
	served    chan struct{}
	drained   chan struct{}
	revoke    chan struct{}
	closeOnce sync.Once
	drainOnce sync.Once
	mu        sync.Mutex
	closing   bool
	serveErr  error
	closeErr  error
	requests  sync.WaitGroup
}

// newNativeSandboxHookIngress consumes listener only on success. Its trusted
// caller must own the socket in a held private directory, retain its exact
// cleanup capability, and expose only that socket through the admitted runtime.
// This helper performs no path lookup, bind, mount or policy relaxation.
// sessionID is the listener owner's immutable native session, independently of
// the credential lookup; it must never come from a guest request or its binding.
// The caller minted the ordinary binding and retains it on constructor error.
// After success Close owns revocation; retain this object after a Close error.
func (a *APIServer) newNativeSandboxHookIngress(ctx context.Context, listener *net.UnixListener, sessionID, bindingID, token string) (*nativeSandboxHookIngress, error) {
	if ctx == nil || ctx.Err() != nil || listener == nil {
		return nil, errNativeHookIngress
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > 24*time.Hour {
		return nil, errNativeHookIngress
	}
	address, ok := listener.Addr().(*net.UnixAddr)
	if !ok || address.Net != "unix" || address.Name == "" || strings.HasPrefix(address.Name, "@") {
		return nil, errNativeHookIngress
	}
	state := a.sandboxIngressState()
	if state == nil {
		return nil, errNativeHookIngress
	}
	store, ok := state.bindings.(*sandboxauth.FileStore)
	if !ok || store == nil {
		return nil, errNativeHookIngress
	}
	binding, err := store.Match(token)
	if err != nil || binding.ID != bindingID || sessionID == "" || binding.SandboxID != sessionID || binding.ExecutionOS != runtime.GOOS ||
		binding.Workdir.Mode != sandboxauth.WorkdirCopy || len(binding.Workdir.Mounts) != 0 ||
		len(binding.Routes) != 1 || binding.Routes[0] != sandboxauth.RouteHook ||
		binding.ExpiresAt.IsZero() || !binding.ExpiresAt.After(time.Now()) || binding.ExpiresAt.After(time.Now().Add(24*time.Hour)) {
		return nil, errNativeHookIngress
	}
	state.handlerOnce.Do(func() { state.handler = a.newSandboxIngressHandler(state) })
	owned, cancel := context.WithCancel(ctx)
	endpoint := &nativeSandboxHookIngress{api: a, state: state, store: store, bindingID: bindingID,
		bearer: token, ctx: owned, cancel: cancel, listener: listener, handler: state.handler,
		served: make(chan struct{}), drained: make(chan struct{}), revoke: make(chan struct{}, 1)}
	endpoint.server = &http.Server{
		Handler: endpoint, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute,
		IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10,
		BaseContext: func(net.Listener) context.Context { return owned },
		ConnContext: endpoint.connectionContext,
	}
	// Closing a listener must not unlink a replacement pathname. The caller's
	// held asset owner cleans up the exact socket only after Close succeeds.
	listener.SetUnlinkOnClose(false)
	go func() {
		err := endpoint.server.Serve(listener)
		endpoint.mu.Lock()
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			endpoint.serveErr = errNativeHookIngress // no socket paths in errors
		}
		endpoint.mu.Unlock()
		close(endpoint.served)
		cancel() // a failed listener also closes admission and revokes its binding
	}()
	context.AfterFunc(owned, func() {
		cleanup, done := context.WithTimeout(context.Background(), sandboxIngressShutdownTimeout)
		defer done()
		_ = endpoint.Close(cleanup) // caller still retains retryable ownership
	})
	return endpoint, nil
}

func (endpoint *nativeSandboxHookIngress) connectionContext(ctx context.Context, connection net.Conn) context.Context {
	if _, ok := connection.(*net.UnixConn); !ok {
		return ctx
	}
	// Only this server installs this unexported, per-owner marker. Headers,
	// query parameters and addresses cannot select a binding. Reusing this
	// handler on a TCP listener therefore supplies no native authority.
	return context.WithValue(ctx, nativeHookConnectionKey{}, endpoint)
}

func (endpoint *nativeSandboxHookIngress) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Context().Value(nativeHookConnectionKey{}) != endpoint {
		writeSandboxIngressError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	endpoint.mu.Lock()
	if endpoint.closing || endpoint.ctx.Err() != nil || endpoint.api.sandboxIngressState() != endpoint.state {
		endpoint.mu.Unlock()
		writeSandboxIngressError(w, http.StatusServiceUnavailable, "sandbox unavailable")
		return
	}
	endpoint.requests.Add(1)
	bearer := endpoint.bearer
	endpoint.mu.Unlock()
	defer endpoint.requests.Done()
	// Guest Authorization is never forwarded, interpreted or used to choose
	// identity. All remaining credential, route, connector, rate, CSRF, body,
	// replay, FSView and shared-policy checks stay in the existing chain.
	for name := range request.Header {
		if strings.EqualFold(name, "Authorization") {
			writeSandboxIngressError(w, http.StatusBadRequest, "guest authorization is not accepted")
			return
		}
	}
	forward := request.Clone(request.Context())
	if forward.Header == nil {
		forward.Header = make(http.Header)
	}
	forward.Header.Set("Authorization", "Bearer "+bearer)
	endpoint.handler.ServeHTTP(w, forward)
}

// Close closes admission, revokes the ordinary binding, then cancels requests
// and closes the listener. It waits for admitted handlers and Serve to finish.
// A timeout retains ownership for retry; it never relabels a pending handler
// as cleaned up. FileStore's synchronous filesystem operations, as elsewhere,
// are not made hard-deadline-interruptible by this context.
func (endpoint *nativeSandboxHookIngress) Close(ctx context.Context) error {
	if endpoint == nil || ctx == nil {
		return errNativeHookIngress
	}
	endpoint.mu.Lock()
	endpoint.closing = true
	endpoint.mu.Unlock()
	var revokeErr error
	select {
	case endpoint.revoke <- struct{}{}:
		revokeErr = endpoint.store.Revoke(endpoint.bindingID)
		if errors.Is(revokeErr, sandboxauth.ErrNotFound) {
			revokeErr = nil
		} else if revokeErr != nil {
			revokeErr = errNativeHookIngress // no host store paths in transport errors
		}
		<-endpoint.revoke
	case <-ctx.Done():
		revokeErr = ctx.Err()
	}
	endpoint.closeOnce.Do(func() {
		endpoint.cancel()
		serverErr := endpoint.server.Close()
		listenerErr := endpoint.listener.Close()
		endpoint.mu.Lock()
		if serverErr != nil && !errors.Is(serverErr, net.ErrClosed) || listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) {
			endpoint.closeErr = errNativeHookIngress // uncertain close stays sticky
		}
		endpoint.bearer = ""
		endpoint.mu.Unlock()
	})
	endpoint.drainOnce.Do(func() {
		go func() {
			endpoint.requests.Wait()
			<-endpoint.served
			close(endpoint.drained)
		}()
	})
	select {
	case <-endpoint.drained:
		endpoint.mu.Lock()
		serveErr := errors.Join(endpoint.serveErr, endpoint.closeErr)
		endpoint.mu.Unlock()
		if revokeErr != nil {
			return errors.Join(errNativeHookIngress, revokeErr)
		}
		return serveErr
	case <-ctx.Done():
		return errors.Join(errNativeHookIngress, revokeErr, ctx.Err())
	}
}
