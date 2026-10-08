// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/acp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// acpLoopbackPeerUID names the account of the process on the client end of
// a loopback TCP request, from the kernel connection table; replaceable in
// tests. A connection is looked up once: the guard sends every evaluation of
// a session over the same connection, one per streamed frame.
var acpLoopbackPeerUID = func(r *http.Request) (int, error) {
	if peer, ok := r.Context().Value(acpConnPeerKey{}).(*acpConnPeer); ok {
		return peer.lookup()
	}
	local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if local == nil || err != nil {
		return -1, errors.New("the request carries no TCP addresses")
	}
	return peercred.LoopbackTCPPeerUID(local, remote)
}

// acpConnPeerKey carries the peer account lookup of one TCP connection.
type acpConnPeerKey struct{}

// acpConnPeer is the account on the client end of one accepted TCP
// connection, read from the kernel on first use. A failed lookup is not
// kept, so the next request asks again.
type acpConnPeer struct {
	mu            sync.Mutex
	local, remote *net.TCPAddr
	uid           int
	known         bool
}

func (p *acpConnPeer) lookup() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.known {
		return p.uid, nil
	}
	uid, err := peercred.LoopbackTCPPeerUID(p.local, p.remote)
	if err != nil {
		return -1, err
	}
	p.uid, p.known = uid, true
	return uid, nil
}

// acpPeerConnContext gives each accepted TCP connection its peer account
// lookup. It reads nothing until an ACP request needs it.
func acpPeerConnContext(ctx context.Context, conn net.Conn) context.Context {
	local, _ := conn.LocalAddr().(*net.TCPAddr)
	remote, _ := conn.RemoteAddr().(*net.TCPAddr)
	if local == nil || remote == nil {
		return ctx
	}
	return context.WithValue(ctx, acpConnPeerKey{}, &acpConnPeer{local: local, remote: remote})
}

// The refusal reasons of a managed ACP request whose caller is another
// account than its credential's, or could not be told.
const (
	acpCallerAccountMismatchReason   = "acp_caller_account_mismatch"
	acpCallerAccountUnverifiedReason = "acp_caller_account_unverified"
)

// acpCallerAccountChecked reports whether this gateway checks the OS account
// of an ACP caller: a standalone managed gateway on Linux or macOS, whose
// kernel names the owner of a loopback TCP socket. Windows tells a service
// only the process of a TCP connection, and Secure Client keeps the bearer
// check of main (issue #1092).
func (a *APIServer) acpCallerAccountChecked() bool {
	return runtime.GOOS != "windows" && a != nil && a.scannerCfg != nil &&
		managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) && !a.scannerCfg.SecureClientIntegration()
}

// acpCallerAccountRefusal is the authentication failure reason for a
// managed ACP request whose loopback caller is not the account its
// enrollment credential was issued to, or "" when the account matches or
// is not checked. A copied bearer used to run another user's guarded
// session recorded as the verified token owner, with the owner's guardrail
// profile (GAP-0348).
func (a *APIServer) acpCallerAccountRefusal(r *http.Request) string {
	if !a.acpCallerAccountChecked() {
		return ""
	}
	credential, enrolled := acpEnterpriseCredentialFromContext(r.Context())
	kind, value, _ := strings.Cut(credential.Principal, ":")
	if !enrolled || kind != "uid" {
		// A home: principal names no account and binds none.
		return ""
	}
	want, err := strconv.Atoi(value)
	if err != nil {
		return acpCallerAccountUnverifiedReason
	}
	got, err := acpLoopbackPeerUID(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] ACP caller account unavailable: %v\n", err)
		return acpCallerAccountUnverifiedReason
	}
	if got != want {
		return acpCallerAccountMismatchReason
	}
	return ""
}

// writeACPSignedOtherAccountRefusal answers an ACP request whose valid
// credential belongs to another account with a refusal signed by that
// credential.
func writeACPSignedOtherAccountRefusal(w http.ResponseWriter, r *http.Request, token, nonce string) {
	body := []byte(`{"error":"unauthorized","code":"` + acp.RefusalOtherAccount + `"}` + "\n")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(acp.AuthResponseMACHeader, acp.HTTPResponseMAC(token, r.Header.Get(acp.AuthKeyIDHeader), nonce, http.StatusUnauthorized, body))
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write(body)
}

// withRevokedACPCredential names, on an authentication failure row no
// kernel answer attributed (Windows), the account a revoked managed
// credential was issued to, by the non-secret key ID the guard presented:
// the row named no one, so an administrator could not tell who still ran a
// revoked guard (GAP-0354). Secure Client keeps its rows.
func (a *APIServer) withRevokedACPCredential(ctx context.Context, r *http.Request) context.Context {
	if a == nil || a.scannerCfg == nil || !managed.IsManagedEnterprise(a.scannerCfg.DeploymentMode) ||
		a.scannerCfg.SecureClientIntegration() || !identityFactsEnabled.Load() {
		return ctx
	}
	if identity, _ := ctx.Value(verifiedUserScopedIdentityContextKey{}).(string); identity != "" {
		return ctx
	}
	revoked, ok := acp.RevokedEnterpriseCredentialForKeyID(a.scannerCfg.DataDir, r.Header.Get(acp.AuthKeyIDHeader))
	if !ok {
		return ctx
	}
	identity := acpPrincipalIdentity(revoked.Principal)
	if identity == "" {
		return ctx
	}
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	agent := AgentIdentityFromContext(ctx)
	agent.UserID, agent.UserIDKind = identity, useridentity.KindForID(identity)
	agent.UserName = sanitizeLLMEventUser(userScopedIdentityName(identity))
	return ContextWithAgentIdentity(ctx, agent)
}

// withACPCallerAccount names the kernel-verified account of a refused ACP
// caller on the authentication failure row, which named no one, so an
// administrator could not tell who was presenting a revoked or copied
// credential (GAP-0354).
func (a *APIServer) withACPCallerAccount(ctx context.Context, r *http.Request) context.Context {
	if !a.acpCallerAccountChecked() || !identityFactsEnabled.Load() {
		return ctx
	}
	uid, err := acpLoopbackPeerUID(r)
	if err != nil || uid < 0 {
		return ctx
	}
	id := strconv.Itoa(uid)
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, id)
	identity := AgentIdentityFromContext(ctx)
	// The account database the hook socket uses names directory accounts
	// too; os/user in this cgo-free build reads only /etc/passwd, so an AD
	// borrower's row carried only its uid (GAP-0690).
	identity.UserID, identity.UserIDKind = id, useridentity.KindPOSIXUID
	identity.UserName = sanitizeLLMEventUser(userScopedIdentityName(id))
	return ContextWithAgentIdentity(ctx, identity)
}
