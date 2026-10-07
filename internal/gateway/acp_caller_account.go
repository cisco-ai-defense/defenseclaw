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
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// acpLoopbackPeerUID names the account of the process on the client end of
// a loopback TCP request, from the kernel connection table; replaceable in
// tests.
var acpLoopbackPeerUID = func(r *http.Request) (int, error) {
	local, _ := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	if local == nil || err != nil {
		return -1, errors.New("the request carries no TCP addresses")
	}
	return peercred.LoopbackTCPPeerUID(local, remote)
}

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
		return "acp_caller_account_unverified"
	}
	got, err := acpLoopbackPeerUID(r)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] ACP caller account unavailable: %v\n", err)
		return "acp_caller_account_unverified"
	}
	if got != want {
		return "acp_caller_account_mismatch"
	}
	return ""
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
	identity.UserID, identity.UserIDKind, identity.UserName = id, useridentity.KindPOSIXUID, ""
	if account, lookupErr := user.LookupId(id); lookupErr == nil {
		identity.UserName = sanitizeLLMEventUser(account.Username)
	}
	return ContextWithAgentIdentity(ctx, identity)
}
