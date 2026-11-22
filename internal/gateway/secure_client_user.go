// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// End-user attribution under the Secure Client integration.
//
// Cisco AI Defense needs to know which person on a managed endpoint caused
// each inspection, event and inventory record, to attribute it and to choose
// that person's policy. The hook names its OS account in the
// X-DefenseClaw-User-* headers, which any local process holding the hook
// token can set. Under Secure Client the gateway labels that claim: when the
// kernel connection table names the account that owns the hook's loopback
// connection, the account is verified, and only a verified account gets its
// directory UPN. Otherwise the header account is sent marked claimed.
//
// This only labels the identity. It never refuses, delays past a small
// budget or changes a hook decision, and every failure (an unreadable table,
// an exited caller, a panic) leaves the request as it was: the header
// account, claimed, and no UPN.
//
// Identity facts (identityFactsEnabled) stay off under Secure Client, so
// guardrail profiles, assignments, session facts and the identity spool
// remain unreachable; this flag reaches only the attribution fields.

// secureClientUserAttribution is on exactly when the Secure Client
// integration is. Wired by applyIdentityPosture with the other identity
// flags; every function in this file returns at once while it is off.
var secureClientUserAttribution atomic.Bool

func setSecureClientUserAttribution(v bool) { secureClientUserAttribution.Store(v) }

// secureClientCallerBudget bounds how long a hook request waits for the
// kernel connection table. Past it the account is sent as claimed; the
// lookup still finishes in the background and serves the next request on
// the same connection.
const secureClientCallerBudget = 50 * time.Millisecond

// The bounds of the identity block's text values: the telemetry registry's
// limits for user.id and defenseclaw.user.principal, and the account name
// limit the hook headers already apply.
const (
	secureClientUserIDMaxBytes   = 256
	secureClientUserNameMaxBytes = 256
	secureClientUPNMaxBytes      = 512
)

// secureClientUser is the identity block of one request.
type secureClientUser struct {
	// ID is the SID or uid; IDKind is useridentity.KindWindowsSID or
	// KindPOSIXUID.
	ID, IDKind string
	// Assurance is verified when the kernel named this account as the
	// caller, claimed when it is the hook's header alone.
	Assurance useridentity.Assurance
	// Name is the account name the hook reported for the same ID, empty
	// when the kernel named another account than the header.
	Name string
	// UPN is the directory UPN of a verified account, from the in-memory
	// directory cache; empty when not cached yet or none exists.
	UPN string
}

type secureClientUserContextKey struct{}

// secureClientUserFromContext returns the identity block attached by
// attachSecureClientUser.
func secureClientUserFromContext(ctx context.Context) (secureClientUser, bool) {
	if ctx == nil || !secureClientUserAttribution.Load() {
		return secureClientUser{}, false
	}
	user, ok := ctx.Value(secureClientUserContextKey{}).(secureClientUser)
	return user, ok && user.ID != ""
}

// errSecureClientCallerTimeout is the lookup that exceeded
// secureClientCallerBudget.
var errSecureClientCallerTimeout = errors.New("the caller account lookup exceeded its budget")

// secureClientCallerAccount names the account on the client end of the
// request's loopback TCP connection; replaceable in tests.
var secureClientCallerAccount = func(ctx context.Context) (string, error) {
	peer, ok := ctx.Value(acpConnPeerKey{}).(*acpConnPeer)
	if !ok || peer == nil {
		return "", errors.New("the request carries no TCP connection")
	}
	return peer.account(secureClientCallerBudget)
}

// loopbackPeerAccount is the kernel lookup behind acpConnPeer.account;
// replaceable in tests.
var loopbackPeerAccount = peercred.LoopbackTCPPeerAccount

// account returns the account that owns the client end of the connection
// (a SID on Windows, a decimal uid elsewhere), waiting at most budget. The
// lookup runs once per connection, in its own goroutine, so a slow table
// read never holds the request past budget; a later request on the same
// connection gets the answer it found.
func (p *acpConnPeer) account(budget time.Duration) (string, error) {
	p.accountOnce.Do(func() {
		p.accountDone = make(chan struct{})
		local, remote := p.local, p.remote
		go func() {
			defer close(p.accountDone)
			defer func() {
				if r := recover(); r != nil {
					p.accountErr = fmt.Errorf("caller account lookup panicked: %v", r)
				}
			}()
			p.accountID, p.accountErr = loopbackPeerAccount(local, remote)
		}()
	})
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-p.accountDone:
		return p.accountID, p.accountErr
	case <-timer.C:
		return "", errSecureClientCallerTimeout
	}
}

// attachSecureClientUser labels the request's end user after token
// authentication. It never fails the request: any error, and any panic,
// returns ctx with at most the claimed header account.
func attachSecureClientUser(ctx context.Context) (out context.Context) {
	if ctx == nil || !secureClientUserAttribution.Load() {
		return ctx
	}
	if _, sandboxed := sandboxauth.FromContext(ctx); sandboxed {
		return ctx
	}
	if _, done := ctx.Value(secureClientUserContextKey{}).(secureClientUser); done {
		return ctx
	}
	defer func() {
		if r := recover(); r != nil {
			out = ctx
			secureClientUserWarnf("end-user attribution skipped after a panic: %v", r)
		}
	}()
	claim := AgentIdentityFromContext(ctx)
	user := secureClientUser{
		ID:   secureClientUserText(claim.UserID, secureClientUserIDMaxBytes),
		Name: secureClientUserText(claim.UserName, secureClientUserNameMaxBytes),
	}
	if useridentity.KindForID(user.ID) == "" {
		// Not an OS account id: nothing AI Defense can key on.
		user.ID, user.Name = "", ""
	}
	account, err := secureClientCallerAccount(ctx)
	account = strings.TrimSpace(account)
	switch {
	case err == nil && useridentity.KindForID(account) != "" && sameSecureClientAccount(account, user.ID):
		user.ID = account
		user.Assurance = useridentity.AssuranceVerified
	case err == nil && useridentity.KindForID(account) != "":
		if user.ID != "" {
			secureClientUserWarnf("the hook named account %s but its connection belongs to %s; reporting %s", user.ID, account, account)
		}
		user.ID, user.Name = account, ""
		user.Assurance = useridentity.AssuranceVerified
	case user.ID != "":
		user.Assurance = useridentity.AssuranceClaimed
	default:
		return ctx
	}
	user.IDKind = useridentity.KindForID(user.ID)
	if user.Assurance == useridentity.AssuranceVerified {
		user.UPN = secureClientCachedUPN(user.ID)
	}
	ctx = context.WithValue(ctx, secureClientUserContextKey{}, user)
	if user.Assurance == useridentity.AssuranceVerified {
		// Records built from the request name the account the kernel
		// proved, not the header claim.
		id := AgentIdentityFromContext(ctx)
		if id.UserID != user.ID || id.UserName != user.Name {
			id.UserID, id.UserIDKind, id.UserName = user.ID, user.IDKind, user.Name
			ctx = ContextWithAgentIdentity(ctx, id)
		}
	}
	return ctx
}

// sameSecureClientAccount compares two account ids; a SID's letters are
// case-insensitive.
func sameSecureClientAccount(a, b string) bool {
	return a != "" && strings.EqualFold(a, b)
}

// secureClientUserText trims a value and drops it when it is longer than
// limit or holds a control character or a space other than inside an
// account name.
func secureClientUserText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > limit {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

// secureClientUPNSupported reports whether the gateway can resolve a
// directory UPN by itself under Secure Client: Windows answers it from the
// SID (LSA, TranslateNameW). macOS and Linux name the UPN only through the
// guardian's identity record, which Secure Client does not run, so no
// lookup is started there.
var secureClientUPNSupported = runtime.GOOS == "windows"

// secureClientDirectoryFacts reads the in-memory directory cache without
// waiting; a cold or expired entry starts one background lookup. Tests
// replace it.
var secureClientDirectoryFacts = func(id string) (useridentity.DirectoryFacts, bool) {
	key := id
	if useridentity.KindForID(id) == useridentity.KindWindowsSID {
		key = strings.ToUpper(id)
	}
	return peerDirectoryCache().getWithColdWait(key, false, false)
}

// secureClientCachedUPN returns the cached UPN of a verified account, or "".
func secureClientCachedUPN(id string) (upn string) {
	if !secureClientUPNSupported || id == "" {
		return ""
	}
	defer func() {
		if r := recover(); r != nil {
			upn = ""
			secureClientUserWarnf("directory lookup skipped after a panic: %v", r)
		}
	}()
	facts, ok := secureClientDirectoryFacts(id)
	if !ok {
		return ""
	}
	return secureClientUPN(facts.UPN)
}

// secureClientUPN validates a UPN: name@suffix with no space or control
// character, within the registry's principal limit.
func secureClientUPN(upn string) string {
	upn = secureClientUserText(upn, secureClientUPNMaxBytes)
	at := strings.LastIndexByte(upn, '@')
	if at <= 0 || at == len(upn)-1 || strings.ContainsAny(upn, " \t") {
		return ""
	}
	return upn
}

// secureClientRequestIdentity is requestIdentityFor under Secure Client: the
// verified UPN of the request's account as its principal, and nothing else.
func secureClientRequestIdentity(ctx context.Context, userID string) *llmEventIdentity {
	user, ok := secureClientUserFromContext(ctx)
	if !ok || user.UPN == "" || user.Assurance != useridentity.AssuranceVerified ||
		!sameSecureClientAccount(user.ID, userID) {
		return nil
	}
	return &llmEventIdentity{Directory: useridentity.DirectoryFacts{
		Principal: user.UPN,
		UPN:       user.UPN,
		Assurance: useridentity.AssuranceVerified,
	}}
}

// v8RecordNamesCaller reports whether a guardrail evaluation record names
// its caller. Outside Secure Client it always does. Under Secure Client it
// does for a request whose end user attachSecureClientUser labelled, so
// Cisco AI Defense can tell whose inspection a verdict was; any other
// Secure Client record keeps naming no user.
func v8RecordNamesCaller(ctx context.Context, callerID string) bool {
	if !ManagedEnterpriseActive() {
		return true
	}
	user, ok := secureClientUserFromContext(ctx)
	return ok && sameSecureClientAccount(user.ID, callerID)
}

// secureClientInventoryIdentity is the principal of an inventory record's
// owner under Secure Client. The owner of a profile directory comes from the
// filesystem, never from a request, so it is verified like a kernel-named
// caller; the UPN is read from the directory cache without waiting.
func secureClientInventoryIdentity(userID string) *llmEventIdentity {
	if !secureClientUserAttribution.Load() {
		return nil
	}
	upn := secureClientCachedUPN(strings.TrimSpace(userID))
	if upn == "" {
		return nil
	}
	return &llmEventIdentity{Directory: useridentity.DirectoryFacts{
		Principal: upn,
		UPN:       upn,
		Assurance: useridentity.AssuranceVerified,
	}}
}

// secureClientUserWarnLast rate-limits secureClientUserWarnf to one line a
// minute, so a misbehaving caller cannot flood the gateway log.
var secureClientUserWarnLast atomic.Int64

func secureClientUserWarnf(format string, args ...any) {
	now := time.Now().UnixNano()
	last := secureClientUserWarnLast.Load()
	if now-last < int64(time.Minute) || !secureClientUserWarnLast.CompareAndSwap(last, now) {
		return
	}
	fmt.Fprintf(os.Stderr, "[identity] "+format+"\n", args...)
}
