// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// profileExplainLookupTimeout bounds the account lookup of explain.
const profileExplainLookupTimeout = 10 * time.Second

// profileExplainAccount names an account (name or uid) through the platform
// resolver the hook path uses: NSS on Linux, so directory accounts resolve
// even where os/user reads only the local files, and Open Directory on macOS,
// which has no getent.
var profileExplainAccount = func(name string) (id, userName string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	resolver := unixidentity.Default(ctx)
	// name@domain and DOMAIN\name resolve as getent resolves them, when the
	// answer is the same account (GAP-0711).
	account, err := unixidentity.LookupAccountSpelling(resolver, name, func(uid int) (useridentity.DirectoryFacts, bool) {
		facts, err := profileExplainDirectoryFacts(strconv.Itoa(uid))
		return facts, err == nil
	})
	if err != nil {
		uid, convErr := strconv.Atoi(name)
		if convErr != nil {
			return "", "", err
		}
		if account, err = resolver.LookupUID(uid); err != nil {
			return "", "", err
		}
	}
	return strconv.Itoa(account.UID), sanitizeLLMEventUser(account.Name), nil
}

// profileExplainUnresolved resolves an account the platform resolver cannot
// name through the OS account database (os/user), with its error.
var profileExplainQualifiedName = func(ctx context.Context, name string) string {
	return unixidentity.QualifiedUserName(ctx, unixidentity.Default(ctx), name)
}

func profileExplainUnresolved(name string, _ error) (profileSubject, error) {
	if local, err := lookupLocalProfileSubject(name); err == nil {
		return local, nil
	}
	if cached, ok := profileExplainCachedSubject(name, time.Now()); ok {
		return cached, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	if qualified := profileExplainQualifiedName(ctx, name); qualified != "" {
		return profileSubject{UserName: name}, fmt.Errorf("no account named %q on this host; getent passwd knows %q: use that spelling or its uid", name, qualified)
	}
	check := "getent passwd"
	if runtime.GOOS == "darwin" {
		check = "id or dscl /Search -read /Users/<name>" // macOS has no getent (GAP-1107)
	}
	return profileSubject{UserName: name}, fmt.Errorf("no account named %q on this host; check the current spelling with %s or use the account uid", name, check)
}

// profileExplainDirectoryFacts resolves the facts a verified request from
// uid carries: the account database plus the guardian identity spool.
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	return resolvePeerDirectoryFacts(id)
}

// profileExplainCachedSubject serves explain for an account the directory
// cannot name now (SSSD stopped, a domain controller away) from what its
// hooks apply: the facts the gateway cached for the uid whose account had
// that name (or that uid), within the hour they are served. Explain then
// shows the hook's profile with the age of the facts, not a spelling error
// (GAP-0899).
var profileExplainCachedSubject = func(name string, now time.Time) (profileSubject, bool) {
	uid, userName, ok := managedHookPeerHomes.cachedHolder(name)
	if !ok {
		return profileSubject{}, false
	}
	id := strconv.Itoa(uid)
	facts, fetchedAt, ok := peerDirectoryCache().peek(id)
	if !ok || now.Sub(fetchedAt) > identityDirectoryMaxAge {
		return profileSubject{}, false
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: userName, Directory: facts,
	}, identityLookupBlocking.Load())
	subject.cachedFactsAge = max(now.Sub(fetchedAt), time.Second)
	return subject, true
}
