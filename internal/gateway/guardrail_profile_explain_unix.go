// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"fmt"
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
	account, err := resolver.LookupUser(name)
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
	ctx, cancel := context.WithTimeout(context.Background(), profileExplainLookupTimeout)
	defer cancel()
	if qualified := profileExplainQualifiedName(ctx, name); qualified != "" {
		return profileSubject{UserName: name}, fmt.Errorf("no account named %q on this host; getent passwd knows %q: use that spelling or its uid", name, qualified)
	}
	return profileSubject{UserName: name}, fmt.Errorf("no account named %q on this host; check the current spelling with getent passwd or use the account uid", name)
}

// profileExplainDirectoryFacts resolves the facts a verified request from
// uid carries: the account database plus the guardian identity spool.
var profileExplainDirectoryFacts = func(id string) (useridentity.DirectoryFacts, error) {
	return resolvePeerDirectoryFacts(id)
}
