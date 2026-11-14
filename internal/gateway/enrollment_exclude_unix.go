// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import "github.com/defenseclaw/defenseclaw/internal/unixidentity"

// enrollmentExcludeEntryUnknown reports an exclude_users entry that excludes
// nobody on Linux and macOS: the platform resolver (NSS on Linux, Open
// Directory on macOS) answers "no such account", or it resolves a spelling
// (DOMAIN\\name, name@domain, a bare name for a fully qualified account) that
// the enumerator does not match, because exclude_users matches the exact
// account name or its decimal uid. A failed or ambiguous lookup is not
// reported.
var enrollmentExcludeEntryUnknown = func(entry string) bool {
	uid, name, err := profileExplainAccount(entry)
	if err != nil {
		return unixidentity.IsNotFound(err)
	}
	return entry != name && entry != uid
}
