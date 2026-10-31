// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import "github.com/defenseclaw/defenseclaw/internal/unixidentity"

// enrollmentExcludeEntryUnknown reports an exclude_users entry the platform
// resolver (NSS on Linux, Open Directory on macOS) answers with a definitive
// "no such account"; a failed or ambiguous lookup is not reported.
var enrollmentExcludeEntryUnknown = func(entry string) bool {
	_, _, err := profileExplainAccount(entry)
	return err != nil && unixidentity.IsNotFound(err)
}
