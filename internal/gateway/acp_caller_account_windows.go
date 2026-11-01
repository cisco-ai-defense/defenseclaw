//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "net/http"

func acpHomePrincipalUID(_, _ string) (int, bool) { return 0, false }

// acpHomePrincipalPeerRefusal: the caller account is not checked on Windows.
func acpHomePrincipalPeerRefusal(_ *http.Request, _, _ string) string {
	return acpCallerAccountUnverifiedReason
}
