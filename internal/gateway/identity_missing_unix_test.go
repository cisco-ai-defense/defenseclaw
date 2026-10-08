// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	osuser "os/user"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func TestUnixDefinitiveMissingAccount(t *testing.T) {
	if !definitiveMissingAccount(unixidentity.ErrNotFound) || !definitiveMissingAccount(osuser.UnknownUserIdError(1001)) {
		t.Fatal("NSS definitive absence counted as an outage")
	}
	cache := newIdentityDirectoryCache(nil)
	if cache.gone == nil || cache.confirmGone {
		t.Fatal("NSS absence must remain visible after an unrelated local lookup")
	}
}
