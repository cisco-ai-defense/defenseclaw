// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"testing"
)

// writeOTLPTokenEveryAccountCanRead writes token with mode 0644.
func writeOTLPTokenEveryAccountCanRead(t *testing.T, path, token string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0o644); err != nil {
		t.Fatal(err)
	}
}
