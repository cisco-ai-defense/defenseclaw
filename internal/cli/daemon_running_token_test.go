// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestReadRunningGatewayTokenIsPrivateAndPIDBound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, runningGatewayTokenFilename)
	if err := safefile.WritePrivate(path, []byte(`{"pid":1234,"token":"loaded-token"}`)); err != nil {
		t.Fatal(err)
	}
	if got := readRunningGatewayToken(dir, 1234); got != "loaded-token" {
		t.Fatal("private handoff for the verified PID was not read")
	}
	if got := readRunningGatewayToken(dir, 5678); got != "" {
		t.Fatal("handoff from a different process was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(path, []byte(`{"pid":1234,"token":""}`)); err != nil {
		t.Fatal(err)
	}
	if got := readRunningGatewayToken(dir, 1234); got != "" {
		t.Fatal("empty handoff credential was accepted")
	}
}
