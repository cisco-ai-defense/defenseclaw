// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadGatewayTokenDotenvRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.env")
	if err := os.WriteFile(
		target,
		[]byte("DEFENSECLAW_GATEWAY_TOKEN=symlink-secret\n"),
		0o600,
	); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, ".env")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if got := readGatewayTokenDotenv(link); len(got) != 0 {
		t.Fatalf("symlink dotenv produced gateway tokens: %#v", got)
	}
}

func TestReadGatewayTokenDotenvRejectsOversizeInsteadOfParsingPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	body := "DEFENSECLAW_GATEWAY_TOKEN=prefix-must-not-load\n" +
		strings.Repeat("x", maxGatewayDotenvBytes)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write oversize dotenv: %v", err)
	}

	if got := readGatewayTokenDotenv(path); len(got) != 0 {
		t.Fatalf("oversized dotenv produced gateway tokens: %#v", got)
	}
}
