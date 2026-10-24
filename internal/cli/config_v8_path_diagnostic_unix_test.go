// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestConfigValidateExplainsManagedAuditPathPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can inspect a mode 000 directory")
	}
	root := t.TempDir()
	private := filepath.Join(root, "service-private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(private, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(private, 0o700) })
	candidate := filepath.Join(root, "candidate.yaml")
	if err := os.WriteFile(candidate, []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\nguardrail:\n  enabled: true\n  mode: observe\n  host: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := checkConfigV8Candidate(candidate, private)
	var pathError *config.V8ConfigPathError
	if !errors.As(err, &pathError) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("candidate error = %v, want permission-denied path inspection", err)
	}
	failure := configV8ValidationFailure(err)
	if failure.Path != "$.observability.local.path" ||
		!strings.Contains(failure.Reason, "cannot inspect") ||
		!strings.Contains(failure.Reason, "administrator") ||
		strings.Contains(failure.Reason, "could not be compiled safely") {
		t.Fatalf("permission diagnostic = %+v", failure)
	}
}
