// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	outageNowDefaultConfig = "config_version: 9\nobservability: {}\nguardrail:\n  mode: observe\n"
	outageNowStrictConfig  = outageNowDefaultConfig + "  rule_pack: strict\n"
)

func writeOutageNowConfig(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if body == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
