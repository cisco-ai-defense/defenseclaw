// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package opencodebridge

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestV2AdapterContextCacheAndLifecycleIdentity(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for the OpenCode adapter contract")
	}
	module := filepath.Join(t.TempDir(), "adapter.mjs")
	const sanitizer = "function defenseclawSanitizeMCPName(name) { return name.replace(/[^a-zA-Z0-9_-]/g, '_'); }\n"
	if err := os.WriteFile(module, []byte(sanitizer+Adapter+"\nexport { defenseclawV2Setup };\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "testdata/adapter.mjs", module)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("V2 adapter contract: %v\n%s", err, output)
	}
}
