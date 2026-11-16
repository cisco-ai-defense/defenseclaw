// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// rel-1-0-6 GAP-0207: the guardian's removal of a connector the
// administrator took out of guardrail.connectors leaves the home as it was
// before the connector was added: the Amp plugin folders the install created
// and its connector_backups folder go once empty.
func TestRemoveUserHooksRemovesTheFoldersTheInstallCreated(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	opts := InstallOptions{
		ConnectorName: "amp", UserHome: home, OwnerUID: os.Getuid(), OwnerGID: os.Getgid(),
		APIAddr: "127.0.0.1:18970", ProxyAddr: "127.0.0.1:4000",
		APIToken: strings.Repeat("a", 64), OTLPPathToken: strings.Repeat("b", 64),
		GuardrailMode: "action", HookFailMode: "closed", AgentVersion: "0.0.1785334225", Registry: connector.NewDefaultRegistry(),
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install amp: %v", err)
	}
	plugins := filepath.Join(home, ".config", "amp", "plugins")
	if _, err := os.Stat(filepath.Join(plugins, "defenseclaw.ts")); err != nil {
		t.Fatalf("the install did not write the Amp plugin: %v", err)
	}
	if err := RemoveUserHooks(context.Background(), opts); err != nil {
		t.Fatalf("RemoveUserHooks: %v", err)
	}
	for _, gone := range []string{plugins, filepath.Join(home, ".config", "amp"), filepath.Join(home, ".defenseclaw", "connector_backups", "amp")} {
		if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s stays after the removal: %v", gone, err)
		}
	}
}
