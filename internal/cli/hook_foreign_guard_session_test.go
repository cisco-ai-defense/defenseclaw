// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookcli"
)

// runEvent runs the hook-time guard for connector with a payload carrying
// event and, when set, the session ID under key.
func (f *foreignGuardFixture) runEvent(t *testing.T, connector, event, key, session string) hookexec.Options {
	t.Helper()
	payload := map[string]any{"hook_event_name": event, "cwd": filepath.Join(f.project, "src")}
	if session != "" {
		payload[key] = session
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	opts := hookexec.Options{Connector: connector, ManagedEnterprise: true, Stdin: bytes.NewReader(data), Stderr: io.Discard}
	hookcli.ApplyEnterpriseForeignHookGuard(&opts)
	return opts
}

func (f *foreignGuardFixture) guard(connector string) {
	f.summary.Connectors[connector] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
}
