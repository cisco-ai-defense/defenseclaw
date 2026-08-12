// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

func TestDefaultRegistryNotifyEndpointContracts(t *testing.T) {
	expected := map[string]string{
		"codex": "/api/v1/codex/notify",
	}
	registry := NewDefaultRegistry()
	for _, name := range registry.Names() {
		t.Run(name, func(t *testing.T) {
			registered, ok := registry.Get(name)
			if !ok {
				t.Fatalf("default registry lost connector %q", name)
			}
			endpoint, hasNotify := registered.(NotifyEndpoint)
			wantPath, wantNotify := expected[name]
			if hasNotify != wantNotify {
				t.Fatalf("NotifyEndpoint implemented = %v, want %v", hasNotify, wantNotify)
			}
			if hasNotify && endpoint.NotifyAPIPath() != wantPath {
				t.Fatalf("NotifyAPIPath() = %q, want %q", endpoint.NotifyAPIPath(), wantPath)
			}
		})
	}
}
