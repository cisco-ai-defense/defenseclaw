// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestAIRuntimeDynamicHomesOnlyForDirectUnmanagedRoot(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AIDiscovery.HomeDirs = []string{"/home/known"}
	if got := aiRuntimeHomeDirs(cfg, true); !reflect.DeepEqual(got, []string{"/home/known", "/home/*", "/sessions/*"}) {
		t.Fatalf("direct root homes = %v", got)
	}
	if got := aiRuntimeHomeDirs(cfg, false); !reflect.DeepEqual(got, []string{"/home/known"}) {
		t.Fatalf("per-user homes = %v", got)
	}
	cfg.DeploymentMode = "managed_enterprise"
	if got := aiRuntimeHomeDirs(cfg, true); !reflect.DeepEqual(got, []string{"/home/known"}) {
		t.Fatalf("managed homes = %v", got)
	}
}
