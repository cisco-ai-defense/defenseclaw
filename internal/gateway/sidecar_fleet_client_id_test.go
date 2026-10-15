// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestFleetMQTTClientIDsAreDistinctAndBrokerCompatible(t *testing.T) {
	seen := make(map[string]bool, 256)
	for i := 0; i < 256; i++ {
		id, err := newFleetMQTTClientID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) > 23 || len(id) < 1 || seen[id] {
			t.Fatalf("invalid or duplicate Fleet MQTT client ID %q", id)
		}
		seen[id] = true
	}
}

func TestFleetAuditEmitterRequiredOnlyWhenEnabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
	cfg.DataDir = t.TempDir()
	cfg.Gateway.DeviceKeyFile = filepath.Join(cfg.DataDir, "device.key")
	cfg.Fleet.Enabled = true
	if sidecar, err := NewSidecar(cfg, nil, nil); sidecar != nil || err == nil ||
		!strings.Contains(err.Error(), "fleet.enabled requires a durable audit store and emitter") {
		t.Fatalf("Fleet enabled without audit emitter = sidecar:%p error:%v", sidecar, err)
	}
	if sidecar, err := NewSidecar(cfg, nil, audit.NewLogger(nil)); sidecar != nil || err == nil ||
		!strings.Contains(err.Error(), "fleet.enabled requires a durable audit store and emitter") {
		t.Fatalf("Fleet enabled without durable audit store = sidecar:%p error:%v", sidecar, err)
	}

	// The optional feature must impose no audit-emitter prerequisite on a
	// normal hook gateway. The live Fleet-disabled probe also verifies /health,
	// /status and the absent Fleet route with no broker/compiler/keys.
	cfg.Fleet.Enabled = false
	sidecar, err := NewSidecar(cfg, nil, nil)
	if err != nil || sidecar == nil {
		t.Fatalf("Fleet disabled without audit emitter = sidecar:%p error:%v", sidecar, err)
	}
	t.Cleanup(func() {
		if svc := sidecar.aiDiscoverySnapshot(); svc != nil {
			_, _ = svc.CloseIfNeverStarted()
		}
		_ = shutdownJudgeStore(sidecar.judgeStore)
		if sidecar.judgeBodyStore != nil {
			_ = sidecar.judgeBodyStore.Close()
		}
		if sidecar.webhooks != nil {
			sidecar.webhooks.Close()
		}
		sidecar.alertCancel()
	})
}
