// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1253: a test that boots a gateway (NewSidecar seeds the process-wide
// telemetry HMAC key from its device key) leaves the key as it found it, so
// the next test's fresh session has no correlation HMAC.
func TestGAP1253BootedSidecarLeavesTheTelemetryKeyAsItFoundIt(t *testing.T) {
	previous := gatewaylog.SwapTelemetryHMACKeyForTest(nil)
	t.Cleanup(func() { gatewaylog.SwapTelemetryHMACKeyForTest(previous) })

	t.Run("boot a gateway", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.ConfigVersion = config.ObservabilityV8ConfigVersion
		cfg.DataDir = testenv.PrivateTempDir(t)
		cfg.Gateway.DeviceKeyFile = filepath.Join(cfg.DataDir, "device.key")
		restoreGatewayProcessPosture(t)
		sidecar, err := NewSidecar(cfg, nil, nil)
		if err != nil || sidecar == nil {
			t.Fatalf("NewSidecar = sidecar:%p error:%v", sidecar, err)
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
	})

	t.Run("following fresh session", func(t *testing.T) {
		if gatewaylog.ComputePayloadHMAC(struct{ Session string }{"fresh-session"}) != "" {
			t.Fatal("the booted gateway left its telemetry HMAC key active for later tests")
		}
	})
}
