// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A repair of a previously protected target that fails after Setup keeps the
// installed hooks and restores the lock; it never tears the connector down.
func TestInstallRepairFailureKeepsProtectedHooks(t *testing.T) {
	skipIfRoot(t)
	home := newTestHome(t)
	dataDir := filepath.Join(home, ".defenseclaw")
	pluginPath := filepath.Join(home, ".config", "amp", "plugins", "defenseclaw.ts")
	opts := InstallOptions{
		ConnectorName: "amp",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      strings.Repeat("a", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  "0.0.1785334225",
		Registry:      connector.NewDefaultRegistry(),
	}
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("first install: %v", err)
	}
	protectedLock := connector.LoadHookContractLockEntry(dataDir, "amp")
	if protectedLock.Connector == "" {
		t.Fatal("first install left no hook contract lock")
	}

	var events []string
	previousSink := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		events = append(events, managed.FormatResilienceEvent(marker, fields))
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = previousSink })
	originalPublisher := publishEnterpriseHookAPIToken
	publishEnterpriseHookAPIToken = func(_, _, _ string) error {
		return errors.New("injected transient publication failure")
	}
	t.Cleanup(func() { publishEnterpriseHookAPIToken = originalPublisher })

	for pass := 0; pass < 2; pass++ {
		_, err := Install(context.Background(), opts)
		if err == nil || !strings.Contains(err.Error(), "injected transient publication failure") {
			t.Fatalf("repair pass %d error = %v, want the injected failure", pass, err)
		}
		if _, statErr := os.Lstat(pluginPath); statErr != nil {
			t.Fatalf("repair failure tore down the protected plugin: %v", statErr)
		}
		if entry := connector.LoadHookContractLockEntry(dataDir, "amp"); entry.Connector != "amp" {
			t.Fatalf("repair failure dropped the hook contract lock: %+v", entry)
		}
	}
	degraded := 0
	for _, event := range events {
		if strings.HasPrefix(event, managed.MarkerDegraded) && strings.Contains(event, `connector="amp"`) {
			degraded++
		}
	}
	if degraded != 1 {
		t.Fatalf("degraded lines = %d, want one per failure streak: %v", degraded, events)
	}

	publishEnterpriseHookAPIToken = originalPublisher
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("recovery install: %v", err)
	}
	publishEnterpriseHookAPIToken = func(_, _, _ string) error {
		return errors.New("injected transient publication failure")
	}
	if _, err := Install(context.Background(), opts); err == nil {
		t.Fatal("expected the injected failure after recovery")
	}
	degraded = 0
	for _, event := range events {
		if strings.HasPrefix(event, managed.MarkerDegraded) && strings.Contains(event, `connector="amp"`) {
			degraded++
		}
	}
	if degraded != 2 {
		t.Fatalf("a new failure streak after recovery was not logged: %v", events)
	}
}
