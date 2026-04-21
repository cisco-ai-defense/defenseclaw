// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestSkillScanner_SubprocessExitEmptyStdoutFails(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-scanner.sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var emitted []gatewaylog.Event
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

	ss := NewSkillScanner(config.SkillScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})
	ctx := ContextWithGatewayWriter(context.Background(), w)
	_, err = ss.Scan(ctx, "/tmp/target")
	if err == nil {
		t.Fatal("expected error")
	}
	var sawErr bool
	for _, e := range emitted {
		if e.EventType == gatewaylog.EventError && e.Error != nil && e.Error.Code == string(gatewaylog.ErrCodeSubprocessExit) {
			sawErr = true
		}
	}
	if !sawErr {
		t.Fatalf("expected SUBPROCESS_EXIT event, got %d events", len(emitted))
	}
}
