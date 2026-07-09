// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

func TestSkillScanner_SubprocessExitEmptyStdoutFails(t *testing.T) {
	bin := buildScannerFixture(t, "", 7)
	var emitted []gatewaylog.Event
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatal(err)
	}
	w.WithFanout(func(e gatewaylog.Event) { emitted = append(emitted, e) })

	ss := NewSkillScanner(config.SkillScannerConfig{Binary: bin}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})
	ctx := ContextWithGatewayWriter(context.Background(), w)
	_, err = ss.Scan(ctx, t.TempDir())
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
