// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// TestJsonlKillSwitchEnabled_Matrix pins the accepted truthy-string
// vocabulary. Any change to this table is a breaking change to the
// operator-facing contract documented in docs/OBSERVABILITY.md.
func TestJsonlKillSwitchEnabled_Matrix(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
		{"disabled", false},
		{"maybe", false}, // unrecognised → off (fail-safe)
		{"1", true},
		{"true", true},
		{"TRUE", true},
		{"  true  ", true},
		{"yes", true},
		{"YES", true},
		{"on", true},
		{"ON", true},
		{"enable", true},
		{"enabled", true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := jsonlKillSwitchEnabled(tc.in); got != tc.want {
				t.Fatalf("jsonlKillSwitchEnabled(%q)=%v want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestJsonlKillSwitch_EmptyPathSkipsFile exercises the load-bearing
// downstream invariant: when the kill switch is on we construct the
// gatewaylog.Writer with an empty JSONLPath, which the writer
// interprets as "JSONL tier disabled". No file must appear on disk.
// The pretty-writer path is still available because Config.Pretty is
// independent of the JSONL tier.
func TestJsonlKillSwitch_EmptyPathSkipsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway.jsonl")

	w, err := gatewaylog.New(gatewaylog.Config{JSONLPath: ""})
	if err != nil {
		t.Fatalf("New with empty path: %v", err)
	}
	defer w.Close()

	w.Emit(gatewaylog.Event{
		EventType: gatewaylog.EventLifecycle,
		Severity:  gatewaylog.SeverityInfo,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  "gateway",
			Transition: "start",
		},
	})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("kill switch produced file at %s (err=%v)", path, err)
	}
}
