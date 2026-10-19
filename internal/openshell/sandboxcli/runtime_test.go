// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

func TestRunRuntimeSelection(t *testing.T) {
	for _, test := range []struct {
		requested, configured, want string
	}{
		{"", "", "openshell"}, {"auto", "auto", "openshell"},
		{"openshell", "axis", "openshell"}, {"auto", "openshell", "openshell"},
	} {
		got, err := CheckRunRuntime(test.requested, test.configured)
		if err != nil || got != test.want {
			t.Fatalf("selection %q/%q = %q, %v", test.requested, test.configured, got, err)
		}
	}
	for _, pair := range [][2]string{{"axis", ""}, {"auto", "axis"}, {"", "axis"}} {
		_, err := CheckRunRuntime(pair[0], pair[1])
		var unavailable *sandboxapi.Error
		var exit *ExitError
		if !errors.As(err, &unavailable) || unavailable.Code != sandboxapi.CodeUnavailable ||
			!errors.As(err, &exit) || exit.Code != 3 {
			t.Fatalf("AXIS selection %q should refuse as unavailable: %v", pair, err)
		}
	}
	for _, pair := range [][2]string{{"AXIS", ""}, {"other", ""}, {"openshell", "other"}} {
		_, err := CheckRunRuntime(pair[0], pair[1])
		var invalid *sandboxapi.Error
		var exit *ExitError
		if !errors.As(err, &invalid) || invalid.Code != sandboxapi.CodeInvalid ||
			!errors.As(err, &exit) || exit.Code != 2 {
			t.Fatalf("unknown selection %q should refuse: %v", pair, err)
		}
	}
}

func TestRunAxisRefusesBeforeNestedInfoOrHostExecution(t *testing.T) {
	for _, args := range [][]string{nil, {"--version"}, {"auth", "login"}} {
		for _, configured := range []bool{false, true} {
			app := &App{
				Getenv:      func(string) string { t.Fatal("native/host shortcut inspected before runtime refusal"); return "" },
				LookPath:    func(string) (string, error) { t.Fatal("host binary lookup before refusal"); return "", nil },
				ExecProcess: func(string, []string, []string) error { t.Fatal("host execution before refusal"); return nil },
			}
			o := RunOptions{Harness: "claude", Runtime: "axis", Args: args}
			if configured {
				app.Cfg = &config.Config{Sandbox: &config.SandboxConfig{Runtime: "axis"}}
				o.Runtime = "auto"
			}
			var unavailable *sandboxapi.Error
			if err := app.Run(context.Background(), o); !errors.As(err, &unavailable) || unavailable.Code != sandboxapi.CodeUnavailable {
				t.Fatalf("configured=%v args=%v: %v", configured, args, err)
			}
		}
	}
}
