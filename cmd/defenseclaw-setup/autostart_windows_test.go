// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

func TestRunCommandUTF16UnitBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		units   int
		wantErr bool
	}{
		{name: "259", command: strings.Repeat("a", 259), units: 259},
		{name: "260", command: strings.Repeat("a", 260), units: 260},
		{name: "261", command: strings.Repeat("a", 261), units: 261, wantErr: true},
		{name: "surrogate-pair-at-260", command: strings.Repeat("a", 258) + "😀", units: 260},
		{name: "surrogate-pair-at-261", command: strings.Repeat("a", 259) + "😀", units: 261, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := runCommandUTF16Units(test.command); got != test.units {
				t.Fatalf("UTF-16 units = %d, want %d", got, test.units)
			}
			err := validateRunCommand(test.command)
			if test.wantErr && err == nil {
				t.Fatalf("validateRunCommand accepted %d UTF-16 units", test.units)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("validateRunCommand rejected %d UTF-16 units: %v", test.units, err)
			}
		})
	}
}

func TestGatewayAutoStartRegistryCommandUsesStableLocalAppDataLauncher(t *testing.T) {
	localAppData := `C:\Users\Jane Doe\AppData\Local`
	profile := `C:\Users\Jane Doe`
	gateway := localAppData + `\Programs\DefenseClaw\bin\defenseclaw-gateway.exe`

	got, err := gatewayAutoStartRegistryCommandForRoots(gateway, localAppData, profile)
	if err != nil {
		t.Fatal(err)
	}
	want := `"%LOCALAPPDATA%\Programs\DefenseClaw\bin\defenseclaw-startup.exe"`
	if got != want {
		t.Fatalf("gateway auto-start command = %q, want %q", got, want)
	}
	if err := validateRunCommand(got); err != nil {
		t.Fatalf("stable gateway auto-start command violates Run contract: %v", err)
	}
}

func TestGatewayAutoStartRegistryCommandRejectsUnsupportedRedirectedLength(t *testing.T) {
	gateway := `D:\redirected\` + strings.Repeat("x", 245) + `\bin\defenseclaw-gateway.exe`
	_, err := gatewayAutoStartRegistryCommandForRoots(
		gateway,
		`C:\Users\Jane Doe\AppData\Local`,
		`C:\Users\Jane Doe`,
	)
	if err == nil {
		t.Fatal("long redirected gateway path unexpectedly produced a Run command")
	}
	if !strings.Contains(err.Error(), "UTF-16 code units") || !strings.Contains(err.Error(), "maximum is 260") {
		t.Fatalf("long redirected gateway diagnostic = %v", err)
	}
}

func TestSetGatewayAutoStartValueRejectsBeforeMutationAndUsesExpandString(t *testing.T) {
	keyPath := fmt.Sprintf(
		`Software\DefenseClawRunContractTest-%d-%d`,
		os.Getpid(),
		time.Now().UnixNano(),
	)
	key, _, err := registry.CreateKey(
		registry.CURRENT_USER,
		keyPath,
		registry.QUERY_VALUE|registry.SET_VALUE,
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = key.Close()
		_ = registry.DeleteKey(registry.CURRENT_USER, keyPath)
	})

	if err := setGatewayAutoStartValue(key, strings.Repeat("a", 261)); err == nil {
		t.Fatal("registry sink accepted a 261-unit Run command")
	}
	if _, _, err := key.GetStringValue(gatewayAutoStartValueName); err != registry.ErrNotExist {
		t.Fatalf("rejected Run command mutated the registry: %v", err)
	}

	command := `"%LOCALAPPDATA%\Programs\DefenseClaw\bin\defenseclaw-startup.exe"`
	if err := setGatewayAutoStartValue(key, command); err != nil {
		t.Fatal(err)
	}
	got, valueType, err := key.GetStringValue(gatewayAutoStartValueName)
	if err != nil {
		t.Fatal(err)
	}
	if got != command {
		t.Fatalf("stored command = %q, want %q", got, command)
	}
	if valueType != registry.EXPAND_SZ {
		t.Fatalf("stored Run value type = %d, want REG_EXPAND_SZ (%d)", valueType, registry.EXPAND_SZ)
	}
}
