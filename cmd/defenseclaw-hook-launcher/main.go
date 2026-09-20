// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// defenseclaw-hook-launcher is the small inert Windows trampoline retained at
// the canonical cached hook path. Release builds link it with -H=windowsgui.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/hookruntime"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if isIdentityEntrypoint(os.Args[1:]) {
		if err := writeMachineIdentity(os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "defenseclaw-hook-launcher: write identity: %v\n", err)
			os.Exit(1)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		os.Exit(0)
	}
	os.Exit(hookruntime.Delegate(executable, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func isIdentityEntrypoint(args []string) bool {
	return len(args) == 1 && args[0] == "--version-json"
}

func writeMachineIdentity(w io.Writer) error {
	return json.NewEncoder(w).Encode(struct {
		SchemaVersion int    `json:"schema_version"`
		Name          string `json:"name"`
		Version       string `json:"version"`
		Commit        string `json:"commit"`
		Built         string `json:"built,omitempty"`
	}{
		SchemaVersion: 1,
		Name:          "defenseclaw-hook-launcher",
		Version:       version,
		Commit:        commit,
		Built:         date,
	})
}
