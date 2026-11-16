// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0
// Run with: go run ./scripts/check-managed-setup-payload.go <Setup.exe>
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/setuppayload"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: check-managed-setup-payload <Setup.exe>")
		os.Exit(2)
	}
	result, err := setuppayload.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, entry := range result.Entries {
		if strings.EqualFold(entry.Name, "policy_compiler.py") {
			fmt.Fprintln(os.Stderr, "managed Setup contains Fleet compiler")
			os.Exit(1)
		}
	}
	if bytes.Contains(bytes.ToLower(result.Manifest), []byte("policy_compiler.py")) {
		fmt.Fprintln(os.Stderr, "managed Setup manifest includes Fleet compiler")
		os.Exit(1)
	}
	if !json.Valid(result.Manifest) {
		fmt.Fprintln(os.Stderr, "invalid Setup manifest")
		os.Exit(1)
	}
	fmt.Println("managed Setup has no Fleet compiler")
}
