// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// defenseclaw-hook-user is the per-user Unix Claude Code hook entry point.
// It keeps the hook-only package graph small while hookexec supplies the
// shared response and transport rules.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/hookuser"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if len(os.Args) == 1 && stdinPiped() && cursorEvent(os.Stdin) {
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("defenseclaw-hook-user version %s (commit=%s, built=%s)\n", version, commit, date)
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--version-json" {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			SchemaVersion int    `json:"schema_version"`
			Name          string `json:"name"`
			Version       string `json:"version"`
			Commit        string `json:"commit"`
			Built         string `json:"built,omitempty"`
		}{1, "defenseclaw-hook-user", version, commit, date})
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "fallback-guard-user-hook" {
		self, err := os.Executable()
		if err != nil {
			os.Exit(2)
		}
		hookuser.ExitStoppingLooks(runFallbackGuardAt(self, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, hookexec.ProcessStartTime()))
	}
	home, addr, ok := hookuser.RegisteredArgs(os.Args[1:])
	if !ok {
		fmt.Fprintln(os.Stderr, "defenseclaw-hook-user: invalid hook command")
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	hookuser.ExitStoppingLooks(hookuser.Run(self, home, addr, os.Stdin, os.Stdout, os.Stderr, hookexec.ProcessStartTime()))
}

// runFallbackGuardAt uses the native hook only when its companion guard is
// unavailable, so a healthy registration issues one gateway decision.
func runFallbackGuardAt(self string, args []string, stdin io.Reader, stdout, stderr io.Writer, startedAt time.Time) int {
	if len(args) != 7 && len(args) != 9 {
		return 2
	}
	home, addr, ok := hookuser.RegisteredArgs(args[2:])
	if !ok || args[0] != "fallback-guard-user-hook" || filepath.Base(home) != ".defenseclaw" {
		return 2
	}
	account := filepath.Dir(home)
	native := filepath.Join(account, ".local", "bin", "defenseclaw-hook-user")
	guard := filepath.Join(account, ".local", "bin", "defenseclaw-hook-post")
	if args[1] != guard || !sameExecutable(self, native) {
		return 2
	}
	info, err := os.Lstat(guard)
	if err == nil && info.Mode().IsRegular() && info.Mode()&0o111 != 0 && info.Mode().Perm()&0o022 == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		check := exec.CommandContext(ctx, guard, "--guard-user-hook-capability")
		check.Stderr = io.Discard
		capability, checkErr := check.Output()
		if checkErr == nil && bytes.Equal(capability, []byte("defenseclaw-hook-post guard-user-hook v1\n")) {
			return 0
		}
	}
	return hookuser.Run(self, home, addr, stdin, stdout, stderr, startedAt)
}

func sameExecutable(self, registered string) bool {
	if self == registered {
		return true
	}
	actual, err := os.Stat(self)
	if err != nil || !actual.Mode().IsRegular() {
		return false
	}
	expected, err := os.Stat(registered)
	return err == nil && expected.Mode().IsRegular() && os.SameFile(actual, expected)
}

func stdinPiped() bool {
	info, err := os.Stdin.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice == 0
}

func cursorEvent(input io.Reader) bool {
	decoder := json.NewDecoder(input)
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	found := false
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		if key, _ := token.(string); key == "cursor_version" {
			var version string
			if decoder.Decode(&version) != nil {
				return false
			}
			found = found || version != ""
			continue
		}
		if !skipJSONValue(decoder) {
			return false
		}
	}
	token, err := decoder.Token()
	return err == nil && token == json.Delim('}') && found
}

func skipJSONValue(decoder *json.Decoder) bool {
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		switch token {
		case json.Delim('{'), json.Delim('['):
			depth++
		case json.Delim('}'), json.Delim(']'):
			depth--
		}
		if depth == 0 {
			return true
		}
	}
}
