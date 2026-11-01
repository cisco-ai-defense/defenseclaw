// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// installedManifest is runtime.json of the installed tree
// (packaging/unix/build-scanner-runtime.sh).
type installedManifest struct {
	SchemaVersion int               `json:"schema_version"`
	Python        string            `json:"python"`
	Versions      map[string]string `json:"versions"`
}

// installedRuntime is the trusted installed tree; a seam for tests.
var installedRuntime = func() (string, error) {
	_, root, err := managed.InstalledUnixScannerRuntimeInScan()
	return root, err
}

// runInstalled runs a scanner from the runtime the managed-enterprise Linux
// or macOS package installed (GAP-1527). The package manager writes the
// tree root-owned and complete, so there is nothing to unpack: prepare and
// prune have no work here.
func runInstalled(args []string, stdout, stderr io.Writer) int {
	root, err := installedRuntime()
	if err != nil {
		if errors.Is(err, managed.ErrNoScannerRuntime) {
			fmt.Fprintln(stderr, "defenseclaw-scanners: this installation has no scanner runtime; the defenseclaw-enterprise package installs it")
		} else {
			fmt.Fprintf(stderr, "defenseclaw-scanners: the scanner runtime is not trusted: %v; reinstall the defenseclaw-enterprise package to restore it\n", err)
		}
		return 1
	}
	manifest, err := readInstalledManifest(root)
	if err != nil {
		fmt.Fprintf(stderr, "defenseclaw-scanners: %v\n", err)
		return 1
	}
	var script string
	var scriptArgs []string
	switch args[0] {
	case "versions":
		encoded, _ := json.MarshalIndent(map[string]any{"versions": manifest.Versions, "prepared": true, "root": root}, "", "  ")
		fmt.Fprintln(stdout, string(encoded))
		return 0
	case "--version":
		fmt.Fprintln(stdout, installedVersionLine(manifest))
		return 0
	case "prepare", "prune":
		return 0
	case "skill-scanner":
		script, scriptArgs = skillScannerScript, args[1:]
	case "plugin-scan":
		script, scriptArgs = pluginScanScript, args[1:]
	case "mcp-scan":
		script, scriptArgs = mcpScanScript, args[1:]
	default:
		fmt.Fprintf(stderr, "defenseclaw-scanners: unknown tool %q\n", args[0])
		return 2
	}
	python := filepath.Join(root, filepath.FromSlash(manifest.Python))
	// -I: no user site or PYTHON* variables; -B: the tree is read-only and
	// was byte-compiled when it was built.
	cmd := exec.Command(python, append([]string{"-I", "-B", "-c", script}, scriptArgs...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = pythonEnv(os.Environ(), filepath.Dir(python))
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "defenseclaw-scanners: run %s: %v\n", args[0], err)
		return 1
	}
	return 0
}

func readInstalledManifest(root string) (installedManifest, error) {
	var manifest installedManifest
	raw, err := os.ReadFile(filepath.Join(root, "runtime.json"))
	if err != nil {
		return manifest, fmt.Errorf("scanner runtime manifest: %w", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return manifest, fmt.Errorf("scanner runtime manifest: %w", err)
	}
	clean := filepath.ToSlash(filepath.Clean(manifest.Python))
	if manifest.SchemaVersion != 1 || !strings.HasPrefix(clean, "python/") || strings.Contains(clean, "..") {
		return manifest, errors.New("scanner runtime manifest is not schema 1 with an interpreter inside the runtime")
	}
	return manifest, nil
}

// installedVersionLine names every pinned component, so a changed runtime
// changes the scanners' cache key.
func installedVersionLine(manifest installedManifest) string {
	names := make([]string, 0, len(manifest.Versions))
	for name := range manifest.Versions {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := []string{"defenseclaw-scanners"}
	for _, name := range names {
		parts = append(parts, name+" "+manifest.Versions[name])
	}
	return strings.Join(parts, " ") + " runtime installed"
}
