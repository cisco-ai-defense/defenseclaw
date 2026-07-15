// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/nativeinstallstate"
)

const (
	moduleEntryPointScript  = `import os,runpy,sys; cwd=sys.argv[1]; sys.argv=["defenseclaw",*sys.argv[2:]]; os.chdir(cwd) if cwd else None; runpy.run_module("defenseclaw.main",run_name="__main__")`
	consoleEntryPointScript = `import importlib.metadata as m,os,sys; name=sys.argv[1]; cwd=sys.argv[2]; sys.argv=[name,*sys.argv[3:]]; os.chdir(cwd) if cwd else None; matches=[e for e in m.entry_points(group="console_scripts") if e.name==name]; sys.exit(matches[0].load()() if len(matches)==1 else 1)`
)

func main() {
	if runtime.GOOS != "windows" {
		fmt.Fprintln(os.Stderr, "defenseclaw launcher is only supported on Windows")
		os.Exit(1)
	}

	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: resolve launcher path: %v\n", err)
		os.Exit(1)
	}
	binDir := filepath.Dir(self)
	installRoot := filepath.Dir(binDir)
	installState, packaged, stateErr := nativeinstallstate.LoadForExecutable(self)
	if stateErr != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: validate native install state: %v\n", stateErr)
		os.Exit(1)
	}
	python := filepath.Join(installRoot, "runtime", "python", "python.exe")
	if _, err := os.Stat(python); err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: embedded Python runtime is missing: %s\n", python)
		os.Exit(1)
	}

	logicalCWD, processCWD, err := launcherWorkingDirectories(installRoot)
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: resolve working directory: %v\n", err)
		os.Exit(1)
	}
	argv, err := launcherArgs(filepath.Base(self), logicalCWD, os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: %v\n", err)
		os.Exit(1)
	}
	cmd := exec.Command(python, argv...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = launcherEnv(binDir, filepath.Dir(python), installRoot, installState, packaged)
	cmd.Dir = processCWD

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "defenseclaw: launch managed CLI: %v\n", err)
		os.Exit(1)
	}
}

func launcherArgs(executable, workingDirectory string, userArgs []string) ([]string, error) {
	name := strings.ToLower(strings.TrimSuffix(executable, filepath.Ext(executable)))
	if name == "defenseclaw" {
		return append([]string{"-I", "-c", moduleEntryPointScript, workingDirectory}, userArgs...), nil
	}
	entryPoints := map[string]string{
		"skill-scanner":             "skill-scanner",
		"mcp-scanner":               "mcp-scanner",
		"defenseclaw-observability": "defenseclaw-observability",
	}
	entryPoint, ok := entryPoints[name]
	if !ok {
		return nil, errors.New("unrecognized managed launcher name")
	}
	return append([]string{"-I", "-c", consoleEntryPointScript, entryPoint, workingDirectory}, userArgs...), nil
}

func launcherEnv(binDir, pythonDir, installRoot string, state nativeinstallstate.State, packaged bool) []string {
	base := os.Environ()
	if packaged {
		base = state.Environment(base)
	}
	return launcherEnvFromBase(binDir, pythonDir, installRoot, base, packaged)
}

func launcherEnvFromBase(binDir, pythonDir, installRoot string, base []string, packaged bool) []string {
	pathValue := binDir + string(os.PathListSeparator) + pythonDir
	env := make([]string, 0, len(base)+3)
	sawPath := false
	for _, entry := range base {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "PYTHONHOME", "PYTHONPATH":
			continue
		case "PATH":
			sawPath = true
			if value != "" {
				value = string(os.PathListSeparator) + value
			}
			env = append(env, "PATH="+pathValue+value)
		default:
			env = append(env, entry)
		}
	}
	if !sawPath {
		env = append(env, "PATH="+pathValue)
	}
	if !packaged {
		env = append(env, "DEFENSECLAW_INSTALL_ROOT="+installRoot)
	}
	return env
}
