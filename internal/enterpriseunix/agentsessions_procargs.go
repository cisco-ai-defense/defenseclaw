// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const maxProcArgs2Bytes = 256 << 10

// darwinProcessArgv is replaceable by tests that run a macOS environment on Linux.
var darwinProcessArgv = readProcessArgv
var darwinProcessEnv = readProcessEnv
var darwinProcessParent = readProcessParent

// parseProcArgs2 reads argc, the NUL-terminated executable path, padding,
// then argc NUL-terminated arguments from kern.procargs2.
func parseProcArgs2(data []byte) ([]string, error) {
	if len(data) < 5 || len(data) > maxProcArgs2Bytes+4 {
		return nil, fmt.Errorf("kern.procargs2 has %d bytes", len(data))
	}
	argc := int(binary.LittleEndian.Uint32(data[:4]))
	rest := data[4:]
	pathEnd := bytes.IndexByte(rest, 0)
	if pathEnd < 0 || argc <= 0 || argc > len(rest) {
		return nil, fmt.Errorf("kern.procargs2 header does not parse")
	}
	rest = bytes.TrimLeft(rest[pathEnd:], "\x00")
	argv := make([]string, 0, argc)
	for len(argv) < argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, fmt.Errorf("kern.procargs2 arguments are truncated")
		}
		argv = append(argv, string(rest[:end]))
		rest = rest[end+1:]
	}
	return argv, nil
}

// parseProcArgs2Environment reads the environment after argc arguments.
// Only variables relevant to plugin loading survive the parse.
func parseProcArgs2Environment(data []byte) (map[string]string, error) {
	if len(data) < 5 || len(data) > maxProcArgs2Bytes+4 {
		return nil, fmt.Errorf("kern.procargs2 has %d bytes", len(data))
	}
	argc := int(binary.LittleEndian.Uint32(data[:4]))
	rest := data[4:]
	pathEnd := bytes.IndexByte(rest, 0)
	if pathEnd < 0 || argc <= 0 || argc > len(rest) {
		return nil, fmt.Errorf("kern.procargs2 header does not parse")
	}
	rest = bytes.TrimLeft(rest[pathEnd:], "\x00")
	for range argc {
		end := bytes.IndexByte(rest, 0)
		if end < 0 {
			return nil, fmt.Errorf("kern.procargs2 arguments are truncated")
		}
		rest = rest[end+1:]
	}
	return pluginLaunchEnvironment(rest), nil
}
