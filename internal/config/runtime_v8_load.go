// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// LoadRuntimeV8File validates, compiles, and decodes one immutable v8 source
// for non-gateway CLI consumers such as daemon/watchdog status and API
// preflight. Exporter construction remains owned exclusively by the compiled
// observability runtime graph.
func LoadRuntimeV8File(configFile string) (*Config, error) {
	configFile = strings.TrimSpace(configFile)
	if configFile == "" {
		configFile = ConfigPath()
	}
	absPath, err := filepath.Abs(configFile)
	if err != nil {
		return nil, fmt.Errorf("config: resolve v8 source: %w", err)
	}
	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("config: read v8 source %s: %w", absPath, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(ObservabilityV8MaxSourceBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("config: read v8 source %s: %w", absPath, err)
	}
	if len(raw) > ObservabilityV8MaxSourceBytes {
		return nil, fmt.Errorf("config: v8 source exceeds the %d-byte limit", ObservabilityV8MaxSourceBytes)
	}
	compiled, err := ParseCompileObservabilityV8(
		absPath,
		raw,
		ObservabilityV8CompileOptions{DefaultDataDir: DefaultDataPath()},
	)
	if err != nil {
		return nil, err
	}
	candidate, err := LoadRuntimeV8FromBytes(absPath, raw)
	if err != nil {
		return nil, err
	}
	if compiled == nil || compiled.Plan == nil {
		return nil, fmt.Errorf("config: canonical v8 compiler returned no effective plan")
	}
	snapshot := compiled.Plan.Snapshot()
	if strings.TrimSpace(snapshot.Local.Path) == "" || strings.TrimSpace(snapshot.Local.JudgeBodiesPath) == "" {
		return nil, fmt.Errorf("config: canonical v8 local store paths are incomplete")
	}
	candidate.DataDir = compiled.DataDir
	if err := ApplyRuntimeV8DataDirDefaultsFromBytes(candidate, absPath, raw, compiled.DataDir); err != nil {
		return nil, err
	}
	candidate.AuditDB = snapshot.Local.Path
	candidate.JudgeBodiesDB = snapshot.Local.JudgeBodiesPath
	return candidate, nil
}
