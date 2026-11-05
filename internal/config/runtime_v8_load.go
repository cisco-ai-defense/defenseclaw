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
	raw, err := readRuntimeSourceFile(absPath)
	if err != nil {
		return nil, err
	}
	if err := checkManagedConfigTrustBeforeParse(absPath, raw); err != nil {
		return nil, err
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
	if err := UseCompiledLocalStores(candidate, absPath, raw, compiled); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return candidate, nil
}

// UseCompiledLocalStores points candidate, decoded from raw at source, at the
// data_dir and the local stores of compiled, the observability plan of the
// same bytes: data_dir and the path defaults that follow it, AuditDB
// (observability.local.path, else <data_dir>/audit.db) and JudgeBodiesDB.
// These are the files the gateway opens. The runtime decode alone leaves
// AuditDB at a default in the config file's folder whenever data_dir is set,
// because v8 has no audit_db key: on a managed Linux host that is
// /etc/defenseclaw/audit.db, not /var/lib/defenseclaw/audit.db (cowork-1-0-8
// GAP-0025). The gateway start and reload and the CLI loaders call it;
// LocalAuditStorePath gives the same answer to a view that has not compiled
// the source.
func UseCompiledLocalStores(candidate *Config, source string, raw []byte, compiled *ObservabilityV8CompiledConfig) error {
	auditDB, judgeBodiesDB, err := compiledLocalStores(compiled)
	if err != nil {
		return err
	}
	if candidate == nil {
		return fmt.Errorf("no runtime config to point at the local stores")
	}
	candidate.DataDir = compiled.DataDir
	if err := ApplyRuntimeV8DataDirDefaultsFromBytes(candidate, source, raw, compiled.DataDir); err != nil {
		return err
	}
	candidate.AuditDB = auditDB
	candidate.JudgeBodiesDB = judgeBodiesDB
	return nil
}

// LocalAuditStorePath is the audit store of the v8 source raw at source, as
// the gateway resolves it (UseCompiledLocalStores): the local store of the
// source's compiled observability plan. options are the compile options the
// caller checks that source with; DefaultDataDir is the data folder of a
// source that sets no data_dir. The managed status and verify views use it
// for the per-account Cowork lookup.
func LocalAuditStorePath(source string, raw []byte, options ObservabilityV8CompileOptions) (string, error) {
	compiled, err := ParseCompileObservabilityV8(source, raw, options)
	if err != nil {
		return "", err
	}
	auditDB, _, err := compiledLocalStores(compiled)
	return auditDB, err
}

func compiledLocalStores(compiled *ObservabilityV8CompiledConfig) (auditDB, judgeBodiesDB string, err error) {
	if compiled == nil || compiled.Plan == nil {
		return "", "", fmt.Errorf("canonical v8 compiler returned no effective plan")
	}
	snapshot := compiled.Plan.Snapshot()
	auditDB, judgeBodiesDB = strings.TrimSpace(snapshot.Local.Path), strings.TrimSpace(snapshot.Local.JudgeBodiesPath)
	if auditDB == "" || judgeBodiesDB == "" {
		return "", "", fmt.Errorf("canonical v8 local store paths are incomplete")
	}
	return snapshot.Local.Path, snapshot.Local.JudgeBodiesPath, nil
}

// readRuntimeSourceFile reads one config source, bounded by the v8 source
// size limit. The error wraps the underlying os error, so a missing file still
// satisfies errors.Is(err, fs.ErrNotExist).
func readRuntimeSourceFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: read v8 source %s: %w", path, err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(ObservabilityV8MaxSourceBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("config: read v8 source %s: %w", path, err)
	}
	if len(raw) > ObservabilityV8MaxSourceBytes {
		return nil, fmt.Errorf("config: v8 source exceeds the %d-byte limit", ObservabilityV8MaxSourceBytes)
	}
	return raw, nil
}
