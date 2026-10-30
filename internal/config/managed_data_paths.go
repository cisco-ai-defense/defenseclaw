// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// ManagedDataPaths returns the gateway's managed data objects for this
// configuration: data_dir, the audit database, the judge-body store and the
// redaction correlation key, with the same defaults the gateway applies.
// Log files are not included: each service has its own log with its own
// descriptor, so the caller adds the gateway log path itself.
func (c *Config) ManagedDataPaths() managed.ManagedDataPaths {
	if c == nil {
		return managed.ManagedDataPaths{}
	}
	dataDir := strings.TrimSpace(c.DataDir)
	paths := managed.ManagedDataPaths{DataDir: dataDir}
	if dataDir == "" {
		return paths
	}
	paths.AuditDBPath = strings.TrimSpace(c.AuditDB)
	if paths.AuditDBPath == "" {
		paths.AuditDBPath = filepath.Join(dataDir, DefaultAuditDBName)
	}
	paths.JudgeBodyDBPath = strings.TrimSpace(c.JudgeBodiesDB)
	if paths.JudgeBodyDBPath == "" {
		paths.JudgeBodyDBPath = filepath.Join(dataDir, DefaultJudgeBodiesDBName)
	}
	paths.RedactionKeyPath = redaction.CorrelationKeyPath(dataDir)
	return paths
}
