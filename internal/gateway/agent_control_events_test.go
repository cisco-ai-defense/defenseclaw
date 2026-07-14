// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func agentControlEventTestConfig(dataDir string) *config.Config {
	return &config.Config{
		DataDir: dataDir,
		Privacy: config.PrivacyConfig{
			DisableRedaction: true,
		},
		AgentControl: config.AgentControlConfig{
			Enabled: true,
			Observability: config.AgentControlObservabilityConfig{
				Enabled:        true,
				IncludeContent: true,
			},
		},
	}
}

func TestNewAgentControlEventWriterCreatesPrivateSpool(t *testing.T) {
	dataDir := t.TempDir()
	writer, err := newAgentControlEventWriter(agentControlEventTestConfig(dataDir), nil)
	if err != nil {
		t.Fatal(err)
	}
	if writer == nil {
		t.Fatal("expected Agent Control event writer")
	}
	t.Cleanup(func() { _ = writer.Close() })

	path := filepath.Join(dataDir, "agent-control", agentControlRawEventLogName)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("private spool mode = %s, want regular 0600", info.Mode())
	}
	dirInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("private spool directory mode = %s, want directory 0700", dirInfo.Mode())
	}
}

func TestNewAgentControlEventWriterDisabledWithoutRawContent(t *testing.T) {
	cfg := agentControlEventTestConfig(t.TempDir())
	cfg.AgentControl.Observability.IncludeContent = false
	writer, err := newAgentControlEventWriter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if writer != nil {
		t.Fatal("writer must be disabled when include_content=false")
	}
}

func TestNewAgentControlEventWriterUsesStandardStreamWhenRedactionEnabled(t *testing.T) {
	cfg := agentControlEventTestConfig(t.TempDir())
	cfg.Privacy.DisableRedaction = false
	writer, err := newAgentControlEventWriter(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if writer != nil {
		t.Fatal("raw writer must be disabled while global redaction is enabled")
	}
}

func TestNewAgentControlEventWriterRejectsSymlinkDirectory(t *testing.T) {
	dataDir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dataDir, "agent-control")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	writer, err := newAgentControlEventWriter(agentControlEventTestConfig(dataDir), nil)
	if writer != nil {
		_ = writer.Close()
		t.Fatal("unexpected writer for symlinked private directory")
	}
	if err == nil {
		t.Fatal("expected symlink directory rejection")
	}
}

func TestNewAgentControlEventWriterRejectsHardLinkedSpool(t *testing.T) {
	dataDir := t.TempDir()
	privateDir := filepath.Join(dataDir, "agent-control")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(t.TempDir(), "original.jsonl")
	if err := os.WriteFile(original, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, filepath.Join(privateDir, agentControlRawEventLogName)); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	writer, err := newAgentControlEventWriter(agentControlEventTestConfig(dataDir), nil)
	if writer != nil {
		_ = writer.Close()
		t.Fatal("unexpected writer for hard-linked private spool")
	}
	if err == nil {
		t.Fatal("expected hard-linked spool rejection")
	}
}
