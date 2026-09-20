// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type recordingObservabilityBootstrapper struct {
	called bool
	source string
	raw    []byte
	bound  bool
	err    error
}

func (r *recordingObservabilityBootstrapper) BootstrapObservabilityRuntime(
	_ context.Context,
	source string,
	raw []byte,
) (bool, error) {
	r.called = true
	r.source = source
	r.raw = append([]byte(nil), raw...)
	return r.bound, r.err
}

func TestPrepareObservabilityV8StartupCompilesAndProjectsLocalPaths(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	auditPath := filepath.Join(directory, "custom-audit.db")
	judgePath := filepath.Join(directory, "custom-judge.db")
	raw := "config_version: 8\n" +
		"data_dir: " + directory + "\n" +
		"observability:\n" +
		"  local:\n" +
		"    path: " + auditPath + "\n" +
		"    judge_bodies_path: " + judgePath + "\n"
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &config.Config{
		ConfigVersion:  8,
		ConfigFilePath: configPath,
		DataDir:        directory,
		AuditDB:        "previous-audit.db",
		JudgeBodiesDB:  "previous-judge.db",
	}

	startup, err := prepareObservabilityV8Startup(c)
	if err != nil {
		t.Fatal(err)
	}
	if startup.sourceName != configPath || string(startup.raw) != raw {
		t.Fatalf("startup source = %q / %q", startup.sourceName, startup.raw)
	}
	if c.DataDir != directory || c.AuditDB != auditPath || c.JudgeBodiesDB != judgePath {
		t.Fatalf("projected paths = data=%q audit=%q judge=%q", c.DataDir, c.AuditDB, c.JudgeBodiesDB)
	}
}

func TestGatewayV8LoaderStrictParsesBeforeCanonicalActivation(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	raw := "config_version: 8\n" +
		"data_dir: " + directory + "\n" +
		"observability:\n" +
		"  destinations:\n" +
		"    - name: collector\n" +
		"      kind: otlp\n" +
		"      endpoint: https://collector.example.test\n"
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, startup, err := loadGatewayConfigV8(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ConfigVersion != 8 || loaded.ConfigFilePath != configPath {
		t.Fatalf("loaded config version/source = %d/%q", loaded.ConfigVersion, loaded.ConfigFilePath)
	}
	if startup == nil || loaded.AuditDB != filepath.Join(directory, config.DefaultAuditDBName) {
		t.Fatalf("activation startup/path = %+v/%q", startup, loaded.AuditDB)
	}
}

func TestGatewayV8LoaderRebasesOmittedPathsOnCompilerDefaultDataDir(t *testing.T) {
	defaultDataDir := filepath.Join(t.TempDir(), "runtime-state")
	t.Setenv("DEFENSECLAW_HOME", defaultDataDir)
	configDirectory := t.TempDir()
	configPath := filepath.Join(configDirectory, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, _, err := loadGatewayConfigV8(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for path, got := range map[string]string{
		"data_dir":                loaded.DataDir,
		"quarantine_dir":          loaded.QuarantineDir,
		"firewall.config_file":    loaded.Firewall.ConfigFile,
		"guardrail.rule_pack_dir": loaded.Guardrail.RulePackDir,
		"gateway.device_key_file": loaded.Gateway.DeviceKeyFile,
	} {
		if !strings.HasPrefix(got, defaultDataDir+string(filepath.Separator)) && !(path == "data_dir" && got == defaultDataDir) {
			t.Errorf("%s = %q, want path under compiler data_dir %q", path, got, defaultDataDir)
		}
	}
}

func TestGatewayV8LoaderRejectsV7AtStrictEntryPoint(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	raw := "config_version: 7\n" +
		"data_dir: " + directory + "\n" +
		"otel:\n  enabled: true\n"
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, startup, err := loadGatewayConfigV8(configPath)
	if err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("v7 strict startup error = %v", err)
	}
	if loaded != nil || startup != nil {
		t.Fatalf("v7 startup returned config/runtime = %+v/%+v", loaded, startup)
	}
}

func TestPrepareObservabilityV8StartupRejectsInvalidSourceWithoutMutatingPaths(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability:\n  destinationz: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &config.Config{
		ConfigVersion:  8,
		ConfigFilePath: configPath,
		DataDir:        directory,
		AuditDB:        "original-audit.db",
		JudgeBodiesDB:  "original-judge.db",
	}

	_, err := prepareObservabilityV8Startup(c)
	if err == nil || !strings.Contains(err.Error(), "destinationz") {
		t.Fatalf("invalid v8 error = %v", err)
	}
	if c.AuditDB != "original-audit.db" || c.JudgeBodiesDB != "original-judge.db" {
		t.Fatalf("failed compilation mutated paths: audit=%q judge=%q", c.AuditDB, c.JudgeBodiesDB)
	}
}

func TestBootstrapConfiguredObservabilityRuntimeRejectsV7(t *testing.T) {
	recorder := &recordingObservabilityBootstrapper{bound: true}
	err := bootstrapConfiguredObservabilityRuntime(
		context.Background(),
		&config.Config{ConfigVersion: 7},
		nil,
		recorder,
	)
	if err == nil || !strings.Contains(err.Error(), "upgrade") {
		t.Fatalf("v7 bootstrap error = %v", err)
	}
	if recorder.called {
		t.Fatal("v7 startup invoked the v8 runtime bootstrap")
	}
}

func TestBootstrapConfiguredObservabilityRuntimeBindsValidatedV8Source(t *testing.T) {
	recorder := &recordingObservabilityBootstrapper{bound: true}
	startup := &observabilityV8Startup{sourceName: "/tmp/config.yaml", raw: []byte("config_version: 8\n")}
	if err := bootstrapConfiguredObservabilityRuntime(
		context.Background(),
		&config.Config{ConfigVersion: 8},
		startup,
		recorder,
	); err != nil {
		t.Fatal(err)
	}
	if !recorder.called || recorder.source != startup.sourceName || string(recorder.raw) != string(startup.raw) {
		t.Fatalf("bootstrap call = called=%v source=%q raw=%q", recorder.called, recorder.source, recorder.raw)
	}
}

func TestBootstrapConfiguredObservabilityRuntimeFailsClosed(t *testing.T) {
	v8 := &config.Config{ConfigVersion: 8}
	t.Run("missing validated source", func(t *testing.T) {
		recorder := &recordingObservabilityBootstrapper{bound: true}
		err := bootstrapConfiguredObservabilityRuntime(context.Background(), v8, nil, recorder)
		if err == nil || recorder.called {
			t.Fatalf("missing state error/call = %v/%v", err, recorder.called)
		}
	})
	t.Run("bootstrap no-op", func(t *testing.T) {
		recorder := &recordingObservabilityBootstrapper{bound: false}
		err := bootstrapConfiguredObservabilityRuntime(
			context.Background(), v8,
			&observabilityV8Startup{sourceName: "config.yaml", raw: []byte("config_version: 8\n")},
			recorder,
		)
		if err == nil || !strings.Contains(err.Error(), "did not bind") {
			t.Fatalf("no-op bootstrap error = %v", err)
		}
	})
	t.Run("bootstrap failure", func(t *testing.T) {
		want := errors.New("construction failed")
		recorder := &recordingObservabilityBootstrapper{err: want}
		err := bootstrapConfiguredObservabilityRuntime(
			context.Background(), v8,
			&observabilityV8Startup{sourceName: "config.yaml", raw: []byte("config_version: 8\n")},
			recorder,
		)
		if !errors.Is(err, want) {
			t.Fatalf("bootstrap error = %v, want wrapped sentinel", err)
		}
	})
}
