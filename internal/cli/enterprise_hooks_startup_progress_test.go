// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type startupRecordWrites struct {
	paths   []string
	records []enterpriseHookGuardianStartup
	err     error
}

func (w *startupRecordWrites) write(path string, data []byte) error {
	if w.err != nil {
		return w.err
	}
	var record enterpriseHookGuardianStartup
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	w.paths = append(w.paths, path)
	w.records = append(w.records, record)
	return nil
}

func useStartupRecordWrites(t *testing.T, enabled bool) *startupRecordWrites {
	t.Helper()
	writes := &startupRecordWrites{}
	saved := enterpriseHookStartup
	clock := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	enterpriseHookStartup = &enterpriseHookStartupProgress{
		enabled: func() bool { return enabled },
		write:   writes.write,
		now: func() time.Time {
			clock = clock.Add(time.Second)
			return clock
		},
	}
	t.Cleanup(func() { enterpriseHookStartup = saved })
	return writes
}

// GAP-0401: the guardian records its startup reconcile as it moves through
// the targets, and that it finished, so Setup can wait for a long first
// reconcile and not for a stuck or dead guardian.
func TestEnterpriseHookStartupProgressRecordsTheFirstReconcile(t *testing.T) {
	writes := useStartupRecordWrites(t, true)
	dataDir := t.TempDir()
	var log bytes.Buffer

	enterpriseHookStartup.target(&log, 0, 10) // before begin: nothing
	enterpriseHookStartup.begin(&log, dataDir)
	for done := range 3 {
		enterpriseHookStartup.target(&log, done, 10)
	}
	enterpriseHookStartup.end(&log)
	enterpriseHookStartup.target(&log, 0, 10) // a later pass: nothing
	enterpriseHookStartup.end(&log)

	if len(writes.records) != 5 {
		t.Fatalf("wrote %d records, want begin, 3 targets and end: %+v", len(writes.records), writes.records)
	}
	want := filepath.Join(dataDir, hookGuardianStartupFile)
	for i, path := range writes.paths {
		if path != want {
			t.Fatalf("record %d written to %s, want %s", i, path, want)
		}
	}
	first, last := writes.records[0], writes.records[4]
	if first.Version != 1 || first.PID != os.Getpid() || first.State != hookGuardianStartupReconciling ||
		first.StartedAt == "" || first.StartedAt != first.UpdatedAt || first.TargetsTotal != 0 {
		t.Fatalf("begin record = %+v", first)
	}
	if got := writes.records[3]; got.State != hookGuardianStartupReconciling || got.TargetsDone != 2 ||
		got.TargetsTotal != 10 || got.StartedAt != first.StartedAt || got.UpdatedAt <= writes.records[2].UpdatedAt {
		t.Fatalf("target record = %+v after %+v", got, writes.records[2])
	}
	if last.State != hookGuardianStartupFinished || last.StartedAt != first.StartedAt || last.PID != first.PID {
		t.Fatalf("end record = %+v", last)
	}
	if log.Len() != 0 {
		t.Fatalf("log = %q", log.String())
	}
}

func TestEnterpriseHookStartupProgressWritesNothingWhenDisabled(t *testing.T) {
	writes := useStartupRecordWrites(t, false)
	enterpriseHookStartup.begin(io.Discard, t.TempDir())
	enterpriseHookStartup.target(io.Discard, 0, 1)
	enterpriseHookStartup.end(io.Discard)
	if len(writes.records) != 0 {
		t.Fatalf("a disabled tracker wrote %+v", writes.records)
	}
}

// A record that cannot be written is logged once; the reconcile goes on.
func TestEnterpriseHookStartupProgressLogsAFailedWriteOnce(t *testing.T) {
	writes := useStartupRecordWrites(t, true)
	writes.err = errors.New("access is denied")
	var log bytes.Buffer
	enterpriseHookStartup.begin(&log, t.TempDir())
	enterpriseHookStartup.target(&log, 0, 2)
	enterpriseHookStartup.end(&log)
	if got := strings.Count(log.String(), "could not write the startup record"); got != 1 {
		t.Fatalf("logged the failed write %d times: %q", got, log.String())
	}
}

// The watch loop brackets its startup reconcile with the record, also when
// that reconcile fails (here on a missing manifest).
func TestEnterpriseHooksWatchRecordsItsStartupReconcile(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	previousManifest := enterpriseHookManifest
	t.Cleanup(func() { enterpriseHookManifest = previousManifest })
	writes := useStartupRecordWrites(t, true)
	dataDir := t.TempDir()
	cfg = &config.Config{DeploymentMode: "local", DataDir: dataDir}
	enterpriseHookManifest = filepath.Join(t.TempDir(), "targets.yaml")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetErr(io.Discard)
	if err := runEnterpriseHooksWatch(cmd, nil); err == nil {
		t.Fatal("watch without a manifest returned no error")
	}
	if len(writes.records) != 2 || writes.records[0].State != hookGuardianStartupReconciling ||
		writes.records[1].State != hookGuardianStartupFinished {
		t.Fatalf("startup records = %+v, want reconciling then finished", writes.records)
	}
	if writes.paths[0] != filepath.Join(dataDir, hookGuardianStartupFile) {
		t.Fatalf("record path = %s", writes.paths[0])
	}
}
