// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// A log that cannot be opened must not stop the helper: the gateway service
// depends on it, so refusing to start would take managed hooks down too.
func TestNewHelperLoggerKeepsRunningWhenServiceLogIsUnusable(t *testing.T) {
	var fallback bytes.Buffer
	logger, closeLog := newHelperLogger("relative\\sensor-helper.log", &fallback)
	defer closeLog()
	logger.Error("sensor helper exited", "error", "listen failed")
	output := fallback.String()
	if !strings.Contains(output, "sensor helper log is unavailable") ||
		!strings.Contains(output, "sensor helper exited") {
		t.Fatalf("fallback did not report the unusable log and later lines: %q", output)
	}
	// Without a service log the fallback gets the lines directly.
	fallback.Reset()
	logger, closeFallback := newHelperLogger("", &fallback)
	defer closeFallback()
	logger.Info("sensor helper listening")
	if !strings.Contains(fallback.String(), "sensor helper listening") {
		t.Fatalf("fallback did not receive the log line: %q", fallback.String())
	}
}

func TestNewHelperLoggerAppendsToServiceLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The Windows opener additionally requires an administrator-only
		// directory, which a test temp directory is not.
		t.Skip("covered by the Windows trusted-directory contract")
	}
	path := filepath.Join(t.TempDir(), "sensor-helper.log")
	if err := os.WriteFile(path, []byte("earlier run\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fallback bytes.Buffer
	logger, closeLog := newHelperLogger(path, &fallback)
	logger.Error("sensor helper exited", "error", "listen failed")
	closeLog()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "earlier run\n") ||
		!strings.Contains(string(data), "sensor helper exited") {
		t.Fatalf("service log was not appended: %q", data)
	}
	if fallback.Len() != 0 {
		t.Fatalf("fallback received output while the service log was usable: %q", fallback.String())
	}
}

func TestOpenHelperLogRejectsNoncanonicalPaths(t *testing.T) {
	sep := string(filepath.Separator)
	unclean := t.TempDir() + sep + "x" + sep + ".." + sep + "sensor-helper.log"
	for _, path := range []string{"", "sensor-helper.log", unclean} {
		if file, err := openHelperLog(path); err == nil {
			_ = file.Close()
			t.Fatalf("openHelperLog(%q) accepted a noncanonical path", path)
		}
	}
}
