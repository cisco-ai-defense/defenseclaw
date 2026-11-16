// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestManagedRecoveryPreservesLiteralUnixDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX recovery command")
	}
	dataDir := filepath.Join(t.TempDir(), "person$group's `name`", "custom-acp")
	flags := managedSetupFlags("http://127.0.0.1:18970/api/v1/acp/evaluate", filepath.Join(dataDir, "acp", "zed-kiro.token"))
	cmd := exec.Command("sh", "-c", "set -- "+posixSetupArguments(flags)+`; printf '%s\n' "$@"`)
	cmd.Env = append(cmd.Environ(), "group=expanded")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "--api-port\n18970\n--data-dir\n" + dataDir + "\n"; string(out) != want {
		t.Fatalf("recovery arguments = %q, want %q (flags %s)", out, want, flags)
	}
	if strings.Contains(string(out), "expanded") {
		t.Fatal("recovery expanded the runtime path")
	}
}

// g072 review 2 M4: on Windows the managed setup is a PowerShell call from
// the managed renderer, the path and the data dir PowerShell literals with
// the typographic quotes doubled; the guard built `& "<path>" ...` in double
// quotes, which expand a $. Elsewhere the command keeps its shape.
func TestManagedSetupCommandLineQuotesForEachShell(t *testing.T) {
	args := []string{"enterprise", "acp", "setup", "--client", "zed", "--agent", "kiro", "--profile", "locked", "--activate",
		"--api-port", "18970", "--data-dir", "C:\\Users\\O\u2019Brien$x\\.dc"}
	gateway := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe`
	want := `& 'C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw.exe' enterprise acp setup --client zed --agent kiro --profile locked --activate ` +
		"--api-port 18970 --data-dir 'C:\\Users\\O\u2019\u2019Brien$x\\.dc'"
	if got := managedSetupCommandLine(true, gateway, args); got != want {
		t.Errorf("Windows setup = %s, want %s", got, want)
	}
	args[len(args)-1] = "/home/o'brien/.dc"
	if got, want := managedSetupCommandLine(false, "/opt/defenseclaw/bin/defenseclaw-gateway", args),
		"/opt/defenseclaw/bin/defenseclaw-gateway enterprise acp setup --client zed --agent kiro --profile locked --activate "+
			"--api-port 18970 --data-dir '/home/o'\\''brien/.dc'"; got != want {
		t.Errorf("POSIX setup = %s, want %s", got, want)
	}
}
