// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// windowsCommandLineGolden is the file cli/tests/test_powershell_quote_golden.py
// reads to check that winquote.powershell_command_line renders the same line
// as WindowsCommandLine (g072 review 3 M2): the Python CLI prints the managed
// Windows ACP setup command the Go CLI prints.
var windowsCommandLineGolden = filepath.Join("..", "..", "testdata", "powershell_quotes", "command_lines.json")

type windowsCommandLineGoldenRow struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	Line       string   `json:"line"`
}

// TestWindowsCommandLineMatchesThePythonGolden renders the golden rows and
// compares them with the checked-in file; DEFENSECLAW_UPDATE_GOLDEN=1
// rewrites it.
func TestWindowsCommandLineMatchesThePythonGolden(t *testing.T) {
	gateway := `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`
	var rows []windowsCommandLineGoldenRow
	for _, quote := range []string{"'", "\u2018", "\u2019", "\u201a", "\u201b"} {
		profile := `C:\Users\O` + quote + `Brien`
		rows = append(rows, windowsCommandLineGoldenRow{Executable: gateway, Args: []string{
			"enterprise", "acp", "setup", "--client", "zed", "--agent", "kiro", "--profile", "default", "--activate",
			"--data-dir", profile + `\AppData\Local\DefenseClaw\acp`, "--api-port", "18970",
			"--guard-binary", `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-acp.exe`,
		}})
		rows = append(rows, windowsCommandLineGoldenRow{Executable: profile + `\bin\defenseclaw.exe`, Args: []string{"status"}})
	}
	rows = append(rows,
		windowsCommandLineGoldenRow{Executable: gateway, Args: []string{"enterprise", "windows", "status", "<account>", "<path to scan>", "", "John Smith", "svc$", "a`b", "<a'b>", "x=1", "--opt=v:1/2+3"}},
		windowsCommandLineGoldenRow{Executable: "defenseclaw-gateway", Args: []string{"enterprise", "acp", "setup"}},
	)
	for i := range rows {
		rows[i].Line = WindowsCommandLine(rows[i].Executable, rows[i].Args...)
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"about": "Written by TestWindowsCommandLineMatchesThePythonGolden (internal/managed); " +
			"read by cli/tests/test_powershell_quote_golden.py. Regenerate with DEFENSECLAW_UPDATE_GOLDEN=1.",
		"rows": rows,
	}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(windowsCommandLineGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(windowsCommandLineGolden, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(windowsCommandLineGolden)
	if err != nil {
		t.Fatalf("missing golden (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n")), buf.Bytes()) {
		t.Fatalf("%s drifted from WindowsCommandLine (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1, then run the Python test):\n--- want\n%s\n--- got\n%s", windowsCommandLineGolden, want, buf.Bytes())
	}
}
