package scanner

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestMCPScanRefusesProfilePathBeforeStartingChild(t *testing.T) {
	refused := errors.New("the managed gateway runs as LocalSystem and does not read inside user profiles; scan the folder as the signed-in user (defenseclaw ... from the user session) or move it outside the profile")
	previousGuard, previousRun := requireScannerTargetPath, runMCPScannerCommand
	childStarted := false
	requireScannerTargetPath = func(path string) error {
		if path != `C:\Users\sample\project\.mcp.json` {
			t.Fatalf("guarded path = %q", path)
		}
		return refused
	}
	runMCPScannerCommand = func(*exec.Cmd) error {
		childStarted = true
		return nil
	}
	t.Cleanup(func() {
		requireScannerTargetPath, runMCPScannerCommand = previousGuard, previousRun
	})
	scan := &MCPScanner{}
	if _, err := scan.Scan(context.Background(), `C:\Users\sample\project\.mcp.json`); !errors.Is(err, refused) {
		t.Fatalf("MCP scan error = %v, want profile refusal", err)
	}
	if childStarted {
		t.Fatal("MCP scanner child started for a profile path")
	}
	project := `C:\Users\sample\project`
	requireScannerTargetPath = func(path string) error {
		if path != project {
			t.Fatalf("guarded project path = %q", path)
		}
		return refused
	}
	scan.Project = project
	if _, err := scan.Scan(context.Background(), "local-server"); !errors.Is(err, refused) {
		t.Fatalf("MCP project scan error = %v, want profile refusal", err)
	}
	if childStarted {
		t.Fatal("MCP scanner child started from a profile project")
	}
}
