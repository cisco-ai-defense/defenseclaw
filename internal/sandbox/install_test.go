package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckVersionCompatibility(t *testing.T) {
	tests := []struct {
		installed string
		required  string
		wantErr   bool
	}{
		{"0.6.2", "0.6.2", false},
		{"v0.6.2", "0.6.2", false},
		{"0.6.2", "v0.6.2", false},
		{"0.6.1", "0.6.2", true},
		{"0.7.0", "0.6.2", true},
		{"", "0.6.2", true},
	}
	for _, tt := range tests {
		t.Run(tt.installed+"_vs_"+tt.required, func(t *testing.T) {
			err := CheckVersionCompatibility(tt.installed, tt.required)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckVersionCompatibility(%q, %q) error = %v, wantErr %v",
					tt.installed, tt.required, err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOpenShellBinary_NotFound(t *testing.T) {
	_, err := VerifyOpenShellBinary("/nonexistent/openshell-sandbox")
	if err == nil {
		t.Error("expected error for nonexistent binary")
	}
}

func TestVerifyOpenShellBinary_HappyPath(t *testing.T) {
	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "openshell-sandbox")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho \"openshell-sandbox v0.6.2\""), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}

	version, err := VerifyOpenShellBinary(bin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "0.6.2" {
		t.Errorf("got version %q, want %q", version, "0.6.2")
	}
}

func TestVerifyOpenShellBinary_Directory(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := VerifyOpenShellBinary(tmpDir)
	if err == nil {
		t.Fatal("expected error for directory path")
	}
	if !strings.Contains(err.Error(), "is a directory") {
		t.Errorf("error %q should contain %q", err.Error(), "is a directory")
	}
}

func TestVerifyOpenShellBinary_VersionVariants(t *testing.T) {
	tests := []struct {
		name    string
		output  string
		wantVer string
	}{
		{"bare_version", "0.7.0", "0.7.0"},
		{"no_v_prefix", "openshell-sandbox 0.7.0", "0.7.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			bin := filepath.Join(tmpDir, "openshell-sandbox")
			script := "#!/bin/sh\necho \"" + tt.output + "\""
			if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
				t.Fatal(err)
			}

			version, err := VerifyOpenShellBinary(bin)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if version != tt.wantVer {
				t.Errorf("got version %q, want %q", version, tt.wantVer)
			}
		})
	}
}
