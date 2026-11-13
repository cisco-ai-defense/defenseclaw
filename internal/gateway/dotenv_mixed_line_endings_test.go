package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A .env an older writer left half CRLF and half LF leaves every gateway
// writer with one ending, and the other keys and the token survive.
func TestGatewayDotEnvWritersNormalizeAMixedFileToOneEnding(t *testing.T) {
	const mixed = "DEFENSECLAW_LLM_KEY=keep\r\nDEFENSECLAW_GATEWAY_TOKEN=old-token\n# note\r\n"
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, dir string)
		want  []string
	}{
		{"OpenClaw token refresh", func(t *testing.T, dir string) {
			if err := saveOpenClawToken(t, dir, "new-token"); err != nil {
				t.Fatal(err)
			}
		}, []string{"DEFENSECLAW_LLM_KEY=keep", "DEFENSECLAW_GATEWAY_TOKEN=old-token", "# note", "OPENCLAW_GATEWAY_TOKEN=new-token"}},
		{"first boot append", func(t *testing.T, dir string) {
			if err := appendEnvLine(filepath.Join(dir, ".env"), "DEFENSECLAW_GATEWAY_TOKEN", "boot-token"); err != nil {
				t.Fatal(err)
			}
		}, []string{"DEFENSECLAW_LLM_KEY=keep", "# note", "DEFENSECLAW_GATEWAY_TOKEN=boot-token"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			if err := os.WriteFile(path, []byte(mixed), 0o600); err != nil {
				t.Fatal(err)
			}
			tc.write(t, dir)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(body)
			if strings.Contains(text, "\r") || !strings.HasSuffix(text, "\n") {
				t.Fatalf("not one LF ending: %q", text)
			}
			for _, want := range tc.want {
				if !strings.Contains("\n"+text, "\n"+want+"\n") {
					t.Fatalf("line %q missing from %q", want, text)
				}
			}
		})
	}
}

// A benign twin: a file that is CRLF throughout stays CRLF throughout.
func TestGatewayDotEnvWritersKeepAnEntirelyCRLFFileCRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	if err := os.WriteFile(path, []byte("DEFENSECLAW_LLM_KEY=keep\r\n# note\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := appendEnvLine(path, "DEFENSECLAW_GATEWAY_TOKEN", "boot-token"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := "DEFENSECLAW_LLM_KEY=keep\r\n# note\r\nDEFENSECLAW_GATEWAY_TOKEN=boot-token\r\n"; string(body) != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
}
