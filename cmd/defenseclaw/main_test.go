// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/nativeinstallstate"
)

func TestNativeGatewayProcessEnvironmentUsesAuthenticatedGeminiHome(t *testing.T) {
	root := t.TempDir()
	geminiCLIHome := filepath.Join(root, "profile")
	geminiHome := filepath.Join(geminiCLIHome, ".gemini")
	previous := loadNativeInstallState
	loadNativeInstallState = func(executable string) (nativeinstallstate.State, bool, error) {
		if executable != filepath.Join(root, "bin", "defenseclaw-gateway.exe") {
			t.Fatalf("native state executable = %q", executable)
		}
		return nativeinstallstate.State{
			InstallRoot:     root,
			DataRoot:        filepath.Join(root, "data"),
			GeminiCLIHome:   geminiCLIHome,
			GeminiConfigDir: geminiHome,
		}, true, nil
	}
	t.Cleanup(func() { loadNativeInstallState = previous })

	environment, packaged, err := nativeGatewayProcessEnvironment(
		filepath.Join(root, "bin", "defenseclaw-gateway.exe"),
		[]string{
			"HOME=" + filepath.Join(root, "hostile-home"),
			"USERPROFILE=" + filepath.Join(root, "hostile-profile"),
			"GEMINI_CLI_HOME=" + filepath.Join(root, "hostile-vendor-root"),
			"GEMINI_CONFIG_DIR=" + filepath.Join(root, "hostile-vendor-home"),
			"DEFENSECLAW_GEMINI_CONFIG_HOME=" + filepath.Join(root, "hostile-internal-home"),
		},
	)
	if err != nil || !packaged {
		t.Fatalf("native gateway environment packaged=%t err=%v", packaged, err)
	}
	joined := strings.Join(environment, "\n")
	if !strings.Contains(joined, "DEFENSECLAW_GEMINI_CONFIG_HOME="+geminiHome) {
		t.Fatalf("authenticated Gemini home missing: %v", environment)
	}
	if !strings.Contains(joined, "GEMINI_CLI_HOME="+geminiCLIHome) {
		t.Fatalf("authenticated Gemini CLI root missing: %v", environment)
	}
	for _, forbidden := range []string{"hostile-vendor-root", "hostile-vendor-home", "hostile-internal-home"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("hostile Gemini binding survived native gateway bootstrap: %v", environment)
		}
	}
}

func TestReleaseCommandNameForPathRecognizesOnlyCLIReleaseName(t *testing.T) {
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "defenseclaw.exe", want: "defenseclaw"},
		{path: "DEFENSECLAW.EXE", want: "defenseclaw"},
		{path: "defenseclaw", want: "defenseclaw"},
		{path: "defenseclaw-gateway.exe"},
		{path: "renamed-by-user.exe"},
	} {
		if got := releaseCommandNameForPath(test.path); got != test.want {
			t.Fatalf("releaseCommandNameForPath(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}
