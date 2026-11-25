// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package harness

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The launcher tests (launcher_test.go) run the sandbox image's POSIX shell
// launchers on the host, so they skip on native Windows, where OpenShell
// sandboxes are not supported at all (rel-1-0-10:GAP-1682, accepted by
// design). This is their Windows twin: on native Windows every harness
// refuses to render sandbox artifacts and the platform gate refuses the
// host, so no launcher is ever written there; on Linux and macOS every
// harness renders. A Windows that rendered artifacts, or a POSIX host that
// stopped rendering them, fails here.
func TestSandboxArtifactsRefusedOnlyOnWindows(t *testing.T) {
	names := Names()
	if len(names) == 0 {
		t.Fatal("no harness is registered")
	}
	for _, name := range names {
		spec, ok := Get(name)
		if !ok {
			t.Fatalf("Names() lists %q but Get does not find it", name)
		}
		_, err := spec.Provider.SandboxArtifacts(connector.SandboxRenderTarget{IngressPort: 18971, AgentVersion: spec.DefaultVersion})
		if runtime.GOOS == "windows" {
			if err == nil || !strings.Contains(err.Error(), "cannot be rendered on Windows") {
				t.Errorf("%s: sandbox artifacts on native Windows: err=%v, want the Windows refusal", name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: sandbox artifacts on %s: %v", name, runtime.GOOS, err)
		}
	}
	err := openshell.CheckPlatform(runtime.GOOS)
	if runtime.GOOS == "windows" {
		if !errors.Is(err, openshell.ErrUnsupportedPlatform) {
			t.Fatalf("CheckPlatform(windows) = %v, want ErrUnsupportedPlatform", err)
		}
	} else if err != nil {
		t.Fatalf("CheckPlatform(%s) = %v", runtime.GOOS, err)
	}
}
