// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kitspec

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// pinnedBaseEnv is the image environment of openshell.DefaultBaseImage
// (TestPinnedBaseEnvIsTheOpenShellRecord keeps the two the same).
var pinnedBaseEnv = map[string]string{
	"PATH":                    "/sandbox/.venv/bin:/usr/local/bin:/usr/bin:/bin",
	"DEBIAN_FRONTEND":         "noninteractive",
	"PYTHONDONTWRITEBYTECODE": "1",
	"PYTHONUNBUFFERED":        "1",
	"UV_PYTHON_INSTALL_DIR":   "/sandbox/.uv/python",
	"VIRTUAL_ENV":             "/sandbox/.venv",
}

// dockerfileEnv reads the ENV instructions of a Dockerfile (both forms:
// ENV K=V K2=V2, and ENV K V).
func dockerfileEnv(t *testing.T, df []byte) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(df))
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		rest, ok := strings.CutPrefix(l, "ENV ")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		if !strings.Contains(f[0], "=") {
			out[f[0]] = strings.TrimSpace(strings.TrimPrefix(rest, f[0]))
			continue
		}
		for _, kv := range f {
			k, v, _ := strings.Cut(kv, "=")
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out
}

// GAP-0447: the stock template of every connector builds. The image
// environment template build checks is the harness base image's own
// (pinnedBaseEnv), what the connector's harness stage adds
// (its Dockerfile's ENV) and the kit layer's; each must pass the actor
// environment allowlist, so a base image pin or a harness change cannot
// block every template build again.
func TestEveryConnectorsHarnessEnvironmentPassesTheAllowlist(t *testing.T) {
	for _, c := range kit.Connectors() {
		h, ok := harness.Get(c)
		if !ok {
			t.Fatalf("%s: no harness", c)
		}
		ictx, err := image.NewContext(image.BuildSpec{Harness: h, HarnessVersion: kit.HarnessRelease(c), UID: 1000, GID: 1000, IngressPort: 18970,
			DefenseClawVersion: "test", Owner: "0000000000000000"})
		if err != nil {
			t.Fatalf("%s: harness context: %v", c, err)
		}
		if ictx.Spec.BaseImage != openshell.DefaultBaseImage {
			t.Fatalf("%s: harness base %s is not DefaultBaseImage: record its environment and check it here", c, ictx.Spec.BaseImage)
		}
		env := map[string]string{}
		for k, v := range pinnedBaseEnv {
			env[k] = v
		}
		for k, v := range dockerfileEnv(t, ictx.Dockerfile) {
			env[k] = v
		}
		spec, _, err := Spec(Options{Connector: c, KitVersion: "test", HookBinary: []byte("x"), RelayBinary: []byte("x"), MetadataOnly: true})
		if err != nil {
			t.Fatalf("%s: kit spec: %v", c, err)
		}
		for k, v := range spec.Env {
			env[k] = v
		}
		if bad := attest.CheckEnv(env); len(bad) > 0 {
			t.Errorf("%s: the stock template's environment fails the allowlist: %s", c, attest.FormatEnvRefusals(bad))
		}
		// The base image's own settings alone pass too (a template built
		// --from the harness base before the kit layer).
		if bad := attest.CheckEnv(pinnedBaseEnv); len(bad) > 0 {
			t.Errorf("the harness base environment fails the allowlist: %s", attest.FormatEnvRefusals(bad))
		}
	}
}
