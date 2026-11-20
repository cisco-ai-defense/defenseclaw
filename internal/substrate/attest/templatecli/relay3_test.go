// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package templatecli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0354: `template publish --env` applies admission's allowlist, so it
// never creates a template the controller refuses: an unexpected variable,
// or a kit variable with another value, stops it, naming the variable and
// not its value; the kit's variables and ordinary settings pass.
func TestPublishEnvFollowsTheAdmissionAllowlist(t *testing.T) {
	for _, c := range []struct{ kv, want string }{
		{"LD_PRELOAD=/tmp/x-secret.so", "LD_PRELOAD (not on the allowlist)"},
		{"GIT_CONFIG_COUNT=1", "GIT_CONFIG_COUNT (not on the allowlist)"},
		{"PERLLIB=/tmp/x-secret", "PERLLIB (not on the allowlist)"},
		{"SSL_CERT_FILE=/tmp/x-secret.pem", `SSL_CERT_FILE (the kit sets it to "` + kit.TrustBundle + `" only)`},
	} {
		code, out, errText := publish(t, "--template", "team/kit", "--env", c.kv)
		if code != ExitUsageError || !strings.Contains(errText, c.want) || !strings.Contains(errText, "admission refuses") {
			t.Errorf("--env %s: exit %d: %s", c.kv, code, errText)
		}
		if strings.Contains(out+errText, "x-secret") {
			t.Errorf("--env %s: the value is printed: %s%s", c.kv, out, errText)
		}
	}
	env, err := parseEnv([]string{"LANG=C.UTF-8", "SSL_CERT_FILE=" + kit.TrustBundle, "DISABLE_TELEMETRY=1", "NODE_VERSION=22.1.0",
		"ANTHROPIC_API_KEY=" + kit.PlaceholderSecret})
	if err != nil || len(env) != 5 {
		t.Fatalf("the kit's variables: %v %v", env, err)
	}
}
