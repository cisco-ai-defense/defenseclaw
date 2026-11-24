//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// RV-T6B (GAP-0768): the push scripts also clear what in the relay's
// environment would move the repository's common dir or attributes, change
// the TLS client (certificate, key, ciphers, version, CA), the proxy auth
// method, or run a password prompt. Before, those reached git.
func TestGAP0768PushScriptsClearTLSRepoAndPromptVariables(t *testing.T) {
	set := []string{"GIT_COMMON_DIR=/tmp/elsewhere", "GIT_ATTR_SOURCE=HEAD~1", "GIT_SSL_CERT=/tmp/c.pem", "GIT_SSL_KEY=/tmp/k.pem",
		"GIT_SSL_CIPHER_LIST=NULL", "GIT_SSL_VERSION=tlsv1.0", "GIT_SSL_CAINFO=/tmp/ca.pem", "GIT_SSL_NO_VERIFY=1",
		"GIT_SSL_CERT_PASSWORD_PROTECTED=1", "GIT_HTTP_PROXY_AUTHMETHOD=basic", "GIT_ASKPASS=/bin/false", "SSH_ASKPASS=/bin/false"}
	cmd := exec.Command("sh", "-c", pushGit+"env")
	cmd.Env = append(os.Environ(), set...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			env[k] = v
		}
	}
	for _, kv := range set {
		k, _, _ := strings.Cut(kv, "=")
		if v, ok := env[k]; ok {
			t.Errorf("%s=%s reaches the push", k, v)
		}
	}
}
