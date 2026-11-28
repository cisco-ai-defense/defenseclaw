//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package workspace

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// RV-T6A (GAP-0768): the push scripts run no command and change no
// transport through what the relay's environment carries: the ssh, proxy
// and exec-path variables and every trace are unset, and https is the only
// protocol. Before, they reached git from the relay's environment.
func TestGAP0768PushScriptsClearTheGitEnvironment(t *testing.T) {
	cmd := exec.Command("sh", "-c", pushGit+"env")
	cmd.Env = append(os.Environ(), "GIT_SSH=/bin/false", "GIT_SSH_COMMAND=false", "GIT_SSH_VARIANT=ssh", "GIT_PROXY_COMMAND=false",
		"GIT_EXEC_PATH=/nonexistent", "GIT_TRACE=1", "GIT_TRACE_CURL=1", "GIT_TRACE2_EVENT=/tmp/t", "GIT_TRACE_PACKET=1",
		"GIT_CURL_VERBOSE=1", "GIT_ALLOW_PROTOCOL=ext:file:ssh", "GIT_PROTOCOL_FROM_USER=1")
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
	for _, k := range []string{"GIT_SSH", "GIT_SSH_COMMAND", "GIT_SSH_VARIANT", "GIT_PROXY_COMMAND", "GIT_EXEC_PATH", "GIT_TRACE", "GIT_TRACE_CURL", "GIT_TRACE2_EVENT", "GIT_TRACE_PACKET", "GIT_CURL_VERBOSE", "GIT_PROTOCOL_FROM_USER"} {
		if v, ok := env[k]; ok {
			t.Errorf("%s=%s reaches the push", k, v)
		}
	}
	if env["GIT_ALLOW_PROTOCOL"] != "https" {
		t.Errorf("GIT_ALLOW_PROTOCOL=%q, want https", env["GIT_ALLOW_PROTOCOL"])
	}
}

// RV-T6A (GAP-0768): a credential helper in the agent's repository, user
// or XDG config never reaches the push; only the kit's helper is set.
func TestGAP0768PushUsesOnlyTheKitCredentialHelper(t *testing.T) {
	s := rv4Setup(t)
	home := filepath.Join(s.tmp, "home")
	gitT(t, s.repo, "config", "credential.helper", "!echo password=agent-repo")
	gap0768File(t, filepath.Join(home, ".gitconfig"), "[credential]\n\thelper = !echo password=agent-user\n")
	gap0768File(t, filepath.Join(home, ".config", "git", "config"), "[credential]\n\thelper = !echo password=agent-xdg\n")
	cmd := exec.Command("sh", "-c", pushGit+`t=$(mktemp -d) && git init -q --bare --template= "$t/g" && export GIT_DIR=$t/g && g config --get-all credential.helper; rm -rf "$t"`)
	cmd.Dir = s.repo
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, ".config"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != kit.CredHelper {
		t.Fatalf("the push's credential helpers: %q, want only %q", got, kit.CredHelper)
	}
}

// RV-T6A (GAP-0768): which record names the origin when this computer has
// a run --clone record and an upload record for the same name: the newer,
// and a clone record with no time loses to a timed upload (and wins over
// an upload with none).
func TestGAP0768RecordedOriginOrderWithoutTimes(t *testing.T) {
	data := t.TempDir()
	at := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		clone      time.Time
		uploadedAt string
		want       string
	}{
		{"clone untimed, upload timed", time.Time{}, `,"uploaded_at":"2026-11-20T00:00:00Z"`, gap0768Origin},
		{"clone timed, upload untimed", at, ``, "https://git.example.test/team/cl.git"},
		{"clone newer", at.Add(time.Hour), `,"uploaded_at":"2026-11-20T00:00:00Z"`, "https://git.example.test/team/cl.git"},
		{"upload newer", at.Add(-time.Hour), `,"uploaded_at":"2026-11-20T00:00:00Z"`, gap0768Origin},
	} {
		name := strings.ReplaceAll(strings.ReplaceAll(tc.name, ",", ""), " ", "-")
		gap0768File(t, filepath.Join(data, "sandboxes", name, "copy", "copy.json"),
			`{"version":1,"name":"`+name+`","remotes":{"origin":"`+gap0768Origin+`"}`+tc.uploadedAt+`}`)
		rec := &hostRecord{Version: hostRecordVersion, Name: name, CloneURL: "https://git.example.test/team/cl.git", UploadedAt: tc.clone}
		if err := rec.save(data); err != nil {
			t.Fatal(err)
		}
		if up, err := osw.LoadCopy(data, name); err != nil || up == nil {
			t.Fatalf("%s: upload record: %v", tc.name, err)
		}
		if got := RecordedOrigin(data, name); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
