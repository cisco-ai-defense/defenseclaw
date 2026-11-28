// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/http"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/attach"
)

// B3.1: --key-replay only tightens the cluster's substrate.launcher.key_replay
// (D3.1-3), an older gateway leaves the default (ask), and a bad value is a
// usage error.
func TestKeyReplayFlagOnlyTightens(t *testing.T) {
	cluster := `{"workspace_max_bytes":1048576,"key_replay":"ask"}`
	useFakeAdmin(t, &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){
		"GET launcher": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(cluster)) },
	}})
	s, err := substrateOpen(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmd := &cobra.Command{}
	cmd.SetContext(t.Context())
	for _, c := range []struct{ cluster, flag, want string }{
		{`{"key_replay":"ask"}`, "on", attach.KeyReplayAsk},
		{`{"key_replay":"ask"}`, "off", attach.KeyReplayOff},
		{`{"key_replay":"off"}`, "on", attach.KeyReplayOff},
		{`{"key_replay":"on"}`, "", attach.KeyReplayOn},
		{`{"workspace_max_bytes":1048576}`, "", attach.KeyReplayAsk},
	} {
		cluster = c.cluster
		got, err := substrateKeyReplay(cmd, s, c.flag)
		if err != nil || got != c.want {
			t.Errorf("cluster %s flag %q: %q %v, want %q", c.cluster, c.flag, got, err, c.want)
		}
	}
	if _, err := substrateKeyReplay(cmd, s, "always"); err == nil {
		t.Fatal("a bad --key-replay was accepted")
	}
}
