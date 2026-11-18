// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// GAP-0116: a kit image may run as root only when root runs the relay and
// the relay starts the agent as a non-root relay.agent_user; any other root
// image is refused as before.
func TestRootUserOnlyForTheRelayWithAnAgentUser(t *testing.T) {
	f := newFixture(t)
	root := func(entry []string, cfg string) func(*BuildOptions) {
		return func(o *BuildOptions) {
			o.Kit.User, o.Kit.Entrypoint = "0:0", entry
			if cfg != "" {
				o.Kit.Files = append(o.Kit.Files, LayerFile{Path: kit.ConfigPath, Mode: 0o644, Data: []byte(cfg)})
			}
		}
	}
	relay := []string{kit.RelayBinary, "serve"}
	if _, err := f.build(t, root(relay, `{"relay":{"agent_user":"1000:1000"}}`)); err != nil {
		t.Fatalf("a root relay with an agent user: %v", err)
	}
	for name, mut := range map[string]func(*BuildOptions){
		"no kit config":        root(relay, ""),
		"no agent user":        root(relay, `{"relay":{}}`),
		"root agent user":      root(relay, `{"relay":{"agent_user":"0:0"}}`),
		"another entrypoint":   root([]string{"/bin/sh"}, `{"relay":{"agent_user":"1000:1000"}}`),
		"base entrypoint kept": root(nil, `{"relay":{"agent_user":"1000:1000"}}`),
	} {
		if _, err := f.build(t, mut); !errors.Is(err, ErrHooksNotSafe) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
