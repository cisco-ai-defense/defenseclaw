// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0920GuestSplitGapTwinsReadNoHostFile: the effect twins a sandbox call
// with a parse gap is judged by, in a folder of the guest
// (withSandboxGuestSplitGapEffects), never lstat or readlink a host file
// spelled at a guest path, for any connector. claudecode and codex set
// SkipLocalFilesystemResolution for every sandbox call; the generic hook path
// does not, so before 017daa0f88 a twin of another connector read a host link
// that sits at the guest path and judged the call by where it leads.
// Here the guest working directory is a folder that exists on the host and
// holds dc-link, a link to the host's DefenseClaw config: the guest holds no
// such link, so $CMD followed by echo x >> dc-link is a write to an ordinary
// file of the guest and must not name the tamper rule.
func TestGAP0920GuestSplitGapTwinsReadNoHostFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway")
	}
	root := t.TempDir()
	home := filepath.Join(root, "guesthome")
	guestCWD := filepath.Join(home, "work")
	hostCWD := filepath.Join(root, "hostwork")
	for _, dir := range []string{guestCWD, hostCWD, filepath.Join(home, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(home, ".defenseclaw", "config.yaml")
	if err := os.WriteFile(config, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.defenseclaw/config.yaml", filepath.Join(guestCWD, "dc-link")); err != nil {
		t.Fatal(err)
	}
	const command = "$CMD\necho x >> dc-link"
	// The same call from a guest folder that holds no link.
	plainCWD := filepath.Join(home, "plain")
	if err := os.MkdirAll(plainCWD, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"opencode", "cursor"} {
		t.Run(connector, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, connector, "default")
			cfg := newGAP0920Config(connector)
			args, err := json.Marshal(map[string]string{"command": command})
			if err != nil {
				t.Fatal(err)
			}
			verdict := func(guest string) gap0920Verdict {
				request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector}
				action := trustedActionRequest{
					Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: hostCWD, ActiveHome: home,
						DialectHint: actionfacts.DialectPOSIX},
					LegacyText: string(args), Connector: connector, EnforcementCapable: true,
					SandboxGuestCWD: guest,
				}
				v := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(), request, action)
				out := gap0920Verdict{Action: v.Action, Findings: slices.Clone(v.Findings)}
				slices.Sort(out.Findings)
				return out
			}
			withLink, plain := verdict(guestCWD), verdict(plainCWD)
			if withLink.Action != plain.Action || !slices.Equal(withLink.Findings, plain.Findings) {
				t.Errorf("a host link at the guest path changed the verdict: with %+v, without %+v", withLink, plain)
			}
		})
	}
}

// gap0920Verdict is the part of a verdict this test compares.
type gap0920Verdict struct {
	Action   string
	Findings []string
}

func newGAP0920Config(connector string) *config.Config {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.BlockAt = "HIGH"
	return cfg
}
