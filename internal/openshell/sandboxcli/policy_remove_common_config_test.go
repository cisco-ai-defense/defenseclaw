// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxcli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

func TestPolicyRemoveCommonConfigMessagesFollowCurrentWriteAuthority(t *testing.T) {
	for _, source := range []struct {
		name, body, namespace string
		legacyMirror          bool
	}{
		{"legacy", "openshell:\n  egress: {%s: [remove.example, keep.example]}\n", "openshell", true},
		{"common explicit", "sandbox:\n  enabled: false\n  egress: {%s: [remove.example, keep.example]}\n", "sandbox", false},
		{"common inherited", "openshell:\n  egress: {%s: [remove.example, keep.example]}\nsandbox: {enabled: false}\n", "sandbox", true},
	} {
		for _, list := range []string{"allow", "block"} {
			t.Run(source.name+"/"+list, func(t *testing.T) {
				t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
				t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
				directory := t.TempDir()
				t.Setenv("DEFENSECLAW_HOME", directory)
				path := filepath.Join(directory, "config.yaml")
				raw := fmt.Sprintf("config_version: 9\ndata_dir: %q\n", directory) + fmt.Sprintf(source.body, list)
				if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
				var output bytes.Buffer
				app := &App{
					// Deliberately stale: current source, not this legacy model,
					// must select the namespace inside the writer transaction.
					Cfg:        &config.Config{DataDir: directory},
					ConfigPath: path,
					IO:         IO{In: strings.NewReader(""), Out: &output, Err: &output},
				}
				key := source.namespace + ".egress." + list
				if err := app.PolicyRemove(context.Background(), list, []string{"remove.example", "missing.example"}); err != nil {
					t.Fatalf("PolicyRemove: %v", err)
				}
				for _, message := range []string{"removed remove.example from " + key, "missing.example is not in " + key} {
					if !strings.Contains(output.String(), message) {
						t.Fatalf("output %q does not contain %q", output.String(), message)
					}
				}
				other := "sandbox.egress." + list
				if source.namespace == "sandbox" {
					other = "openshell.egress." + list
				}
				if strings.Contains(output.String(), other) {
					t.Fatalf("output names the other write authority: %s", output.String())
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				root, err := sandboxSource(after)
				if err != nil {
					t.Fatal(err)
				}
				var retained []string
				if node := sandboxSourceAt(root, key); node == nil {
					t.Fatalf("persisted write authority %s is absent", key)
				} else if err := node.Decode(&retained); err != nil || !slices.Equal(retained, []string{"keep.example"}) {
					t.Fatalf("persisted %s = %v, %v", key, retained, err)
				}
				legacy := sandboxSourceAt(root, "openshell.egress."+list)
				if (legacy != nil) != source.legacyMirror {
					t.Fatal("message fix changed legacy persistence")
				}
				if legacy != nil {
					if err := legacy.Decode(&retained); err != nil || !slices.Equal(retained, []string{"keep.example"}) {
						t.Fatalf("legacy mirror = %v, %v", retained, err)
					}
				}
				if source.namespace == "openshell" && sandboxSourceAt(root, "sandbox") != nil {
					t.Fatal("legacy removal introduced the common namespace")
				}
				state, err := configwrite.ReadGenerationState(path)
				if err != nil {
					t.Fatal(err)
				}
				output.Reset()
				err = app.PolicyRemove(context.Background(), list, []string{"absent.example"})
				if err == nil || !strings.Contains(err.Error(), "absent.example is not in "+key) || strings.Contains(err.Error(), other) {
					t.Fatalf("refusal = %v; want current authority %s", err, key)
				}
				if output.Len() != 0 {
					t.Fatalf("refusal printed success or warning: %q", output.String())
				}
				unchanged, readErr := os.ReadFile(path)
				unchangedState, stateErr := configwrite.ReadGenerationState(path)
				if readErr != nil || stateErr != nil || !bytes.Equal(unchanged, after) || !reflect.DeepEqual(state, unchangedState) {
					t.Fatalf("refusal changed source or generation: read=%v state=%v", readErr, stateErr)
				}
			})
		}
	}
}
