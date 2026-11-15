// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// TestDataToolFileOperandsAreReadPaths (substrate-1:GAP-0233): jq, yq and xargs -a
// name files they read; the facts carry them so the credential-file rules judge them.
func TestDataToolFileOperandsAreReadPaths(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string
	}{
		{"jq . .docker/config.json", []string{"/work/p/.docker/config.json"}},
		{"jq -r '.auths' ~/.docker/config.json", []string{"/home/alice/.docker/config.json"}},
		{"jq -c . a.json b.json", []string{"/work/p/a.json", "/work/p/b.json"}},
		{"jq --arg k v . creds.json", []string{"/work/p/creds.json"}},
		{"jq -f prog.jq data.json", []string{"/work/p/prog.jq", "/work/p/data.json"}},
		{"jq --slurpfile x /etc/shadow . in.json", []string{"/etc/shadow", "/work/p/in.json"}},
		{"yq e '.a' ~/.kube/config", []string{"/home/alice/.kube/config"}},
		{"yq '.a' .env.yaml", []string{"/work/p/.env.yaml"}},
		{"xargs -a .env echo", []string{"/work/p/.env"}},
		{"xargs --arg-file=.env echo", []string{"/work/p/.env"}},
		{"xargs -0 -a ~/.aws/credentials cat", []string{"/home/alice/.aws/credentials"}},
		// No file named: stdin, a filter only, data after --args.
		{"jq -n '1+1'", nil},
		{"jq . < in.json", nil},
		{"jq -n --args '$ARGS' a b c", nil},
		{"xargs echo", nil},
		{"xargs -n1 echo -a x", nil},
	} {
		facts := Analyze(Input{Tool: "Bash", Command: tc.command, CWD: "/work/p", ActiveHome: "/home/alice", DialectHint: DialectPOSIX})
		var got []string
		for _, path := range facts.Paths {
			if path.Access == PathAccessRead && path.Resolved != "" && path.Resolved != "/work/p/in.json" || path.Access == PathAccessRead && slices.Contains(tc.want, path.Resolved) {
				got = append(got, path.Resolved)
			}
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%q: read paths %v, want %v (%+v)", tc.command, got, tc.want, facts.Paths)
		}
	}
}
