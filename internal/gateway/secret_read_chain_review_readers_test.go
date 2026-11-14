// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// Which readers and table rows arm the chain (review round 1, cases by id).
func TestSecretReadChainReviewReadersAndTable(t *testing.T) {
	const f = "/work/p/.env"
	rows := []struct{ id, cmd string }{
		{"RD-tac", "tac " + f}, {"RD-nl", "nl " + f}, {"RD-od", "od -c " + f}, {"RD-strings", "strings " + f},
		{"RD-cut", "cut -d= -f2 " + f}, {"RD-sort", "sort " + f}, {"RD-hexdump", "hexdump -C " + f},
		{"RD-xargs", "xargs -a " + f + " echo"}, {"RD-nice", "nice -n 5 cat " + f}, {"RD-time", "time cat " + f},
		{"RD-timeout", "timeout 5 cat " + f}, {"RD-nohup", "nohup cat " + f}, {"RD-envassign", "env A=1 cat " + f},
		{"RD-tar", "tar czf /tmp/o.tgz " + f}, {"RD-tar2", "tar -czf /tmp/o.tgz " + f}, {"RD-zip", "zip /tmp/o.zip " + f},
		{"RD-sedbare", "sed s/a/b/ " + f}, {"RD-sede", "sed -e s/a/b/ " + f}, {"RD-awkF", "awk -F= '{print $2}' " + f},
		{"RD-diff", "diff " + f + " /tmp/x"}, {"RD-rsync", "rsync " + f + " /tmp/x"}, {"RD-openssl", "openssl base64 -in " + f},
	}
	for _, r := range rows {
		facts := gap0210Facts(r.cmd, "/work/p")
		if got := credentialFileContentRead(facts); got != srd2ReviewReaderArms[r.id] {
			t.Errorf("reader probe %s: arms = %t, want %t (parse %s)", r.id, got, srd2ReviewReaderArms[r.id], facts.Parse.Status)
		}
	}
	for _, p := range []string{
		"/home/a/.claude/.credentials.json", "/home/a/.codex/auth.json", "/home/a/.gemini/oauth_creds.json",
		"/home/a/.config/git/credentials", "/home/a/.aws/sso/cache/x.json", "/home/a/.aws/cli/cache/y.json",
		"/home/a/.config/gcloud/legacy_credentials/u@x/adc.json", "/home/a/.vault-token",
		"/home/a/.terraform.d/credentials.tfrc.json", "/home/a/.cargo/credentials.toml", "/home/a/.gem/credentials",
		"/home/a/.config/containers/auth.json", "/home/a/.m2/settings-security.xml", "/home/a/.kube/config.bak",
		"/home/a/.config/github-copilot/hosts.json", "/home/a/.copilot/config.json",
		"/home/a/.aws/sso/cache/x.json.template", "/home/a/proj/.credentials.json.example",
	} {
		_, ok := actionfacts.MatchCredentialFileShape(p)
		if want := !strings.HasSuffix(p, ".template") && !strings.HasSuffix(p, ".example"); ok != want {
			t.Errorf("table row %s: match = %t, want %t", p, ok, want)
		}
	}
}

// srd2ReviewReaderArms: sed with a bare or -e script, awk -F and openssl
// base64 -in stay out (substrate-1:GAP-0233: their scripts and subcommands
// can write or run files); env VAR=value stays fail-closed by decision.
var srd2ReviewReaderArms = map[string]bool{
	"RD-tac": true, "RD-nl": true, "RD-od": true, "RD-strings": true, "RD-cut": true, "RD-sort": true,
	"RD-hexdump": true, "RD-xargs": true, "RD-nice": true, "RD-time": true, "RD-timeout": true, "RD-nohup": true,
	"RD-envassign": false, "RD-tar": true, "RD-tar2": true, "RD-zip": true,
	"RD-sedbare": false, "RD-sede": false, "RD-awkF": false,
	"RD-diff": true, "RD-rsync": true, "RD-openssl": false,
}
