// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestGAP1219HeredocTwinRejectsUnsharedParameters pins the hook verdict for
// parameters the holding shell and receiving shell cannot share. These rows
// failed at a88baa0761: the twin read the body and both protected tiers allowed.
func TestGAP1219HeredocTwinRejectsUnsharedParameters(t *testing.T) {
	commands := map[string]string{
		"nested-single-quote-alternate": "cat <<EOF | sh\nrm -rf ${HOME:+'$HOME'}/*\nEOF",
		"nested-single-quote-default":   "cat <<EOF | sh\nrm -rf ${NOPE:-'$HOME'}/*\nEOF",
		"nested-single-quote-write":     "cat <<EOF | sh\necho x >> ${HOME:+'$HOME'}/.bashrc\nEOF",
		"printf-fused":                  "cat <<EOF | bash\nprintf -vD /tmp/build\nrm -rf $D/*\nEOF",
		"eval":                          "cat <<EOF | sh\neval D=/tmp/build\nrm -rf $D/*\nEOF",
		"wait-p":                        "cat <<EOF | bash\nsleep 0 & wait -p D\nrm -rf /tmp/$D/*\nEOF",
		"rematch":                       "cat <<EOF | bash\n[[ /tmp/build =~ (.*) ]]\nrm -rf ${BASH_REMATCH[1]}/*\nEOF",
		"read-reply":                    "cat <<EOF | bash\nread <<< /tmp/build\nrm -rf $REPLY/*\nEOF",
		"underscore":                    "true /; cat <<EOF | sh\nrm -rf $_*\nEOF",
		"directory-change":              "cat <<EOF | sh\ncd /tmp/build\nrm -rf $PWD/*\nEOF",
		"source":                        "cat <<EOF | sh\n. ./env.sh\nrm -rf $D/*\nEOF",
		"declare-name-reference":        "cat <<EOF | bash\ndeclare -n D=OTHER\nrm -rf $D/*\nEOF",
		"arithmetic-index":              "cat <<EOF | bash\n((D[0]=1))\nrm -rf $D/*\nEOF",
		"descriptor-name":               "cat <<EOF | bash\n{D}>/tmp/out\nrm -rf $D/*\nEOF",
		"getopts-name":                  "cat <<EOF | bash\ngetopts a D\nrm -rf $D/*\nEOF",
		"dynamic-program":               "cat <<EOF | bash\n$TOOL D=/tmp/build\nrm -rf $D/*\nEOF",
		"R07-named-coproc-pid":          "cat <<EOF | bash\ncoproc WORK { :; }\nrm -rf /tmp/$WORK_PID/*\nEOF",
		"R08-unnamed-coproc-pid":        "cat <<EOF | bash\ncoproc { :; }\nrm -rf /tmp/$COPROC_PID/*\nEOF",
	}
	benign := map[string]string{
		"commit-file":  "git commit -F - <<EOF\nfix for $USER\nEOF",
		"gh-body":      "gh pr create --title t --body \"$(cat <<EOF\nby '$USER'\nEOF\n)\"",
		"cat-file":     "cat > notes.md <<EOF\nbuilt for $USER\nEOF",
		"tee-file":     "tee notes.md <<EOF\nD=/tmp/build\n$D '$HOME'\nEOF",
		"jq-input":     "jq -n --arg b \"$(cat <<EOF\nplain text\nEOF\n)\" '{b:$b}'",
		"mysql-input":  "mysql -u root <<EOF\nselect 1;\nEOF",
		"python-input": "python3 - <<EOF\nprint('plain text')\nEOF",
		"ssh-plain":    "ssh host bash <<EOF\necho plain text\nEOF",
	}
	shellTextTiers(t, func(tier string, decide func(string) (string, []string), _ func(string, bool) (string, []string)) {
		least := "allow"
		switch {
		case strings.HasSuffix(tier, "/strict"):
			least = "block"
		case strings.HasSuffix(tier, "/default"):
			least = "alert"
		}
		for name, command := range commands {
			t.Run(tier+"/"+name, func(t *testing.T) {
				got, findings := decide(command)
				if gap1137Rank[got] < gap1137Rank[least] || !strings.Contains(strings.Join(findings, "|"), gap1147UnreadReason) {
					t.Errorf("got %s (%q), want at least %s with unread reason", got, findings, least)
				}
			})
		}
		for name, command := range benign {
			t.Run(tier+"/benign/"+name, func(t *testing.T) {
				got, findings := decide(command)
				if got != "allow" || strings.Contains(strings.Join(findings, "|"), gap1147UnreadReason) {
					t.Errorf("got %s (%q), want allow without unread reason", got, findings)
				}
			})
		}
	})
}
