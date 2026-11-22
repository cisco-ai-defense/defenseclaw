// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

func TestGAP1219RoundCReviewHookTiers(t *testing.T) {
	rows := []struct{ name, body string }{
		{"M01", "rm -rf ${NOPE:-/etc/*; :}"},
		{"M02", "rm -rf ${HOME:+/etc/*; :}"},
		{"M03", "rm -rf ${NOPE:-# /etc/*}"},
		{"M04", "rm -rf ${NOPE:->/etc/*}"},
		{"M05", "rm -rf ${NOPE:-/etc/* /tmp/x}"},
		{"O01", "rm -rf $D/*"},
		{"B01", "rm -rf $HOME{a,b}/*"},
		{"A01", "[[ D=1 ]]; rm -rf $D/*"},
		{"Z01", "rm -rf ${NOPE:-/etc/* /tmp/x}"},
		{"Z02", "rm -rf $HOME/*"},
		{"Z03", "rm -rf $HOME{a,b}/*"},
		{"Z04", "rm -rf $HOME[1]/*"},
		{"Z05", "rm -rf ${NOPE:-/etc/*; :}"},
		{"Z06", "rm -rf ${HOME:+/etc/*; :}"},
		{"Z07", "rm -rf $D/*"},
		{"Z08", "[[ D=1 ]]; rm -rf $D/*"},
		// Review round 3: an indexed printf destination and a mapfile
		// callback bind D in the receiving shell (V06, V07).
		{"V06", "printf -v D[0] %s /tmp/x; rm -rf $D/*"},
		{"V06b", "printf -vD[0] %s /tmp/x; rm -rf $D/*"},
		{"V07", "mapfile -C 'D=/tmp/x; :' -c 1 L < /etc/hostname; rm -rf $D/*"},
		{"V07b", "readarray -tC 'D=/tmp/x; :' -c 1 L < /etc/hostname; rm -rf $D/*"},
		{"A02", "[[ 1 -eq D=1 ]]; rm -rf $D/*"},
	}
	shellTextTiers(t, func(tier string, decide func(string) (string, []string), oracle func(string, bool) (string, []string)) {
		if !strings.HasSuffix(tier, "/permissive") {
			if direct, findings := oracle("rm -rf /etc/*; :", true); direct != "block" {
				t.Errorf("%s: metacharacter oracle is %s (%q), want block", tier, direct, findings)
			}
		}
		for _, row := range rows {
			shell := "bash"
			if strings.HasPrefix(row.name, "Z") {
				shell = "zsh"
			}
			prefix := ""
			if row.name == "O01" || row.name == "Z07" {
				prefix = "D=/tmp/outer; "
			}
			command := prefix + "cat <<EOF | " + shell + "\n" + row.body + "\nEOF"
			t.Run(tier+"/"+row.name, func(t *testing.T) {
				got, findings := decide(command)
				least := "allow"
				if strings.HasSuffix(tier, "/default") {
					least = "alert"
				}
				if strings.HasSuffix(tier, "/strict") {
					least = "block"
				}
				if gap1137Rank[got] < gap1137Rank[least] || !strings.Contains(strings.Join(findings, "|"), gap1147UnreadReason) {
					t.Errorf("%s: %s (%q), want at least %s and unread reason", row.name, got, findings, least)
				}
			})
		}
		// Review round 3 C02: a string, file or numeric test binds nothing,
		// so the body is read as written and a benign call stays allowed.
		for _, body := range []string{
			"[[ -n $HOME ]] && echo $HOME",
			"[[ -f $HOME/.bashrc ]] && echo $HOME",
		} {
			command := "cat <<EOF | bash\n" + body + "\nEOF"
			t.Run(tier+"/C02/"+body, func(t *testing.T) {
				if got, findings := decide(command); got != "allow" || strings.Contains(strings.Join(findings, "|"), gap1147UnreadReason) {
					t.Errorf("%q: %s (%q), want allow without the unread reason", body, got, findings)
				}
			})
		}
	})
}
