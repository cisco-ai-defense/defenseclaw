// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package actionfacts

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// These are the independent round-two review shapes. Only a plain, unbound
// parameter printed for bash or sh can be read as written. A matching output
// from one run does not make an operator or a zsh expansion provably shared.
func TestGAP1219RoundCReviewDifferential(t *testing.T) {
	rows := []struct {
		name, shell, prefix, body string
	}{
		{"M01-default-semicolon", "bash", "", "printf '<%s>' ${NOPE:-a; printf R}"},
		{"M02-alternate-semicolon", "bash", "", "printf '<%s>' ${HOME:+a; printf R}"},
		{"M03-default-comment", "bash", "", "printf '<%s>' ${NOPE:-# comment}"},
		{"M04-default-redirect", "bash", "", "printf '<%s>' ${NOPE:->/dev/null}"},
		{"M05-default-space", "bash", "", "printf '<%s>' ${NOPE:-a b}"},
		{"O01-outer-assignment", "bash", "D=OUT; ", "printf '<%s>' $D"},
		{"B01-brace-after-bare", "bash", "", "printf '<%s>' $HOME{a,b}"},
		{"A01-test-arithmetic", "bash", "", "[[ D=1 ]]; printf '<%s>' $D"},
		{"Z01-zsh-default-space", "zsh", "", "printf '<%s>' ${NOPE:-a b}"},
		{"Z02-zsh-bare-space", "zsh", "", "printf '<%s>' $HOME"},
		{"Z03-zsh-brace", "zsh", "", "printf '<%s>' $HOME{a,b}"},
		{"Z04-zsh-subscript", "zsh", "", "printf '<%s>' $HOME[1]"},
		{"Z05-zsh-default-semicolon", "zsh", "", "printf '<%s>' ${NOPE:-a; printf R}"},
		{"Z06-zsh-alternate-semicolon", "zsh", "", "printf '<%s>' ${HOME:+a; printf R}"},
		{"Z07-zsh-outer-assignment", "zsh", "D=OUT; ", "printf '<%s>' $D"},
		{"Z08-zsh-test-arithmetic", "zsh", "", "[[ D=1 ]]; printf '<%s>' $D"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if _, err := exec.LookPath(row.shell); err != nil {
				t.Skipf("%s unavailable", row.shell)
			}
			command := row.prefix + "cat <<EOF | " + row.shell + "\n" + row.body + "\nEOF"
			cmd := exec.Command("bash", "-c", command)
			cmd.Env = append(os.Environ(), "HOME=/hh")
			cmd.Stdin = strings.NewReader("")
			if _, err := cmd.CombinedOutput(); err != nil && !strings.HasPrefix(row.name, "Z04-") {
				t.Fatalf("oracle failed: %v", err)
			}
			if twin, ok, _, unread := RunTimeShellTwin(command); !unread {
				t.Errorf("%s: twin %q, ok=%v unread=%v; want unread", row.name, twin, ok, unread)
			}
		})
	}
}

func TestGAP1219RoundCPlainAndLengthControls(t *testing.T) {
	for _, body := range []string{
		"printf '<%s>' $HOME/x",
		"printf '<%s>' ${HOME}/x",
		"printf '<%s>' ${#HOME}",
	} {
		command := "cat <<EOF | bash\n" + body + "\nEOF"
		if _, ok, _, unread := RunTimeShellTwin(command); !ok || unread {
			t.Errorf("plain shared parameter %q: ok=%v unread=%v", body, ok, unread)
		}
	}
	for _, command := range []string{
		"env D=/tmp cat <<EOF | bash\nprintf '<%s>' $D\nEOF",
		"cat <<EOF | bash\nprintf '<%s>' $PWD\nEOF",
	} {
		if _, _, _, unread := RunTimeShellTwin(command); !unread {
			t.Errorf("unshared parameter %q was marked known", command)
		}
	}
}
