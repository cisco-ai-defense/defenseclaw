// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestR107KnownCopyWordAfterCdGetsTheVerdictWithoutTheCd: the unquoted
// rel-1-0-2:GAP-0004 copy forms (a source named by an assigned plain value
// or a one-name for loop) after a leading cd get the verdict they get
// without it, in every cell (rel-1-0-6:GAP-0320). The cd twins of the
// keys-bound forms, and a copy of the keys link after cd, still block.
func TestR107KnownCopyWordAfterCdGetsTheVerdictWithoutTheCd(t *testing.T) {
	checkDynamicWordParity(t,
		[]string{
			`f=a.txt; cp $f out.txt && echo ok`,
			`cd ~/proj && f=a.txt; cp "$f" out.txt && echo ok`,
			`cd ~/proj && f=a.txt; cp $f out.txt && echo ok`,
			`cd ~/proj; f=a.txt; cp $f out.txt`,
			`cd ~/proj && f=a.txt; cp $f out.txt`,
			`cd ~/proj && for x in a.txt; do cp $x build/; done; echo hi > report.txt`,
			`cd ~/proj && cp a.txt out.txt; echo hi > report.txt`,
			`cd build && f=a.txt; cp ../ out.txt && echo ok`,
		},
		[]string{
			`cd ~/proj && cp $f build/ && echo hi > report.txt`,
			`cd ~/proj && f=a.txt; cp $f disklink`,
			`cd ~/proj && for f in a.txt; do cp $f disklink; done`,
			`cd ~/proj && f=a.txt; cp $f build/; echo hi > disklink`,
			`cd ~/proj && f=a.txt; read f; cp $f build/ && echo hi > report.txt`,
			`cd ~/proj && T=--target-directory=$HOME/.ssh; cp $T a.txt`,
			`cd ~/proj && f=disklink; cp -a $f kbak && echo k >> kbak`,
			`cd ~/proj && cp -a disklink kbak && echo k >> kbak`,
			`cd ~/.ssh && f=a.txt; cp ~/proj/$f authorized_keys`,
			`cd ~ && f=a.txt; cp proj/$f .ssh/authorized_keys`,
		})
}
