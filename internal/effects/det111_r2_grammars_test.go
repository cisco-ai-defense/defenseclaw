// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"testing"
)

// DET111 step 4, class R2 (DESIGN D2): option grammars and the closed text
// grammars of the program table. Red at a64bfdb931 unless marked pin.

// r2Subtree wants a write at path that covers the tree below it.
func r2Subtree(path string) func(Result) string {
	return func(r Result) string {
		for _, e := range r.Effects {
			if e.Kind == KindWrite && e.Target.Path == path && e.Target.Subtree {
				return ""
			}
		}
		return "no subtree write at " + path
	}
}

// r2Send wants a network send to host.
func r2Send(host string) func(Result) string {
	return func(r Result) string {
		for _, e := range r.Effects {
			if e.Kind == KindNetworkSend && e.Target.Host == host {
				return ""
			}
		}
		return "no network send to " + host
	}
}

const r2Hook = "/home/u/.claude/settings.json"

var r2GrammarCases = []r2case{
	// sed: w, W and s///w write their file, r reads one, e runs a command.
	{"GAP-1288 sed -i -e w", raLin, `sed -i -e 'w out[9]' file`, r2Verdict("K|write:/home/u/proj/file,write:/home/u/proj/out[9]"), false},
	{"GAP-1318 sed s///w", raLin, `sed 's/a/b/w outa' file`, r2Verdict("K|write:/home/u/proj/outa"), false},
	{"GAP-1500 sed -n w", raLin, `sed -n 'w ` + r2Hook + `' /dev/null`, r2Verdict("K|write:" + r2Hook), false},
	{"GAP-1500 sed W", raLin, `sed -n 'W ` + r2Hook + `' f`, r2Verdict("K|write:" + r2Hook), false},
	{"GAP-1500 sed s///gw", raLin, `sed 's/a/b/gw ` + r2Hook + `' f`, r2Verdict("K|write:" + r2Hook), false},
	{"GAP-1500 sed -e w", raLin, `sed -e 'w ` + r2Hook + `' f`, r2Verdict("K|write:" + r2Hook), false},
	// e COMMAND runs COMMAND with /bin/sh: its effects are the command's.
	{"GAP-1500 sed e runs", raLin, `sed '1e touch x' f`, r2Verdict("K|write:/home/u/proj/x"), true},
	{"GAP-1500 sed e hook write", raLin, `sed -n '1e echo x > ` + r2Hook + `' f`, r2Verdict("K|write:" + r2Hook), false},
	{"GAP-1500 sed e pattern space", raLin, `sed 's/a/b/e' f`, r2Verdict("U|"), false},
	{"R2 sed w stdout", raLin, `sed -n '/x/w /dev/stdout' f`, r2Verdict("K|"), false},
	{"R2 sed r reads", raLin, `sed 'r /home/u/notes.txt' f`, r2All(r2Has(KindRead, "/home/u/notes.txt", true), r2Verdict("U|")), false},
	{"R2 sed plain", raLin, `sed -n 's/a/b/p' f`, r2Verdict("K|"), true},
	// awk: a print redirect writes its literal file; gawk /inet is a connection.
	{"GAP-1239 awk print redirect", raLin, `awk 'BEGIN{print "x" > "/home/u/.defenseclaw/config.yaml"}'`, r2Verdict("U|write:/home/u/.defenseclaw/config.yaml"), false},
	{"GAP-1239 env awk", raLin, `env awk 'BEGIN{print "x" > "/home/u/.defenseclaw/config.yaml"}'`, r2Verdict("U|write:/home/u/.defenseclaw/config.yaml"), false},
	{"GAP-1239 sudo awk", raLin, `sudo awk 'BEGIN{print "x" > "/home/u/.defenseclaw/config.yaml"}'`, r2Has(KindWrite, "/home/u/.defenseclaw/config.yaml", true), false},
	{"R2 awk append", raLin, `awk '{print >> "log.txt"}' f`, r2Verdict("U|append:/home/u/proj/log.txt"), false},
	{"GAP-1571 gawk inet", raLin, `gawk 'BEGIN{print "x" > "/inet/tcp/0/example.test/80"}'`, r2Send("example.test"), false},
	{"R2 gawk plain", raLin, `gawk '{print $1}' f`, r2Verdict("K|"), false},
	// GNU long-option abbreviations (getopt_long).
	{"GAP-1666 grep --incl=", raLin, `grep -r --incl='*.env' KEY .`, r2Verdict("K|"), false},
	{"R2 sort --out=", raLin, `sort --out=` + r2Hook + ` /tmp/x`, r2Verdict("K|write:" + r2Hook), false},
	{"GAP-0506 cp --target=", raLin, `cp --target=/home/u/.defenseclaw x`, r2Verdict("K|write:/home/u/.defenseclaw/x"), false},
	{"GAP-0506 cp --target-dir DIR", raLin, `cp --target-dir /home/u/.defenseclaw x`, r2Verdict("K|write:/home/u/.defenseclaw/x"), false},
	{"GAP-0506 cp -at DIR", raLin, `cp -at /home/u/.defenseclaw x`, r2Verdict("K|write:/home/u/.defenseclaw/x/**"), false},
	{"R2 ambiguous prefix stays unknown", raLin, `cp --no-t x y`, r2Verdict("U|"), true},
	// tar: abbreviations and the letters that take a value.
	{"GAP-0661 tar --ext --dir", raLin, `tar --ext -f a.tar --dir /home/u/.defenseclaw`, r2Has(KindWrite, "/home/u/.defenseclaw", false), false},
	{"GAP-0661 tar -xvC", raLin, `tar -xvC /home/u/.defenseclaw -f a.tar`, r2Has(KindWrite, "/home/u/.defenseclaw", false), false},
	{"GAP-0661 tar old style xfC", raLin, `tar xfC a.tar /home/u/.defenseclaw`, r2Has(KindWrite, "/home/u/.defenseclaw", false), false},
	{"GAP-0661 tar -T members", raLin, `tar -c -T list -f out.tar`, r2HasUnknownTarget(KindRead, ReasonOperandsFromInput), false},
	{"GAP-0104 tar -c reads", raLin, `tar -cf /tmp/x.tar ` + r2Hook, r2Verdict("K|write:/tmp/x.tar"), true},
	// rsync: a dry run writes no operand, its log file is written.
	{"GAP-1478 rsync -n --log-file", raLin, `rsync -an --log-file=/home/u/.defenseclaw/audit.db a/ b/`, r2Verdict("K|append:/home/u/.defenseclaw/audit.db"), false},
	{"GAP-0104 rsync -n", raLin, `rsync -n -a /home/u/.defenseclaw/ /tmp/bk/`, r2Verdict("K|"), false},
	{"GAP-0104 rsync --dry-run", raLin, `rsync --dry-run -av /home/u/.codex/config.toml /tmp/bk/`, r2Verdict("K|"), false},
	{"R2 rsync -a tree", raLin, `rsync -a /tmp/bk/ /home/u/.defenseclaw/`, r2Subtree("/home/u/.defenseclaw"), false},
	// cp -r / -a: the destination write covers the tree (GAP-1261).
	{"GAP-1261 cp -rt", raLin, `cp -rt /home/u .defenseclaw`, r2Verdict("K|write:/home/u/.defenseclaw/**"), false},
	{"GAP-1261 cp -r into dir", raLin, `cp -r /tmp/d/.defenseclaw /home/u/`, r2Subtree("/home/u/.defenseclaw"), false},
	{"GAP-0104 cp FROM reads", raLin, `cp ` + r2Hook + ` /tmp/bk/`, r2Verdict("K|write:/tmp/bk/settings.json"), true},
	{"GAP-0104 sha256sum reads", raLin, `sha256sum ` + r2Hook + ` /home/u/.codex/config.toml`, r2Verdict("K|"), true},
}

func TestDET111R2Grammars(t *testing.T) {
	runR2(t, r2GrammarCases)
}
