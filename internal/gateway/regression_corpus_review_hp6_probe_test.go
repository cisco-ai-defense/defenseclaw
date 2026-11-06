// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build regressioncorpora

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hookparse6 review probes (not committed). Strict ProtectHome fixture:
// soundness neighbours of the dead-value exemption, GAP-0418 forms,
// loop-copy neighbours and the GAP-0397 sweep form.
func hp6ProbeRows(project string) []struct{ name, command, want string } {
	return []struct{ name, command, want string }{
		{"sp-while", `f=a.txt; n=; while [ -z "$n" ]; do f=keylink; n=1; done; echo m >> "$f"`, "block"},
		{"sp-and", `f=a.txt; [ -d ordinary ] && f=keylink; echo m >> "$f"`, "block"},
		{"sp-or", `f=a.txt; false || f=keylink; echo m >> "$f"`, "block"},
		{"sp-case", `f=a.txt; case x in x) f=keylink;; esac; echo m >> "$f"`, "block"},
		{"sp-brace", `f=a.txt; { f=keylink; }; echo m >> "$f"`, "block"},
		{"sp-if", `f=a.txt; if [ -d ordinary ]; then f=keylink; fi; echo m >> "$f"`, "block"},
		{"sp-negated", `f=a.txt; ! f=keylink; echo m >> "$f"`, "block"},
		{"sp-time", `f=a.txt; time f=keylink; echo m >> "$f"`, "block"},
		{"sp-time-block", `f=a.txt; time { f=keylink; }; echo m >> "$f"`, "block"},
		{"sp-printf-attached", `f=a.txt; printf -vf %s keylink; echo m >> "$f"`, "block"},
		{"sp-printf-quoted", `f=a.txt; printf "-v" f %s keylink; echo m >> "$f"`, "block"},
		{"sp-printf-attached-before", `f=keylink; { echo m >> "$f"; printf -vf %s a.txt; }; echo m >> "$f"`, "block"},
		{"sp-dplout", `f=a.txt; echo m >> "$f"; g=keylink; echo m >& "$g"`, "block"},
		{"sp-dplout-only", `g=keylink; echo m >& "$g"`, "block"},
		{"sp-inout", `f=a.txt; echo m >> "$f"; g=keylink; : 1<> "$g"`, "block"},
		{"sp-dotslash", `f=keylink; f=./keylink; echo m >> "$f"`, "block"},
		{"sp-dirlink", `f=a.txt; f=sshlink/authorized_keys; echo m >> "$f"`, "block"},
		{"sp-dirlink-concat", `d=sshlink; echo m >> "$d/authorized_keys"`, "block"},
		{"sp-cd-dot", `cd . && f=keylink; echo m >> "$f"`, "block"},
		{"sp-subst", `f=a.txt; echo m >> "${f/a.txt/keylink}"`, "block"},
		{"sp-indirect", `g=keylink; x=g; echo m >> "${!x}"`, "block"},
		{"sp-case-mod", `f=KEYLINK; echo m >> "${f,,}"`, "block"},
		{"sp-last-arg", `echo keylink >/dev/null; echo m >> "./$_"`, "block"},
		{"sp-install-final", `f=a.txt; f=keylink; install -m 644 b.txt "$f"`, "block"},
		{"sp-second-write", `f=a.txt; echo m >> "$f"; f=keylink; echo m >> "$f"`, "block"},
		{"sb-heredoc", "f=keylink; f=a.txt; cat > \"$f\" <<EOF\nx\nEOF", "allow"},
		{"sb-clobber", `f=keylink; f=a.txt; echo m >| "$f"`, "allow"},
		{"sb-all", `f=keylink; f=a.txt; echo m &>> "$f"`, "allow"},
		{"sb-bg-write", `f=keylink; f=a.txt; echo m >> "$f" &`, "allow"},
		{"sb-and-benign", `f=a.txt; [ -d ordinary ] && f=b.txt; echo m >> "$f"`, "allow"},
		{"sb-case-benign", `f=a.txt; case x in x) f=b.txt;; esac; echo m >> "$f"`, "allow"},
		{"sb-time-benign", `f=a.txt; time f=b.txt; echo m >> "$f"`, "allow"},
		{"sb-printf-benign", `f=a.txt; printf -vf %s b.txt; echo m >> "$f"`, "allow"},
		{"g418-compact", "HOME=" + project + "; " + hp3r4IfDefaults(10, `echo m >> ~/keylink`), "block"},
		{"g418-compact-benign", "HOME=" + project + "; " + hp3r4IfDefaults(10, `echo m >> ~/out.txt`), "allow"},
		{"g418-plain", "HOME=" + project + "; echo m >> ~/keylink", "block"},
		{"g418-plain-benign", "HOME=" + project + "; echo m >> ~/out.txt", "allow"},
		{"g418-pwd", `HOME=$PWD; echo m >> ~/keylink`, "block"},
		{"g418-pwd-benign", `HOME=$PWD; echo m >> ~/out.txt`, "allow"},
		{"g418-var", "HOME=" + project + "; f=~/keylink; echo m >> \"$f\"", "block"},
		{"g418-printf", `printf -v HOME %s "$PWD"; echo m >> ~/keylink`, "block"},
		{"g418-cd", "HOME=" + project + "; cd ~ && echo m >> keylink", "block"},
		{"g397-copy-dir", `for f in a.txt b.txt; do cp $f copy/$f; done; echo done > report.txt`, "allow"},
		{"g397-build", `for f in a.txt b.txt; do cp $f build/; done; echo done > report.txt`, "allow"},
		{"lc-dest-dir", `for f in a.txt b.txt; do cp a.txt "copy/$f"; done`, "allow"},
		{"lc-keyname-folder", `for f in keylink; do cp a.txt "copy/$f"; done`, "allow"},
		{"lc-suffix", `for f in keylink; do cp a.txt "$f.bak"; done`, "allow"},
		{"lc-twins-glob", `for f in out2.txt out3.txt; do cp a.txt $f; done`, "allow"},
		{"lc-source-link", `for f in out2.txt; do cp keylink "$f"; done`, "allow"},
		{"lc-protected-subpath", `for d in sshlink; do cp a.txt "$d/authorized_keys"; done`, "block"},
		{"lc-cd-prefix", `cd . && for f in out2.txt keylink; do cp a.txt $f; done`, "block"},
		{"lc-second-stmt", `true; for f in out2.txt keylink; do cp a.txt $f; done`, "block"},
		{"lc-mv", `for f in out2.txt keylink; do mv a.txt $f; done`, "block"},
		{"lc-two-body", `for f in out2.txt keylink; do cp a.txt $f; echo ok; done`, "block"},
		{"lc-cp-opt", `for f in out2.txt keylink; do cp -f a.txt $f; done`, "block"},
	}
}

func TestReviewHP6Probe(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, link := range []struct{ target, name string }{{"../.ssh/authorized_keys", "keylink2"}, {"../.ssh", "sshlink"}} {
		if err := os.Symlink(link.target, filepath.Join(f.project, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range []string{"copy", "build"} {
		if err := os.MkdirAll(filepath.Join(f.project, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"a.txt": "x\n", "b.txt": "x\n", "out.txt": "x\n", "names.txt": "keylink\n"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := hp6ProbeRows(f.project)
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("hp6/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		t.Logf("HP6PRROW %s | %s | want %s", call.name, call.verdict, rows[i/4].want)
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
	_ = strings.TrimSpace
}
