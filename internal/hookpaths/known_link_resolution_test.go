// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

func TestKnownLinkTargetsResolveFromCWDAndPythonHome(t *testing.T) {
	home, cwd := "/home/synthetic", "/home/synthetic/workspace"
	command := `ln -s "$(cd;pwd)/$(printf '\x2e\x73\x73\x68')" /tmp/alias && echo marker >> /tmp/alias/authorized_keys`
	links := CommandLinks("Bash", command, cwd, home)
	target, ok := links.Target("/tmp/alias/authorized_keys")
	if !ok || target != home+"/.ssh/authorized_keys" || !links.Known() {
		t.Fatalf("cwd-resolved link target = %q, known=%t target-ok=%t", target, links.Known(), ok)
	}
	for _, expr := range []struct{ source, want string }{
		{`os.path.join(os.path.expanduser(chr(126)),'.ss'+'h','authorized_'+'keys')`, home + "/.ssh/authorized_keys"},
		{`os.environ['HOME']+'/.ssh/authorized_'+'keys'`, home + "/.ssh/authorized_keys"},
	} {
		got, resolved := pythonPathExpression(expr.source, home)
		if !resolved || got != expr.want {
			t.Fatalf("python path expression %q = %q, resolved=%t; want %q", expr.source, got, resolved, expr.want)
		}
	}
	python := `import os,sys; os.symlink(os.environ['HOME']+'/.ssh/authorized_'+'keys','/tmp/python-alias')`
	links = CommandLinks("Bash", `python3 -c "`+python+`" && echo marker >> /tmp/python-alias`, cwd, home)
	target, ok = links.Target("/tmp/python-alias")
	if !ok || target != home+"/.ssh/authorized_keys" || !links.Known() {
		t.Fatalf("python-resolved link target = %q, known=%t target-ok=%t", target, links.Known(), ok)
	}
}
