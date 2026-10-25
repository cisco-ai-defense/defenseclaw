// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestInfraSetAtomicNoisePosture(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		activeHome string
		present    []string
		absent     []string
		strictOnly bool
	}{
		{
			name: "generic sudoers mutation", command: `printf configured > /etc/sudoers.d/opsbot`,
			present: []string{"PATH-ETC-SUDOERS"}, strictOnly: true,
		},
		{
			name:    "exact unrestricted sudoers grant",
			command: `printf '%s\n' 'opsbot ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/opsbot`,
			present: []string{"privilege.sudoers_unrestricted_nopasswd"},
		},
		{
			name: "targeted shadow account check", command: `grep -q '^opsbot:' /etc/shadow`,
			absent: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "full shadow read", command: `cat /etc/shadow`,
			present: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "shadow mutation", command: `sed -i 's/^opsbot:/disabled:/' /etc/shadow`,
			present: []string{"PATH-ETC-SHADOW"},
		},
		{
			name: "ordinary ssh identity use", command: `ssh -i /home/alice/.ssh/id_ed25519 server.example`,
			activeHome: "/home/alice", absent: []string{"PATH-SSH-KEY"},
		},
		{
			name: "ssh private key content read", command: `cat /home/alice/.ssh/id_ed25519`,
			activeHome: "/home/alice", present: []string{"PATH-SSH-KEY"},
		},
		{
			name: "ordinary ssh metadata mutation", command: `touch /home/alice/.ssh/known_hosts`,
			activeHome: "/home/alice", absent: []string{"PATH-SSH-DIR"},
		},
		{
			name: "authorized keys mutation", command: `printf '%s\n' 'ssh-ed25519 AAAAfixture' >> /home/alice/.ssh/authorized_keys`,
			activeHome: "/home/alice", present: []string{"persistence.ssh_authorized_keys_command"},
		},
		{
			name: "ordinary sudo command", command: `sudo apt-get update`,
			absent: []string{"CMD-SUDO"},
		},
		{
			name: "sudo privilege discovery", command: `sudo -l`,
			present: []string{"CMD-SUDO"}, strictOnly: true,
		},
		{
			name: "sudo elevated shell", command: `sudo -u root /bin/bash`,
			present: []string{"CMD-SUDO"}, strictOnly: true,
		},
		{
			name: "crontab install", command: `crontab /tmp/jobs`,
			present: []string{"CMD-CRONTAB"}, strictOnly: true,
		},
	}

	for _, profile := range []string{"default", "permissive", "strict"} {
		profile := profile
		t.Run(profile, func(t *testing.T) {
			const connector = "infraset-noise"
			installToolCallCorpusProfileConnector(t, connector, profile)
			for _, test := range tests {
				test := test
				t.Run(test.name, func(t *testing.T) {
					input := actionfacts.Input{
						Tool: "shell", Command: test.command, CWD: "/repo",
						ActiveHome: test.activeHome, DialectHint: actionfacts.DialectPOSIX,
					}
					ids := findingIDs(dispatchTrustedAction(t.Context(), trustedActionRequest{
						Input: input, LegacyText: test.command, Connector: connector,
						EnforcementCapable: true,
					}))
					for _, ruleID := range test.present {
						want := !test.strictOnly || profile == "strict"
						if got := slices.Contains(ids, ruleID); got != want {
							t.Fatalf("%s present=%t, want %t; findings=%v", ruleID, got, want, ids)
						}
					}
					for _, ruleID := range test.absent {
						if slices.Contains(ids, ruleID) {
							t.Fatalf("unexpected %s finding: %v", ruleID, ids)
						}
					}
				})
			}
		})
	}
}

func TestBalancedMKFSRemainsVisibleAndNonblocking(t *testing.T) {
	const connector = "infraset-mkfs"
	installToolCallCorpusProfileConnector(t, connector, "default")
	input := actionfacts.Input{
		Tool: "shell", Command: `mkfs.ext4 /dev/sda`, CWD: "/repo",
		DialectHint: actionfacts.DialectPOSIX,
	}
	findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
		Input: input, LegacyText: input.Command, Connector: connector,
		EnforcementCapable: true,
	})
	matched := findingWithID(findings, "CMD-MKFS")
	if matched == nil {
		t.Fatalf("CMD-MKFS finding missing: %+v", findings)
	}
	if matched.Severity != "HIGH" {
		t.Fatalf("balanced CMD-MKFS severity=%q, want HIGH alert posture", matched.Severity)
	}
	if matched.contributesToEnforcement() {
		t.Fatalf("balanced CMD-MKFS unexpectedly contributes to enforcement: %+v", matched)
	}
}

func TestBuiltInProfilesRetainDestructiveEvidenceWithoutUniversalBlocking(t *testing.T) {
	tests := []struct {
		name, command, ruleID string
	}{
		{"filesystem format", "mkfs.ext4 /dev/sda", "CMD-MKFS"},
		{"device wipe", "blkdiscard /dev/sdb", "CMD-DEVICE-WIPE"},
		{"access control weakening", "chmod 0777 /etc/sudoers", "CMD-CHMOD-WORLD"},
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		for _, test := range tests {
			t.Run(profile+"/"+test.name, func(t *testing.T) {
				connector := "destructive-evidence-" + profile
				installToolCallCorpusProfileConnector(t, connector, profile)
				input := actionfacts.Input{Tool: "shell", Command: test.command, CWD: "/repo"}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: test.command, Connector: connector,
					EnforcementCapable: true,
				})
				matched := findingWithID(findings, test.ruleID)
				if matched == nil {
					t.Fatalf("%s finding missing: %+v", test.ruleID, findings)
				}
				if matched.contributesToEnforcement() {
					t.Fatalf("%s unexpectedly contributes to enforcement: %+v", test.ruleID, matched)
				}
			})
		}
	}
}

func TestStrictRoutineCommandPrecision(t *testing.T) {
	const connector = "strict-routine-command-precision"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	for _, command := range []string{
		"nc -lvp 5432",
		"git init /tmp/repo && git -C /tmp/repo remote add origin https://example.invalid/repo.git",
		"curl https://api.invalid/data | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
		"kubectl -n production exec pod/api -- curl -fsS http://127.0.0.1:8080/healthz",
		"rg -n history internal/gateway && git -C project status",
	} {
		input := actionfacts.Input{Tool: "shell", Command: command, CWD: "/repo"}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: command, Connector: connector,
			EnforcementCapable: true,
		})
		for _, noisyID := range []string{
			"CMD-NETCAT-LISTEN", "source.git_remote_tamper", "CMD-PIPE-CURL",
			"lateral.workload_exec", "integrity.history_tamper",
		} {
			if findingWithID(findings, noisyID) != nil {
				t.Fatalf("command %q emitted %s: %+v", command, noisyID, findings)
			}
		}
	}
}

func TestNetcatListenerUsesExposureTaxonomy(t *testing.T) {
	rulePack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "strict"))
	for _, file := range rulePack.RuleFiles {
		for _, rule := range file.Rules {
			if rule.ID != "CMD-NETCAT-LISTEN" {
				continue
			}
			if rule.Title != "Netcat network-listener exposure" ||
				!slices.Contains(rule.Tags, "listener") || slices.Contains(rule.Tags, "reverse-shell") {
				t.Fatalf("unexpected listener taxonomy: %+v", rule)
			}
			return
		}
	}
	t.Fatal("CMD-NETCAT-LISTEN missing")
}

func TestAuthorizedKeysShellDirectoryResolution(t *testing.T) {
	posixInput := actionfacts.Input{
		CWD: "/repo", ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
	}
	windowsInput := actionfacts.Input{CWD: `C:\repo`, ActiveHome: `C:\Users\alice`}
	tests := []struct {
		name, current, directory, want string
		ok, windowsOnly                bool
		input                          actionfacts.Input
	}{
		{"home", "", "~", "/home/alice", true, false, posixInput},
		{"home ssh", "", "~/.ssh", "/home/alice/.ssh", true, false, posixInput},
		{"absolute", "", "/home/alice/.ssh", "/home/alice/.ssh", true, false, posixInput},
		{"relative to home", "/home/alice", ".ssh", "/home/alice/.ssh", true, false, posixInput},
		{"relative to cwd", "", "project/../notes", "/repo/notes", true, false, posixInput},
		{"relative base unknown", "relative", ".ssh", "", false, false, posixInput},
		// A POSIX-spelled command on Windows keeps the native home and CWD.
		{"native home ssh", "", "~/.ssh", `C:\Users\alice\.ssh`, true, true, windowsInput},
		{"native expanded home", "", `C:\Users\alice/.ssh`, `C:\Users\alice\.ssh`, true, true, windowsInput},
		{"relative to native cwd", "", ".ssh", `C:\repo\.ssh`, true, true, windowsInput},
	}
	// On Linux, simulate native Windows path operations so this test still
	// catches an accidental fallback to host paths for a POSIX command.
	windowsPaths := authorizedKeysDirectoryPaths{
		isAbs: func(value string) bool { return strings.HasPrefix(value, `C:\`) },
		join:  func(parts ...string) string { return strings.Join(parts, `\`) },
		clean: func(value string) string { return strings.ReplaceAll(value, "/", `\`) },
	}
	resolvers := []struct {
		name      string
		simulated bool
		resolve   func(actionfacts.Input, string, string) (string, bool)
	}{
		{"host", false, resolveAuthorizedKeysShellDirectory},
		{"simulated Windows host", true, func(input actionfacts.Input, current, directory string) (string, bool) {
			return resolveAuthorizedKeysShellDirectoryWithNative(input, current, directory, windowsPaths)
		}},
	}
	for _, resolver := range resolvers {
		for _, test := range tests {
			if test.windowsOnly && !resolver.simulated {
				continue
			}
			t.Run(resolver.name+"/"+test.name, func(t *testing.T) {
				got, ok := resolver.resolve(test.input, test.current, test.directory)
				if got != test.want || ok != test.ok {
					t.Fatalf("resolved directory = %q, %t; want %q, %t", got, ok, test.want, test.ok)
				}
			})
		}
	}
}

// TestHomeSpelledAuthorizedKeysWriteBlocks pins GAP-0892/0894/0896 on the
// default pack. A lone `echo k >> ~/.ssh/authorized_keys` lost its blocking
// finding because the tilde rewrite gave the path fact its "~" spelling back
// but not the redirect target, so the owner no longer tied the redirect to
// the path; every spelling and writer must block alike, and reads stay quiet.
func TestHomeSpelledAuthorizedKeysWriteBlocks(t *testing.T) {
	const connector = "home-spelled-authorized-keys"
	installToolCallCorpusProfileConnector(t, connector, "default")
	const rule = "persistence.ssh_authorized_keys_command"
	t.Setenv("PYTHONPATH", "")
	t.Setenv("PYTHONHOME", "")
	pythonCWD := t.TempDir()
	shadowCWD := t.TempDir()
	if err := os.WriteFile(filepath.Join(shadowCWD, "subprocess.py"), []byte("# local module\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, command, cwd, home string
		write                    bool
	}{
		{"redirect", `echo dccert-block-marker >> ~/.ssh/authorized_keys`, "", "", true},
		{"home variable", `echo dccert-block-marker >> "$HOME/.ssh/authorized_keys"`, "", "", true},
		{"absolute", `echo dccert-block-marker >> /home/alice/.ssh/authorized_keys`, "", "", true},
		{"quoted suffix", `echo dccert-block-marker >> ~/".ssh/authorized_keys"`, "", "", true},
		{"mkdir and redirect", `mkdir -p ~/.ssh && echo dccert-block-marker >> ~/.ssh/authorized_keys`, "", "", true},
		{"tee", `echo dccert-block-marker | tee -a ~/.ssh/authorized_keys`, "", "", true},
		{"install", `install -m 600 marker.pub ~/.ssh/authorized_keys`, "", "", true},
		{"copy to second keys file", `cp marker.pub ~/.ssh/authorized_keys2`, "", "", true},
		{"move to keys file", `mv marker.pub ~/.ssh/authorized_keys`, "", "", true},
		{"sed in place", `sed -i "$a dccert-block-marker" ~/.ssh/authorized_keys`, "", "", true},
		{"directory change", `cd ~/.ssh && echo dccert-block-marker >> authorized_keys`, "", "", true},
		{"home directory change", `cd ~ && echo dccert-block-marker >> .ssh/authorized_keys`, "", "", true},
		// A quoted program word is not a plain literal (GAP-1530).
		{"quoted directory change", `"cd" ~/.ssh && echo dccert-block-marker >> authorized_keys`, "", "", true},
		{"quoted program then write", `"$PY" -V && echo dccert-block-marker >> notes.txt`, "", "", false},
		{"assigned path", `D=~/.ssh; echo dccert-block-marker >> "$D/authorized_keys"`, "", "", true},
		{"nested shell", `sh -c 'echo dccert-block-marker >> "$HOME/.ssh/authorized_keys"'`, "", "", true},
		{"normalized path", `echo dccert-block-marker >> ~//.ssh//authorized_keys`, "", "", true},
		{"here string", `cat <<< dccert-block-marker >> ~/.ssh/authorized_keys`, "", "", true},
		{"dd output", `echo dccert-block-marker | dd of=$HOME/.ssh/authorized_keys oflag=append conv=notrunc`, "", "", true},
		{"perl no close", `perl -e 'open(F, ">>", "$ENV{HOME}/.ssh/authorized_keys"); print F "dccert-block-marker\n"'`, "", "", true},
		{"apostrophe home tilde", `echo dccert-block-marker >> ~/.ssh/authorized_keys`, "/home/o'brien/proj", "/home/o'brien", true},
		{"apostrophe home variable", `echo dccert-block-marker >> $HOME/.ssh/authorized_keys`, "/home/o'brien/proj", "/home/o'brien", true},
		{"glob path", `echo dccert-block-marker | tee -a ~/.ssh/authorized_k*`, "", "", true},
		{"python write", `python3 -c 'import pathlib; p = pathlib.Path.home() / ".ssh" / "authorized_keys"; p.write_text(p.read_text() + "dccert-block-marker\n")'`, "", "", true},
		{"python open append", `python3 -c "import os; open(os.path.expanduser('~/.ssh/authorized_keys'), 'a').write('dccert-block-marker\n')"`, "", "", true},
		{"python Path home", `python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; p.write_text(p.read_text() + 'dccert-block-marker\n')"`, "", "", true},
		{"python Path expanduser", `python3 -c "from pathlib import Path; Path('~/.ssh/authorized_keys').expanduser().write_text('dccert-block-marker\n')"`, "", "", true},
		// A docstring, a comment, string text or f-string literal text that
		// spells the write may run: a module the agent's import path supplies
		// (PYTHONPATH, a sitecustomize, a shadowed import) can exec
		// __main__.__doc__ or any part of sys.orig_argv, whatever the program
		// imports, and the gateway does not see that path. The gateway's own
		// clean environment and a clean working directory prove nothing, so
		// every such string counts as code (GAP-1199 stays a false block).
		{"python docstring write", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python exec docstring write", `python3 -c 'from pathlib import Path; exec("""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")""")'`, "", "", true},
		// An f-string runs its fields: the write in one is not a docstring.
		{"python f-string write", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{p.write_text("dccert-block-marker")}"""'`, "", "", true},
		{"python f-string same quotes write", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""{"""a""" + str(p.write_text("dccert-block-marker"))}"""'`, "", "", true},
		{"python docstring write beside an f-string", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print(f"{1}")'`, "", "", true},
		{"python f-string literal text write", `python3 -c "p=Path.home()/'.ssh'/'authorized_keys'; f'''p.write_text('sample')'''"`, "", "", true},
		{"python f-string literal text write beside a pathlib import", `python3 -c "from pathlib import Path; p=Path.home()/'.ssh'/'authorized_keys'; f'''p.write_text('sample')'''"`, "", "", true},
		{"python f-string text beside a write field", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; f"""note: {p.write_text("dccert-block-marker")}"""'`, "", "", true},
		{"python exec comment beside a docstring write", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")  # no exec here'`, "", "", true},
		{"python exec word in a docstring write", `python3 -c '"""exec this: p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python getattr exec docstring write", `python3 -c 'from pathlib import Path; getattr(__builtins__, "ex" + "ec")("""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")""")'`, "", "", true},
		{"python child interpreter docstring write", `python3 -c 'import subprocess; subprocess.run(["python3", "-c", """from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""])'`, "", "", true},
		{"python unused subprocess import beside a docstring write", `python3 -c 'import subprocess; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python shadowed subprocess import beside a docstring write", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; import subprocess; print("ok")'`, shadowCWD, "", true},
		{"python import path override beside a docstring write", `PYTHONPATH=` + shadowCWD + ` python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; import subprocess; print("ok")'`, pythonCWD, "", true},
		{"python unused aliased imports beside a docstring write", `python3 -c 'import subprocess as sp, ctypes; from os import system as run, popen; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python unused preloaded imports beside a docstring write", `python3 -c 'from os import system as run, popen; import sys; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python shadowable module import after a docstring write", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; import helper'`, "", "", true},
		{"python fullwidth exec of a string write", `python3 -c 'ｅｘｅｃ("""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")""")'`, "", "", true},
		{"python used json import beside a docstring write", `python3 -c '"""p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; import json; print(json.dumps(1))'`, "", "", true},
		{"python used aliased import beside a docstring write", `python3 -c 'import subprocess as sp; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; sp.run(["true"])'`, "", "", true},
		{"python star import beside a docstring write", `python3 -c 'from subprocess import *; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print("ok")'`, "", "", true},
		{"python module docstring exec", `python3 -c '"""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; exec(__doc__)'`, "", "", true},
		{"python docstring written to a module and imported", `python3 -c 'open("m.py", "w").write("""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""); import m'`, "", "", true},
		{"python posix_spawn child docstring write", `python3 -c 'import os; os.posix_spawn("/usr/bin/python3", ["python3", "-c", """from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""], {})'`, "", "", true},
		{"python timeit docstring write", `python3 -c 'import timeit; timeit.timeit("""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")""", number=1)'`, "", "", true},
		{"python one-line f-string text write", `python3 -c 'p = Path.home() / ".ssh" / "authorized_keys"; print(f"p.write_text(42)")'`, "", "", true},
		{"python one-line f-string text write beside a pathlib import", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; print(f"p.write_text(42)")'`, "", "", true},
		{"python string text write", `python3 -c 'p = Path.home() / ".ssh" / "authorized_keys"; print("p.write_text(42)")'`, "", "", true},
		{"python string text write beside a pathlib import", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; print("p.write_text(42)")'`, "", "", true},
		{"python string in an f-string field write", `python3 -c "p = Path.home() / '.ssh' / 'authorized_keys'; print(f'{\"p.write_text(42)\"}')"`, "", "", true},
		{"python string in an f-string field write beside a pathlib import", `python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; print(f'{\"p.write_text(42)\"}')"`, "", "", true},
		{"python one-line f-string field write", `python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; print(f'{p.write_text(\"k\")}')"`, "", "", true},
		{"python string text expanduser write", `python3 -c "print('Path(\"~/.ssh/authorized_keys\").expanduser().write_text(\"k\")')"`, "", "", true},
		// f"{p=}" does not bind p again.
		{"python format spec text write", `python3 -c 'p = Path.home() / ".ssh" / "authorized_keys"; print(f"{1:p.write_text(42)}")'`, "", "", true},
		{"python format spec text write beside a pathlib import", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; print(f"{1:p.write_text(42)}")'`, "", "", true},
		{"python format spec field write", `python3 -c "from pathlib import Path; p = Path.home() / '.ssh' / 'authorized_keys'; print(f'{1:{p.write_text(\"k\")}}')"`, "", "", true},
		{"python self-documenting field then write", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; print(f"{p=}"); p.write_text("k")'`, "", "", true},
		{"python ordinary variable beside a docstring write", `python3 -c 'source = 1; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print(source)'`, "", "", true},
		{"python ordinary names beside a docstring write", `python3 -c 'doc = copy_count = 1; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print(doc, copy_count)'`, "", "", true},
		{"python local alias of exec docstring write", `python3 -c 'source = exec; source("""from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")""")'`, "", "", true},
		{"python imported source beside a docstring write", `python3 -c 'from inspect import getsource as source; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print(source)'`, "", "", true},
		{"python star import and a variable beside a docstring write", `python3 -c 'from os import *; source = 1; """p = Path.home() / ".ssh" / "authorized_keys"; p.write_text("example")"""; print(source)'`, "", "", true},
		{"python exec string text write", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; exec("p.write_text(42)")'`, "", "", true},
		// A path bound again before the write is not the keys file (GAP-1299).
		{"python reassigned path", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p = Path("notes.txt"); p.write_text("example")'`, "", "", false},
		{"python reassigned pathlib path", `python3 -c "import pathlib; p = pathlib.Path.home() / '.ssh' / 'authorized_keys'; p = pathlib.Path('notes.txt'); p.write_text('example')"`, "", "", false},
		// Only a binding in code to another literal path counts: string text, a
		// self-documenting f-string field, p = p, the keys file again or a loop
		// target may still be the keys file.
		{"python rebinding spelled in string text", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; print("p = Path(1)"); p.write_text("k")'`, "", "", true},
		{"python rebinding spelled in a docstring", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; """p = Path("notes.txt")"""; p.write_text("k")'`, "", "", true},
		{"python path bound to itself", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p = p; p.write_text("k")'`, "", "", true},
		{"python path bound to the keys file again", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p = Path("~/.ssh/authorized_keys").expanduser(); p.write_text("k")'`, "", "", true},
		{"python path bound to a keys literal", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; p = Path("/home/alice/.ssh/authorized_keys"); p.write_text("k")'`, "", "", true},
		{"python conditional rebinding", "python3 -c 'from pathlib import Path; p = Path.home() / \".ssh\" / \"authorized_keys\";\nif False:\n    p = Path(\"notes.txt\")\np.write_text(\"k\")'", "", "", true},
		{"python attribute rebinding", `python3 -c 'from pathlib import Path; import types; x = types.SimpleNamespace(); p = Path.home() / ".ssh" / "authorized_keys"; x.p = Path("notes.txt"); p.write_text("k")'`, "", "", true},
		{"python loop target path", `python3 -c 'from pathlib import Path; p = Path.home() / ".ssh" / "authorized_keys"; [p.write_text("k") for p in [p]]'`, "", "", true},
		{"python append absolute", `python3 -c 'open("/home/alice/.ssh/authorized_keys", "a").write("dccert-block-marker")'`, "", "", true},
		{"python home append", `python -c 'open("$HOME/.ssh/authorized_keys", "a").write("dccert-block-marker")'`, "", "", true},
		{"perl write", `perl -e 'open(F, ">>", "$ENV{HOME}/.ssh/authorized_keys"); print F "dccert-block-marker\n"; close(F)'`, "", "", true},
		{"perl append absolute", `perl -e 'open(F, ">>", "/home/alice/.ssh/authorized_keys"); print F "dccert-block-marker"'`, "", "", true},
		{"ruby append", `ruby -e 'File.open("~/.ssh/authorized_keys", "a") { |f| f.write("dccert-block-marker") }'`, "", "", true},
		{"node append", `node -e 'require("fs").appendFileSync("/home/alice/.ssh/authorized_keys", "dccert-block-marker")'`, "", "", true},
		{"node write target", `node -e 'require("fs").writeFileSync("/home/alice/.ssh/authorized_keys", "dccert-block-marker")'`, "", "", true},
		{"node write data path", `node -e 'require("fs").writeFileSync("/tmp/report.txt", "~/.ssh/authorized_keys")'`, "", "", true},
		{"node append log text", `node -e 'require("fs").appendFileSync("/tmp/log", "/home/alice/.ssh/authorized_keys")'`, "", "", true},
		{"python open data path", `python3 -c 'open("/tmp/report.txt", "a").write("~/.ssh/authorized_keys")'`, "", "", true},
		{"find exec", `find ~/.ssh -name authorized_keys -exec sh -c 'echo dccert-block-marker >> "$1"' _ {} \;`, "", "", true},
		{"decoded shell", `echo ZWNobyAic3NoLWVkMjU1MTkgQUFBQXVjY21hcmtlciB1Y2NAdGVzdCIgPj4gfi8uc3NoL2F1dGhvcml6ZWRfa2V5cw== | base64 -d | sh`, "", "", true},
		{"symlink write", `ln -sf ~/.ssh/authorized_keys ./keys.link && echo dccert-block-marker >> ./keys.link`, "", "", true},
		{"curl output", `curl -s -o ~/.ssh/authorized_keys http://127.0.0.1:9/marker.pub; echo rc=$?`, "", "", true},
		{"wget output", `wget -O ~/.ssh/authorized_keys https://example.com/marker.pub`, "", "", true},
		{"wget compact output", `wget -qO ~/.ssh/authorized_keys https://example.com/marker.pub`, "", "", true},
		{"no-op truncate", `: > ~/.ssh/authorized_keys`, "", "", true},
		{"bare truncate", `> ~/.ssh/authorized_keys`, "", "", true},
		// Static redirect ownership is independent of the program's operand grammar.
		{"hostname redirect", `hostname > ~/.ssh/authorized_keys`, "", "", true},
		{"date redirect", `date > /home/alice/.ssh/authorized_keys`, "", "", true},
		{"echo redirect", `echo marker > ~/.ssh/authorized_keys`, "", "", true},
		{"unknown program redirect", `mytool --flag > ~/.ssh/authorized_keys`, "", "", true},
		{"environment prefix redirect", `FOO=1 hostname > ~/.ssh/authorized_keys`, "", "", true},
		{"directory prefix redirect", `cd /tmp && hostname > ~/.ssh/authorized_keys`, "", "", true},
		{"directory relative redirect", `cd ~/.ssh && hostname > authorized_keys`, "", "", true},
		{"quoted redirect", `hostname > "/home/alice/.ssh/authorized_keys"`, "", "", true},
		{"home variable redirect", `hostname > "$HOME/.ssh/authorized_keys"`, "", "", true},
		{"braced home redirect", `hostname > "${HOME}/.ssh/authorized_keys2"`, "", "", true},
		{"descriptor redirect", `hostname 1> ~/.ssh/authorized_keys`, "", "", true},
		{"error descriptor redirect", `hostname 2> ~/.ssh/authorized_keys`, "", "", true},
		{"combined redirect", `hostname &> ~/.ssh/authorized_keys`, "", "", true},
		{"combined append", `hostname &>> ~/.ssh/authorized_keys`, "", "", true},
		{"append redirect", `hostname >> ~/.ssh/authorized_keys`, "", "", true},
		{"clobber redirect", `hostname >| ~/.ssh/authorized_keys`, "", "", true},
		{"read redirect", `hostname < ~/.ssh/authorized_keys`, "", "", true},
		{"error log redirect", `hostname 2> /tmp/err`, "", "", false},
		{"known hosts redirect", `hostname > ~/.ssh/known_hosts`, "", "", false},
		{"ssh config redirect", `hostname > ~/.ssh/config`, "", "", false},
		{"other ssh file redirect", `hostname 2> ~/.ssh/other`, "", "", false},
		{"other home file redirect", `hostname > /home/alice/notes.txt`, "", "", false},
		{"structured Write", `{"file_path":"/home/alice/.ssh/authorized_keys","content":"key"}`, "", "", true},
		{"structured Edit", `{"file_path":"/home/alice/.ssh/authorized_keys","old_string":"a","new_string":"b"}`, "", "", true},
		{"structured MultiEdit", `{"file_path":"/home/alice/.ssh/authorized_keys","edits":[{"old_string":"a","new_string":"b"}]}`, "", "", true},
		{"structured Write relative", `{"file_path":"../.ssh/authorized_keys","content":"key"}`, "/home/alice/proj", "", true},
		{"structured Write tilde", `{"file_path":"~/.ssh/authorized_keys","content":"key"}`, "", "", true},
		{"structured Write ordinary", `{"file_path":"/home/alice/proj/notes.md","content":"key"}`, "", "", false},
		{"symlink arbitrary name", `ln -s ~/.ssh/authorized_keys ~/project/key-target && echo dccert-block-marker >> ~/project/key-target`, "", "", true},
		{"symlink quoted name", `ln -sf /home/alice/.ssh/authorized_keys './key target' && echo dccert-block-marker >> './key target'`, "", "", true},
		{"sudo sh append", `sudo sh -c 'echo dccert-block-marker >> /home/alice/.ssh/authorized_keys'`, "", "", true},
		{"sudo bash append", `sudo bash -c 'echo dccert-block-marker >> /root/.ssh/authorized_keys'`, "", "", true},
		{"windows command", `powershell -NoProfile -Command Add-Content -Path C:\Users\alice\.ssh\authorized_keys -Value dccert-block-marker`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows home", `pwsh -c "Set-Content -Path $HOME/.ssh/authorized_keys -Value dccert-block-marker"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows spaced home", `powershell -Command "Add-Content -Path 'C:\Users\Alice Smith\.ssh\authorized_keys' -Value dccert-block-marker"`, `C:/Users/Alice Smith/project`, `C:/Users/Alice Smith`, true},
		{"windows admin keys", `powershell.exe -Command "Add-Content -Path C:/ProgramData/ssh/administrators_authorized_keys -Value dccert-block-marker"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows admin out file", `pwsh -c "'dccert-block-marker' | Out-File -Append C:/ProgramData/ssh/administrators_authorized_keys"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows cmd quoted", `cmd /c "echo dccert-block-marker >> %USERPROFILE%\.ssh\authorized_keys"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows cmd unquoted", `cmd /c echo dccert-block-marker >> %USERPROFILE%\.ssh\authorized_keys`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows home drive", `cmd /c "echo dccert-block-marker >> %HOMEDRIVE%%HOMEPATH%\.ssh\authorized_keys"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows named OutFile", `"dccert-block-marker" | Out-File -Append -FilePath "$HOME\.ssh\authorized_keys"`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"windows Git Bash path", `echo dccert-block-marker >> /c/Users/alice/.ssh/authorized_keys`, `C:/Users/alice/project`, `C:/Users/alice`, true},
		{"cat", `cat ~/.ssh/authorized_keys`, "", "", false},
		{"python read", `python3 -c 'open("/home/alice/.ssh/authorized_keys", "r").read()'`, "", "", true},
		{"python separate write", `python3 -c 'open("/home/alice/.ssh/authorized_keys", "r"); open("/tmp/other", "a")'`, "", "", true},
		{"python printed write", `python3 -c 'print("open(\"/home/alice/.ssh/authorized_keys\", \"a\")")'`, "", "", true},
		{"ruby read", `ruby -e 'File.open("~/.ssh/authorized_keys", "r") { |f| puts f.read }'`, "", "", true},
		{"node read", `node -e 'require("fs").readFileSync("/home/alice/.ssh/authorized_keys")'`, "", "", true},
		{"symlink read", `ln -s ~/.ssh/authorized_keys ./reader.link && cat ./reader.link`, "", "", true},
		{"count", `grep -c ssh-ed25519 ~/.ssh/authorized_keys`, "", "", true},
		{"metadata", `ls -l ~/.ssh/authorized_keys`, "", "", false},
		{"diff", `diff ~/.ssh/authorized_keys marker.pub | head -5`, "", "", true},
		{"line count", `wc -l ~/.ssh/authorized_keys`, "", "", true},
		{"ordinary count", `grep -c ssh-ed25519 report.txt`, "", "", false},
		{"ordinary diff", `diff report.txt marker.pub | head -5`, "", "", false},
		{"ordinary line count", `wc -l report.txt`, "", "", false},
		{"local copy", `cp ~/.ssh/authorized_keys /var/tmp/authorized-keys-copy.txt`, "", "", true},
		{"mention", `echo "check ~/.ssh/authorized_keys" > notes.txt`, "", "", true},
		{"echo path to report", `echo ~/.ssh/authorized_keys > /tmp/report.txt`, "", "", true},
	}
	for _, test := range tests {
		cwd, home := test.cwd, test.home
		if cwd == "" {
			cwd = "/repo"
			if strings.HasPrefix(test.name, "python ") {
				cwd = pythonCWD
			}
		}
		if home == "" {
			home = "/home/alice"
		}
		args := []byte(`{"command":` + strconv.Quote(test.command) + `}`)
		tool := "Bash"
		if strings.HasPrefix(test.name, "structured ") {
			tool = strings.Fields(test.name)[1]
			args = []byte(test.command)
		}
		input := actionfacts.Input{
			Tool: tool, Args: args, CWD: cwd,
			ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
		}
		if test.name == "windows named OutFile" {
			input.DialectHint = actionfacts.DialectPowerShell
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: string(args), Connector: connector,
			EnforcementCapable: true,
		})
		wantAction := guardrailActionAllow
		if test.write {
			wantAction = guardrailActionBlock
		}
		if got := buildVerdict(findings, "tool_call").Action; got != wantAction {
			t.Errorf("%s: verdict %s, want %s", test.name, got, wantAction)
		}
		if !test.write {
			if len(findings) != 0 {
				t.Errorf("%s: unexpected findings %v", test.name, findingIDs(findings))
			}
			continue
		}
		enforced := 0
		for _, finding := range findings {
			if finding.contributesToEnforcement() {
				enforced++
				if finding.RuleID != rule || finding.Severity != "CRITICAL" {
					t.Errorf("%s: enforced finding %s (%s), want %s (CRITICAL)",
						test.name, finding.RuleID, finding.Severity, rule)
				}
			}
		}
		if enforced != 1 {
			t.Errorf("%s: findings %v, want one enforced %s", test.name, findingIDs(findings), rule)
		}
	}
	t.Run("existing symlink", func(t *testing.T) {
		home := t.TempDir()
		project := filepath.Join(home, "project")
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(project, 0o700); err != nil {
			t.Fatal(err)
		}
		keys := filepath.Join(home, ".ssh", "authorized_keys")
		if err := os.WriteFile(keys, []byte("key\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(keys, filepath.Join(project, "keys.link")); err != nil {
			t.Fatal(err)
		}
		for _, input := range []actionfacts.Input{
			{Tool: "Bash", Args: []byte(`{"command":"echo key >> ./keys.link"}`), CWD: project, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX},
			{Tool: "Write", Args: []byte(`{"file_path":"./keys.link","content":"key"}`), CWD: project, ActiveHome: home},
		} {
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
			if finding := findingWithID(findings, rule); finding == nil || !finding.contributesToEnforcement() {
				t.Errorf("%s: findings %v, want enforced %s", input.Tool, findingIDs(findings), rule)
			}
		}
	})
}
