// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

// GAP-0056: CG-EXEC-001 reports a call of a command or code interpreter,
// not a name that ends in exec, eval or system. Every near variant that runs
// a command or code string still matches; method calls, longer names,
// argument-list subprocess.call and comment text do not.
func TestCodeGuardExecMatchesInterpreterCallsOnly(t *testing.T) {
	s := NewCodeGuardScanner("")
	match := map[string][]string{
		".py": {
			"eval(expr)", "result = eval(user_input)", "exec(code)", "exec(request.form['code'])",
			"print(eval(sys.argv[1]))", "if eval(cond):", "x=eval(s)", "f = lambda s: eval(s)", "EVAL(s)",
			`s = f"{eval(x)}"`, "# {eval(x)}", `f.write('import os\neval(payload)')`, `code = "x = 1\texec(y)"`, "builtins.eval(s)", "__builtins__.exec(s)",
			"os.system(cmd)", "os.system('ls ' + path)", "run = os.system",
			"__import__('os').system(cmd)", "importlib.import_module('os').system(c)",
			"subprocess.call(cmd)", "subprocess.call('rm -rf ' + d)", "rc = subprocess.call(args.command)",
			"subprocess.call(cmd, shell=True)", "subprocess.call(['sh', '-c', cmd], shell=True)", "subprocess.call(",
		},
		".js": {
			"eval(userInput)", "const r = eval(req.body.code)", "  eval(atob(payload));", "if (x) eval(code)", "!eval(b)",
			"window.eval(s)", "globalThis.eval(s)", "child_process.exec(cmd)", "child_process.execSync(cmd)",
			"require('child_process').exec(cmd)", "cp.exec(cmd)", "childProcess.exec(cmd)", "require(\"node:child_process\").exec(cmd)", "exec(cmd, (err) => {})",
			"const x = `${eval(input)}`", "// ${eval(input)}", "<p>{eval(input)}</p>",
		},
		".ts": {"eval(userInput)", "await exec(cmd)", "child_process.exec(`ls ${dir}`)", "system(cmd)"},
		".rb": {
			"system(params[:cmd])", "exec(cmd)", "eval(params[:code])", "Kernel.system(cmd)", "Kernel::system(cmd)",
			"Kernel.exec(cmd)", "Kernel.eval(s)", "obj.instance_eval(code)", "Foo.class_eval(code)", "mod.module_eval(code)",
			"x = `#{system(cmd)}`", "#{system(cmd)}",
		},
		".php": {"system($cmd);", "exec($cmd);", "shell_exec($cmd);", "pcntl_exec($path);", "eval($code);", "@eval($_POST['x']);", "{${eval($x)}}"},
	}
	noMatch := map[string][]string{
		".py": {
			"subprocess.call(['make'])", `subprocess.call(["git", "status"])`, "subprocess.call( ['ls'] )",
			"rc = subprocess.call([gateway, 'restart'])", "mock.patch('subprocess.call')",
			"model.eval()", "net.eval()", "self.system(name)", "pool.exec(job)", "platform.system()",
			"ast.literal_eval(value)", "proc = await asyncio.create_subprocess_exec(", "with runner.isolated_filesystem():",
			"# eval(x) is not used here",
		},
		".js": {
			"while ((m = re.exec(s)) !== null) {", "const m = regex.exec(str);", "/a/g.exec(s)", "model.eval()",
			`const r = parseEval("slice(list(1, 2), 1)");`, "page.$eval(sel, fn)", "db.exec(sql)", "myexec(cmd)", "doEval(x)",
			"// eval('class Plugin { ... }');", "  // call exec(cmd) here",
		},
		".ts": {
			"private searchFileSystem(term: string): Item[] {", "const out = pattern.exec(line)", "matcher.exec(input)",
			"this.eval()", "evaluator.eval(ast)", `const m = /^([a-z]+):\s*(.*)$/.exec(line);`,
		},
		".php": {
			"protected function createFlysystem(Adapter $a, array $config)", "new Flysystem($adapter, $config);",
			"// eval('class VendorPlugin { ... }');", "# exec($cmd) runs in the worker",
			"[$d, $w] = $this->createFlysystem($a, $c);", "$fileSystem(x)",
		},
		".rb": {"file_system(x)", "subsystem(x)", "# system(cmd) is called by the runner"},
	}
	has := func(ext, line string) bool {
		for _, f := range s.ScanContent("/src/app"+ext, line) {
			if f.ID == "CG-EXEC-001" {
				if f.Severity != SeverityHigh {
					t.Fatalf("%s %q: CG-EXEC-001 severity = %s, want HIGH", ext, line, f.Severity)
				}
				return true
			}
		}
		return false
	}
	for ext, lines := range match {
		for _, line := range lines {
			if !has(ext, line) {
				t.Errorf("%s %q: CG-EXEC-001 missing", ext, line)
			}
		}
	}
	for ext, lines := range noMatch {
		for _, line := range lines {
			if has(ext, line) {
				t.Errorf("%s %q: CG-EXEC-001 reported a non-interpreter call", ext, line)
			}
		}
	}
	// shell=True keeps both findings: CG-EXEC-002 at MEDIUM beside CG-EXEC-001.
	ids := map[string]Severity{}
	for _, f := range s.ScanContent("/src/app.py", "subprocess.call(cmd, shell=True)") {
		ids[f.ID] = f.Severity
	}
	if ids["CG-EXEC-001"] != SeverityHigh || ids["CG-EXEC-002"] != SeverityMedium {
		t.Fatalf("shell=True findings = %v, want CG-EXEC-001 HIGH and CG-EXEC-002 MEDIUM", ids)
	}
}
