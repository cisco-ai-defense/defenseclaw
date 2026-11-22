// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strings"
)

// inlineCodeAccess classifies the inline code an interpreter child runs with
// the words it is handed (rel-1-0-10:GAP-0365, GAP-0657). Three answers, in
// this order:
//
//   - InlineReads: a read grammar proves the code writes nothing. The only
//     grammar is the Python one (pythonCodeOnlyReads) and it applies to the
//     bare shape `python -c CODE`: no other interpreter option, so no -i, -m
//     or -X flag and no startup hook changes what runs.
//   - InlineWrites: the code names a call of the interpreter's writer table
//     (inlineWriterNames: a file write, a delete, a rename, a mode or owner
//     change, a copy, a process spawn) or opens a file in a write mode.
//     That is positive evidence of a change, so the handed path is judged
//     as a write.
//   - InlineUnknown: neither. The code may read, may write through a
//     spelling no table lists, or is not in the words (stdin). It gets the
//     unknown tier of the pack, never a silent allow.
//
// The writer tables are data, per language; a name is matched as a whole
// identifier anywhere in the text (a method after a dot included). They are
// evidence of a write, not a proof of its absence: code that names none is
// still InlineUnknown, never InlineReads.
func inlineCodeAccess(key, code string, bare bool) InlineAccess {
	if key == "python" && bare && pythonCodeOnlyReads(code) {
		return InlineReads
	}
	names := inlineWriterNames[key]
	code = inlineStdStream.ReplaceAllString(code, " ")
	for _, name := range inlineIdentifierPattern.FindAllString(code, -1) {
		if names[name] {
			return InlineWrites
		}
	}
	if inlineWriteModeOpen.MatchString(code) {
		return InlineWrites
	}
	return InlineUnknown
}

// inlineStdStream is a write to the process's own output (sys.stdout.write,
// process.stderr.write, $stdout.write, fwrite(STDERR ...)): it changes no
// file, so it is not evidence of a write.
var inlineStdStream = regexp.MustCompile(
	`(?:\b(?:sys|process)\.)?\b(?:stdout|stderr)\.(?:write|writelines|flush)\b|\$?\b(?:STDOUT|STDERR)\.(?:write|puts)\b|\b(?:fwrite|fputs)\s*\(\s*(?:STDOUT|STDERR)\b`)

var inlineIdentifierPattern = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// inlineWriteModeOpen matches a file open whose literal mode writes: an open
// or fopen call with a "w", "a", "x" or "+" mode word.
var inlineWriteModeOpen = regexp.MustCompile(
	`(?s)\b(?:open|fopen|openSync|popen)\s*\(\s*(?:[^,()]|\((?:[^()]|\([^()]*\))*\))*,\s*(?:mode\s*=\s*)?['"](?:[wax][bt+]*|r[bt]*\+[bt]*)['"]\s*[,)]`)

// inlineWriterNames lists, per interpreter, the identifiers whose call writes
// a file, changes it, or runs a program.
var inlineWriterNames = map[string]map[string]bool{
	"python": inlineNameSet("write writelines write_text write_bytes remove unlink rmdir rmtree rename renames " +
		"truncate ftruncate chmod chown lchown fchmod copy copy2 copyfile copytree copymode move symlink link " +
		"touch utime makedirs mkdir system popen Popen subprocess spawnl spawnv spawnlp spawnvp execl execle execlp " +
		"execv execve execvp execvpe check_call check_output sendfile dump extract extractall unpack_archive"),
	"node": inlineNameSet("writeFile writeFileSync appendFile appendFileSync createWriteStream write writeSync " +
		"unlink unlinkSync rm rmSync rmdir rmdirSync rename renameSync truncate truncateSync ftruncate " +
		"copyFile copyFileSync cp cpSync chmod chmodSync chown chownSync symlink symlinkSync link linkSync " +
		"utimes utimesSync mkdir mkdirSync child_process exec execSync execFile execFileSync spawn spawnSync fork"),
	"bun": inlineNameSet("write writeFile writeFileSync appendFile appendFileSync createWriteStream writeSync " +
		"unlink unlinkSync rm rmSync rename renameSync truncate copyFile copyFileSync cp cpSync chmod chmodSync " +
		"symlink symlinkSync child_process exec execSync spawn spawnSync fork"),
	"ruby": inlineNameSet("write binwrite delete unlink rename truncate chmod chown lchmod lchown utime symlink link " +
		"mkdir rmdir system exec spawn popen FileUtils Open3 syscall"),
	"php": inlineNameSet("file_put_contents fwrite fputs fputcsv ftruncate unlink rename copy chmod chown chgrp touch " +
		"symlink link rmdir mkdir system exec shell_exec passthru proc_open popen pcntl_exec"),
}

func inlineNameSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, word := range strings.Fields(text) {
		set[word] = true
	}
	return set
}

// InlineProgramHandsWords reports a program word that names an inline-code
// interpreter whose words reach its code (python, node, bun, ruby, php).
func InlineProgramHandsWords(program string) bool {
	key, _, ok := inlineInterpreterRow(program)
	return ok && inlineHandsWords[key]
}
