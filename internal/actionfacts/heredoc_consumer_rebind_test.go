package actionfacts

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// gap0927Rebinds are statements before a data consumer (cat) in the script
// of its own argument that bind a variable that controls command lookup, or
// change the shell's command, alias or function tables, in a form the
// binding reader did not follow before rel-1-0-10:GAP-0927: a builtin behind
// a command or builtin prefix, an attached option value, an arithmetic or
// parameter-expansion write, a name reference, a subshell, a select or
// coproc name, the bash tables of programs and aliases, and the startup
// variables. Each is the unknown tier, never data.
var gap0927Rebinds = []string{
	"printf -vPATH /tmp/x", "command read PATH < /tmp/p", "builtin printf -v PATH /tmp/x",
	"declare -n p=PATH; p=/tmp/x", "BASH_CMDS[cat]=/bin/sh", "hash -p/bin/sh cat", "let PATH=5",
	"((PATH=5))", ": $((PATH=5))", "getopts a PATH", "unset PATH", "typeset -n p=PATH; read p < /tmp/p",
	"command mapfile -t PATH < /tmp/p", "builtin hash -p /bin/sh cat", "BASH_ALIASES[cat]=sh",
	"command printf -v PATH /tmp/x", "export PATH=/tmp/x", "for ((PATH=5;0;)); do :; done",
	"select PATH in /tmp/x; do break; done", "(PATH=/tmp/x)", "eval \"cat() { sh; }\"",
	"shopt -s expand_aliases; alias cat=sh", "BASH_ENV=/tmp/x", "IFS=/", "declare -n p; p=PATH",
	"unset -v PATH", "read -a PATH < /tmp/p", "x=PATH; declare -n p=$x; p=/tmp/x",
	// More spellings of the same rule.
	"command -p read PATH < /tmp/p", "builtin unset PATH", "command builtin printf -vPATH x", ": ${PATH:=/tmp/x}",
	"coproc PATH { :; }", "wait -pPATH", "wait -p PATH", "declare -nx p=PATH", "local -n p=PATH", "typeset -rn p=PATH",
	"let \"PATH=5\"", "let x=1 PATH=5", "((PATH+=1))", "((path=5))", "BASH_CMDS=([cat]=/bin/sh)",
	"declare -A BASH_ALIASES", "local PATH", "readarray -t PATH < /tmp/p", "read -p x PATH < /tmp/p",
	"command alias cat=sh", "builtin enable cat", "command hash -p /bin/sh cat", "FPATH=/tmp/x", "export BASH_ENV=/tmp/x",
	"read $v < /tmp/p", "printf -v $v x", "unset $v", "declare $n=1", "((${v}=5))", "nameref p=PATH", "declare -n",
	"command declare -n p=PATH", "builtin local -n p=PATH", "ZDOTDIR=/tmp/x", "LD_PRELOAD=/tmp/x.so", "ENV=/tmp/x",
}

// gap0927Keeps change no lookup: cat stays data after them. CDPATH changes
// where cd looks, not what a command word runs.
var gap0927Keeps = []string{
	"CDPATH=/tmp/x; cd y", "echo $PATH", "x=PATH", "read -p PATH x < /tmp/p", "printf '%s' PATH", "unset foo",
	"getopts ab opt", "let x=1", "((x=1))", "echo $((y+1))", "declare -r X=1", "local x", "export -n FOO", "export PATH",
	"readonly PATH", "hash cat", "hash -r", "alias ll='ls -l'", "read -r -a arr < f", "mapfile -t lines < f", "echo ${PATH}",
	": ${HOME:=/x}", "wait -n", "printf -v out %s \"$PATH\"", "cd /tmp && ls", "for f in a b; do echo $f; done",
}

// rel-1-0-10:GAP-0927. One rule decides the consumer: a variable that
// controls command lookup that the parsed text writes in any form, a change
// of the shell's tables, or a name reference makes the consumer unresolved,
// as a statement of the call and as the script of its own argument.
func TestHereDocConsumerOneRuleForEveryRebind(t *testing.T) {
	doc := func(script string) shellparse.SyntaxTailHereDoc {
		return shellparse.SyntaxTailHereDoc{Consumer: "cat > notes.txt", Script: script, ScriptKnown: true}
	}
	for _, statement := range gap0927Rebinds {
		if got := syntaxTailHereDocConsumerIn(doc(""), []string{statement}); got == hereDocData {
			t.Errorf("statement %q: hereDocData, want the unknown tier", statement)
		}
		if got := syntaxTailHereDocConsumerIn(doc(statement+"; "), nil); got == hereDocData {
			t.Errorf("script %q: hereDocData, want the unknown tier", statement)
		}
		// End to end: the script before the consumer inside one quoted
		// argument, read by the syntax tail.
		script := "tool - '" + statement + "; cat > notes.txt <<'\"'\"'EOF'\"'\"'\nit'\"'\"'s (x)\necho data\nEOF\necho after'"
		tail, ok := shellparse.ReadSyntaxTail(script)
		if !ok || len(tail.HereDocs) != 1 {
			continue
		}
		if got := syntaxTailHereDocConsumerIn(tail.HereDocs[0], tail.Statements); got == hereDocData {
			t.Errorf("end to end %q: hereDocData, want the unknown tier", statement)
		}
	}
	for _, statement := range gap0927Keeps {
		if got := syntaxTailHereDocConsumerIn(doc(""), []string{statement}); got != hereDocData {
			t.Errorf("statement %q: %d, want hereDocData", statement, got)
		}
		if got := syntaxTailHereDocConsumerIn(doc(statement+"; "), nil); got != hereDocData {
			t.Errorf("script %q: %d, want hereDocData", statement, got)
		}
	}
}
