// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hlinkmatrix generates the GAP-0293 regression corpus: write and
// metadata verbs applied to names that reach a protected keys file through a
// link, spelled in every quoting form, in the link layouts of the HLINK
// review. Every row is DATA derived by transforming one fixture name; no row
// is typed by hand. Tests in hookpaths and gateway share it so the per-user
// reading, the managed reading and the resolver are held to one corpus.
package hlinkmatrix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Effect is what a verb does to the inode its operand names.
type Effect string

const (
	// Content writes the inode in place (open for write).
	Content Effect = "content"
	// Metadata changes the inode's mode, owner or times in place.
	Metadata Effect = "metadata"
	// Replace removes the name and creates a new inode under it: the
	// protected inode is left alone when the name is a link to it.
	Replace Effect = "replace"
)

// Target says what the operand's name is.
type Target string

const (
	// Alias is a name that links to the protected inode (hard link, or a
	// symlink followed by the verb).
	Alias Target = "alias"
	// Ordinary is a name that holds nothing protected.
	Ordinary Target = "ordinary"
	// Unknown is an operand the static reading cannot settle.
	Unknown Target = "unknown"
)

// Row is one corpus case.
type Row struct {
	ID      string
	Command string
	Effect  Effect
	Target  Target
	// Entry is true when the verb changes the symlink entry itself (touch -h
	// on a symlink): the keys inode is left alone.
	Entry bool
}

// Protected reports whether the row must be judged as reaching the keys file.
func (r Row) Protected() bool {
	return r.Target == Alias && !r.Entry && r.Effect != Replace
}

// Names are the fixture entries Setup creates in the project directory.
type Names struct {
	HardBracket  string // hard link of the keys, name has a bracket pair
	PlainBracket string // ordinary file, same shape of name
	KeyHard      string // hard link, plain name
	KeyLink      string // symlink to the keys
	Deep         string // hard link in a subdirectory
	LevelLink    string // symlink to the hard link in the subdirectory
	DirLink      string // symlink to the protected directory
	NoMatchHard  string // hard link whose name is a bracket class that matches no entry
	NoMatchSym   string // symlink whose name is such a class
	SubDir       string
}

// DefaultNames are the names every shared test uses.
func DefaultNames() Names {
	return Names{
		HardBracket: "alias[1]", PlainBracket: "plain[1]", KeyHard: "keyhard", KeyLink: "keylink",
		Deep: "deep[1]", LevelLink: "lvl[1]", DirLink: "dir[1]", NoMatchHard: "nm[xy]", NoMatchSym: "ns[xy]", SubDir: "sub",
	}
}

// Setup creates the fixture entries in project for the keys file at keys.
// Plain files a.txt and b.txt and the ordinary bracket name exist too.
func Setup(t testing.TB, project, keys string, n Names) {
	t.Helper()
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"a.txt", "b.txt", n.PlainBracket} {
		write(name)
	}
	must(os.Link(keys, filepath.Join(project, n.HardBracket)))
	must(os.Link(keys, filepath.Join(project, n.KeyHard)))
	must(os.Link(keys, filepath.Join(project, n.NoMatchHard)))
	if _, err := os.Lstat(filepath.Join(project, n.KeyLink)); err != nil {
		must(os.Symlink(keys, filepath.Join(project, n.KeyLink)))
	}
	must(os.Symlink(keys, filepath.Join(project, n.NoMatchSym)))
	must(os.MkdirAll(filepath.Join(project, n.SubDir), 0o700))
	must(os.Link(keys, filepath.Join(project, n.SubDir, n.Deep)))
	must(os.Symlink(filepath.Join(n.SubDir, n.Deep), filepath.Join(project, n.LevelLink)))
	must(os.Symlink(filepath.Join("..", ".ssh"), filepath.Join(project, n.DirLink)))
}

// Quoting is one spelling of a name.
type Quoting struct {
	ID    string
	Spell func(name string) string
	// NeedsBracket says the form only differs from the plain name when the
	// name holds a bracket pair.
	NeedsBracket bool
}

func transformBrackets(name, openRep, closeRep string) string {
	return strings.NewReplacer("[", openRep, "]", closeRep).Replace(name)
}

// Quotings are the spellings of one name: single and double quotes, a
// backslash before every glob character, ANSI-C plain, hex, octal and unicode
// escapes, quoting only the tail, mixed quote kinds, a brace word, the
// unquoted form (a pattern; bash passes it literally when nothing matches).
func Quotings() []Quoting {
	cut := func(name string) (head, tail string) {
		i := strings.IndexByte(name, '[')
		if i < 0 {
			return name, ""
		}
		return name[:i], name[i:]
	}
	return []Quoting{
		{"single", func(n string) string { return "'" + n + "'" }, false},
		{"double", func(n string) string { return `"` + n + `"` }, false},
		{"escaped", func(n string) string { return transformBrackets(n, `\[`, `\]`) }, true},
		{"ansi-plain", func(n string) string { return "$'" + n + "'" }, false},
		{"ansi-hex", func(n string) string { return "$'" + transformBrackets(n, `\x5b`, `\x5d`) + "'" }, true},
		{"ansi-octal", func(n string) string { return "$'" + transformBrackets(n, `\133`, `\135`) + "'" }, true},
		{"ansi-unicode", func(n string) string { return "$'" + transformBrackets(n, `\u005b`, `\u005d`) + "'" }, true},
		{"mixed-tail", func(n string) string { h, t := cut(n); return h + "'" + t + "'" }, true},
		{"dq-sq", func(n string) string {
			h, t := cut(n)
			if len(t) < 3 {
				return n
			}
			return `"` + h + t[:1] + `"` + t[1:2] + "'" + t[2:] + "'"
		}, true},
		{"esc-open", func(n string) string { h, t := cut(n); return h + `\` + t }, true},
		{"unquoted", func(n string) string { return n }, false},
	}
}

// verbEffectOn is the effect of a verb on a name that is a symlink or a
// hard link. install through a symlink is judged a write of what it leads
// to (rel-1-0-6 GAP-0389: its behavior differs between implementations),
// where mv and sed -i replace the symlink.
func verbEffectOn(v Verb, symlink bool) Effect {
	if symlink && (v.ID == "install" || v.ID == "sed-i") {
		return Content
	}
	return v.Effect
}

// Verb is a writer prefix with the effect it has on the operand.
type Verb struct {
	ID, Prefix string
	Effect     Effect
	// NoDereference marks touch -h.
	NoDereference bool
}

// Verbs are the write and metadata verbs of the corpus.
func Verbs() []Verb {
	return []Verb{
		{"touch-h", "touch -h ", Content, true},
		{"touch", "touch ", Content, false},
		{"append", "echo m >> ", Content, false},
		{"redirect", "echo m > ", Content, false},
		{"tee", "echo m | tee ", Content, false},
		{"tee-a", "echo m | tee -a ", Content, false},
		{"cp", "cp a.txt ", Content, false},
		{"dd", "dd if=a.txt of=", Content, false},
		{"truncate", "truncate -s 0 ", Content, false},
		{"chmod", "chmod 600 ", Metadata, false},
		{"chown", "chown 0 ", Metadata, false},
		{"mv", "mv b.txt ", Replace, false},
		{"install", "install -m 644 a.txt ", Replace, false},
		{"sed-i", "sed -i s/x/y/ ", Replace, false},
	}
}

// Rows generates the corpus for the given names. The Alias rows are the hard
// link and symlink names in every quoting form and verb; the Ordinary rows
// are the plain bracket name; the layout rows move the same verbs through
// subdirectories, cd, CDPATH, a symlinked directory and variables.
func Rows(n Names) []Row {
	var rows []Row
	verbs := Verbs()
	for _, q := range Quotings() {
		for _, v := range verbs {
			for _, alias := range []struct {
				id, name string
				sym      bool
			}{{"hard", n.HardBracket, false}, {"nomatch-hard", n.NoMatchHard, false}, {"nomatch-sym", n.NoMatchSym, true}} {
				if q.ID == "unquoted" && alias.id == "hard" {
					// the unquoted form of a bracket name is a class that
					// matches the ordinary file of the same digit, if any:
					// it is the nomatch rows that carry the literal fallback.
					continue
				}
				rows = append(rows, Row{
					ID:      "HL-" + alias.id + "-" + q.ID + "-" + v.ID,
					Command: v.Prefix + q.Spell(alias.name),
					Effect:  verbEffectOn(v, alias.sym), Target: Alias,
					Entry: v.NoDereference && alias.sym,
				})
			}
		}
		for _, v := range verbs {
			rows = append(rows, Row{
				ID: "HL-ordinary-" + q.ID + "-" + v.ID, Command: v.Prefix + q.Spell(n.PlainBracket),
				Effect: v.Effect, Target: Ordinary,
			})
		}
	}
	// variables naming the hard link or the symlink, for every verb
	for _, target := range []struct{ id, name string }{{"hard", n.KeyHard}, {"sym", n.KeyLink}} {
		for _, v := range verbs {
			rows = append(rows, Row{
				ID:      "HL-var-" + target.id + "-" + v.ID,
				Command: "p=" + target.name + "; " + v.Prefix + `"$p"`,
				Effect:  verbEffectOn(v, target.id == "sym"), Target: Alias, Entry: v.NoDereference && target.id == "sym",
			})
		}
	}
	// link layouts for the content verbs
	for _, v := range verbs[:3] {
		for _, l := range []struct{ id, command string }{
			{"subdir", v.Prefix + "'" + n.SubDir + "/" + n.Deep + "'"},
			{"cd", "cd " + n.SubDir + " && " + v.Prefix + "'" + n.Deep + "'"},
			{"dotdot", v.Prefix + "'../" + "project/" + n.SubDir + "/" + n.Deep + "'"},
			{"sym-to-hard", v.Prefix + "'" + n.LevelLink + "'"},
			{"dir-link-entry", v.Prefix + "'" + n.DirLink + "'/authorized_keys"},
		} {
			rows = append(rows, Row{
				ID: "HL-layout-" + l.id + "-" + v.ID, Command: l.command, Effect: v.Effect, Target: Alias,
				Entry: v.NoDereference && l.id == "sym-to-hard",
			})
		}
	}
	return rows
}

// UncertainRows are operands the static reading cannot settle: an unknown
// variable, a command substitution, a parameter expansion with a default.
// They are judged at the pack's unknown tier, never plain allow.
func UncertainRows() []Row {
	var rows []Row
	forms := []struct{ id, word string }{
		{"unset-var", `"$S7UNSET"`},
		{"cmdsubst", `"$(printf a.txt)"`},
		{"default-expansion", `"${S7UNSET:-a.txt}"`},
	}
	for _, f := range forms {
		for _, v := range Verbs() {
			rows = append(rows, Row{ID: "HL-uncertain-" + f.id + "-" + v.ID, Command: v.Prefix + f.word, Effect: v.Effect, Target: Unknown})
		}
	}
	return rows
}
