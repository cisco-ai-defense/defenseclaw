// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// BoundCommandOperands is the reading of a shell command that the hook
// client and the gateway both judge when the call has more operands than
// actionfacts.MaxOperandsPerCall (GAP-0943): over reports that, and reduced
// keeps the first operands, and of the later ones every word that is not a
// plain name (see plainOperandName), every name that is a link and every
// name that is a hard link to a protected key file, however many there are.
// The operands left out are plain names that no protected file is called by
// once the shell has decoded them and that one read of the file system finds
// to be no link (a relative name is read from cwd). Whether such a name
// leads to a protected file in a way that read does not see is not asked for
// them, so the caller treats the call as unresolved and its policy tier
// decides. Every word is matched as text; only the full resolution is
// bounded.
func BoundCommandOperands(command, cwd, home string) (reduced string, over bool) {
	if len(command) < 2*actionfacts.MaxOperandsPerCall {
		return command, false
	}
	probe := &operandLinkProbe{cwd: cwd, home: home, dirs: map[string]bool{}}
	return actionfacts.BoundOperands(command, probe.droppable)
}

// operandLinkProbe tells, for one call, whether a plain name is read from
// the file system as itself: no link in the name or in the folders below the
// cwd, and no second name of a protected key file. It keeps what it learned
// for the one call only.
type operandLinkProbe struct {
	cwd, home string
	cwdLink   *bool           // the cwd itself is a link
	dirs      map[string]bool // stop + folder -> the folder or one above it is a link
	keys      protectedFiles
	keysRead  bool
}

// droppable reports a word that may be left out past the bound: a plain name
// (decoded as the shell decodes it) that the file system shows to be no link.
func (p *operandLinkProbe) droppable(word string) bool {
	path, plain := plainOperandName(word)
	if !plain {
		return false
	}
	path = filepath.FromSlash(path)
	relative := !filepath.IsAbs(path) && filepath.VolumeName(path) == ""
	stop := ""
	if relative {
		if p.cwdIsLink() {
			return false
		}
		stop = filepath.Clean(p.cwd)
		path = filepath.Join(p.cwd, path)
	}
	info, err := pathLstat(path)
	switch {
	case err == nil:
		if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || p.secondNameOfKeys(path, info) {
			return false
		}
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, syscall.ENOTDIR):
		// Nothing there to be a link; the folders are still read.
	default:
		return false
	}
	return !p.linkAbove(filepath.Dir(path), stop)
}

// cwdIsLink reports that the cwd is itself a link (read once).
func (p *operandLinkProbe) cwdIsLink() bool {
	if p.cwdLink == nil {
		link := false
		if info, err := pathLstat(p.cwd); err == nil {
			link = info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
		}
		p.cwdLink = &link
	}
	return *p.cwdLink
}

// linkAbove reports that dir, or a folder above it up to (not including)
// stop, or up to the root when stop is empty, is a link. The answer for each
// folder of the walk is kept.
func (p *operandLinkProbe) linkAbove(dir, stop string) bool {
	var walked []string
	link := false
	for d := dir; d != stop; {
		if known, seen := p.dirs[stop+"\x00"+d]; seen {
			link = known
			break
		}
		walked = append(walked, d)
		if info, err := pathLstat(d); err == nil && info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			link = true
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	for _, d := range walked {
		p.dirs[stop+"\x00"+d] = link
	}
	return link
}

// secondNameOfKeys reports a file that is another name of a protected key
// file (a hard link), or that may be one when a key file cannot be read, as
// the write readers do (protectedFiles.target).
func (p *operandLinkProbe) secondNameOfKeys(path string, info os.FileInfo) bool {
	if !info.Mode().IsRegular() || p.home == "" {
		return false
	}
	if !p.keysRead {
		p.keys, p.keysRead = newProtectedFiles(p.home), true
	}
	for _, key := range p.keys {
		if (key.info != nil || key.unknown) && linkCount(path, info) > 1 &&
			(key.info == nil || os.SameFile(info, key.info)) {
			return true
		}
	}
	return false
}

// protectedNameParts are the parts of a name that keep it judged however
// plain it reads: the keys files and the folders that hold them, the state of
// DefenseClaw, the places the system and the user shell start programs from,
// and the agent instruction files (InstructionFileNames). They are one
// string, read as a list, because they are no argv words of a program for the
// archive sweep of GAP-0055 to read.
var protectedNameParts = strings.Fields(`key ssh authorized defenseclaw claw id_ rsa ed25519 ecdsa pem secret
	token credential passw shadow sudoers kube aws netrc pgpass env profile bashrc zshrc zshenv zlogin bash_
	cron systemd launch plist init.d rc.d rc.local startup sshd motd hook`)

// protectedSystemRoots are the top folders whose files the system reads as
// its own settings, so that a path below one stays judged.
var protectedSystemRoots = strings.Fields(`etc root boot usr var lib lib64 opt bin sbin proc sys dev private
	system library windows programdata`)

// plainOperandName reports a word that no protected file is called by once
// the shell has decoded it, and that is no form the readers expand, and the
// name the shell reads from it. The word is decoded as a POSIX shell does
// (quotes taken off, an unquoted backslash dropped) and as a Windows shell
// does (quotes taken off, a backslash a separator); it is plain only when
// both readings are, so an escaped spelling is no cover. A plain name is a
// relative or absolute path (a drive letter allowed) of plain segments. A
// segment starts with no dot, has no dot-dot, variable, glob, home, brace,
// percent, stream or short-name form, no trailing dot, no protected name
// part, and is not an ssh control file; the path is not below a system folder
// and is no UNC form. Such a word can name a protected file only through a
// link, which BoundCommandOperands reads for.
func plainOperandName(word string) (name string, plain bool) {
	posix, okPosix := decodeOperand(word, true)
	windows, okWindows := decodeOperand(word, false)
	if !okPosix || !okWindows || !plainDecodedName(posix, true) || !plainDecodedName(windows, false) {
		return "", false
	}
	if filepath.Separator == '\\' {
		return windows, true
	}
	return posix, true
}

// decodeOperand reads word as the POSIX shell does (posix) or as the Windows
// shells do. It refuses a byte a plain name does not hold, outside the
// quotes and also escaped, a backslash the POSIX shell keeps as a name byte
// (in quotes), and a quote that is not closed.
func decodeOperand(word string, posix bool) (string, bool) {
	var out strings.Builder
	var quote byte
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case quote == 0 && (c == 0x27 || c == 0x22):
			quote = c
		case quote != 0 && c == quote:
			quote = 0
		case c == 0x5c && !posix:
			out.WriteByte('/')
		case c == 0x5c:
			i++
			if quote != 0 || i >= len(word) || !plainOperandByte(word[i], out.Len()) {
				return "", false
			}
			out.WriteByte(word[i])
		case plainOperandByte(c, out.Len()):
			out.WriteByte(c)
		default:
			return "", false
		}
	}
	return out.String(), quote == 0
}

// plainDecodedName is the test of plainOperandName on one reading. A drive
// letter is a form of the Windows reading: the POSIX reading of C:\\x is a
// relative name, which the other tests cover.
func plainDecodedName(word string, posix bool) bool {
	if word == "" || word[0] == 0x2d {
		return false
	}
	if strings.HasPrefix(word, "//") {
		return false
	}
	drive := !posix && len(word) >= 2 && word[1] == 0x3a
	if drive && (len(word) < 3 || word[2] != 0x2f) {
		return false
	}
	lower := strings.ToLower(word)
	for _, part := range protectedNameParts {
		if strings.Contains(lower, part) {
			return false
		}
	}
	for _, name := range InstructionFileNames {
		if strings.Contains(lower, strings.ToLower(name)) {
			return false
		}
	}
	segments := strings.Split(lower, "/")
	if drive {
		segments = segments[1:]
	}
	if drive || strings.HasPrefix(word, "/") {
		// The top folder of an absolute word.
		top := ""
		for _, segment := range segments {
			if segment != "" {
				top = segment
				break
			}
		}
		if slices.Contains(protectedSystemRoots, top) {
			return false
		}
	}
	for _, segment := range segments {
		switch {
		case segment == "" || segment == ".":
		case strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, "."):
			return false
		case sshControlName(segment):
			return false
		}
	}
	return true
}

// sshControlName reports a name of the files under ~/.ssh that sshd or ssh
// run or read as policy (SSHControlFiles) or that hold keys (AuthorizedKeysFiles).
func sshControlName(segment string) bool {
	return slices.Contains(SSHControlFiles[:], segment) || slices.Contains(AuthorizedKeysFiles[:], segment)
}

// plainOperandByte reports a byte a plain name is made of: a letter, a digit,
// one of _ . + @ , - /, or the colon of a drive letter (i is its place).
func plainOperandByte(c byte, i int) bool {
	switch {
	case c >= 0x30 && c <= 0x39, c >= 0x41 && c <= 0x5a, c >= 0x61 && c <= 0x7a:
		return true
	case strings.IndexByte("_.+@,-/", c) >= 0:
		return true
	}
	return c == 0x3a && i == 1
}
