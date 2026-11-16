// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/agentchain"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// wrapperHold is how long a transparent wrapper's record waits for its
	// child's exec (cowork-1-0-8 GAP-0055). The wrapped command's exec
	// follows within milliseconds; a child whose image digest is still
	// being read when the hold ends leaves the wrapper reported.
	wrapperHold = 5 * time.Second
	// maxHeldWrappers bounds the records held at once; past it a wrapper is
	// recorded at once.
	maxHeldWrappers = 64
	// maxWrapperChain is the most wrappers a chain held for one client can
	// have (timeout 300 nice claude). A deeper chain records its outer
	// wrappers.
	maxWrapperChain = 2
)

// heldWrapper is the record of a transparent wrapper exec waiting for the
// exec of the command it wraps.
type heldWrapper struct {
	cmdline  string
	tail     string
	event    plane.Event
	lineage  agentchain.Lineage
	match    tactics.Match
	at       time.Time
	instance agentchain.Instance
	timer    *time.Timer
	// linked are the held wrapper records whose child exec this record is:
	// they are dropped with it, or recorded with it.
	linked []*heldWrapper
	// depth is the number of wrappers in this record's chain: its own level
	// (1 for a wrapper, 0 for a client exec) and its deepest linked record's.
	depth int
	// resolved is a wrapper whose source names argv[0] by the resolved
	// binary (Tetragon): its child's command line starts with the child's
	// binary, not with the tail's program word.
	resolved bool
	// digest is a held client exec's image digest: the exec event's, or the
	// one a later KindImageDigest event delivered ("" until then).
	digest string
}

// level is the number of wrappers the record itself adds to a chain.
func (held *heldWrapper) level() int {
	if held.tail != "" {
		return 1
	}
	return 0
}

// transparentWrappers run their argv tail as the command, with no shell in
// between: the tail is the argv of the child exec. timeout forks the child
// and nice and env exec it in place. The table is closed: any other program
// whose argv repeats a client's is reported as its own exec.
var transparentWrappers = map[string]func(args []string) int{
	"timeout": timeoutCommandIndex,
	"nice":    niceCommandIndex,
	"env":     envCommandIndex,
}

var (
	wrapperDuration   = regexp.MustCompile(`^[0-9]*\.?[0-9]+[smhd]?$`)
	wrapperAdjustment = regexp.MustCompile(`^[-+]?[0-9]+$`)
	wrapperEnvName    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// timeoutCommandIndex is the index of the command in a GNU timeout argv
// (timeout [--preserve-status] [--foreground] [-v] [-k D] [-s S] D cmd...),
// or -1.
func timeoutCommandIndex(args []string) int {
	i := 1
options:
	for ; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--":
			i++
			break options
		case arg == "--preserve-status" || arg == "--foreground" || arg == "-v" || arg == "--verbose":
		case arg == "-k" || arg == "-s" || arg == "--kill-after" || arg == "--signal":
			i++
		case strings.HasPrefix(arg, "--kill-after=") || strings.HasPrefix(arg, "--signal="),
			len(arg) > 2 && (strings.HasPrefix(arg, "-k") || strings.HasPrefix(arg, "-s")):
		case strings.HasPrefix(arg, "-"):
			return -1
		default:
			break options
		}
	}
	if i >= len(args) || !wrapperDuration.MatchString(args[i]) {
		return -1
	}
	return commandAt(args, i+1)
}

// niceCommandIndex is the index of the command in a nice argv
// (nice [-n N | -N | --adjustment=N] cmd...), or -1.
func niceCommandIndex(args []string) int {
	i := 1
	for ; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--":
			return commandAt(args, i+1)
		case arg == "-n" || arg == "--adjustment":
			i++
			if i >= len(args) || !wrapperAdjustment.MatchString(args[i]) {
				return -1
			}
		case strings.HasPrefix(arg, "--adjustment="):
			if !wrapperAdjustment.MatchString(strings.TrimPrefix(arg, "--adjustment=")) {
				return -1
			}
		case strings.HasPrefix(arg, "-n") && wrapperAdjustment.MatchString(arg[2:]),
			strings.HasPrefix(arg, "-") && wrapperAdjustment.MatchString(arg[1:]):
		case strings.HasPrefix(arg, "-"):
			return -1
		default:
			return commandAt(args, i)
		}
	}
	return -1
}

// envCommandIndex is the index of the command in an env argv that only
// clears or sets variables (env [-i] [-u NAME] [NAME=VALUE]... cmd...), or
// -1. A loader variable (LD_*, DYLD_*) changes what the client image runs,
// so that env is not transparent.
func envCommandIndex(args []string) int {
	i := 1
	for ; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "--":
			return commandAt(args, i+1)
		case arg == "-i" || arg == "--ignore-environment":
		case arg == "-u" || arg == "--unset":
			i++
			if i >= len(args) || !wrapperEnvName.MatchString(args[i]) {
				return -1
			}
		case strings.HasPrefix(arg, "-"):
			return -1
		case strings.Contains(arg, "="):
			name, _, _ := strings.Cut(arg, "=")
			if !wrapperEnvName.MatchString(name) || strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
				return -1
			}
		default:
			return commandAt(args, i)
		}
	}
	return -1
}

func commandAt(args []string, i int) int {
	if i >= len(args) || args[i] == "" {
		return -1
	}
	return i
}

// wrapperTail splits a transparent wrapper's command line into the
// wrapper's own arguments (the program and its options, env assignments
// included) and the tail, the argv its child execs with. The command line is
// argv joined by single spaces, so it is the prefix, one space and the tail.
func wrapperTail(name, cmdline string) (prefix, tail string, ok bool) {
	args := strings.Split(cmdline, " ")
	if len(args) < 2 || tactics.BaseName(args[0]) != name {
		return "", "", false
	}
	index, ok := transparentWrappers[name]
	if !ok {
		return "", "", false
	}
	at := index(args)
	if at < 0 {
		return "", "", false
	}
	return strings.Join(args[:at], " "), strings.Join(args[at:], " "), true
}

// wrapperRecordLocked returns the record of a transparent wrapper exec whose
// match comes from the command it wraps, when that command would not be
// reported as the verified Claude client, to be held with holdWrapperLocked
// until the wrapped exec shows whether it is that client. It returns nil
// when the record is to be made now.
func (h *hostPlane) wrapperRecordLocked(
	event plane.Event, lineage agentchain.Lineage, match tactics.Match, at time.Time, instance agentchain.Instance,
) *heldWrapper {
	if h.wrapperHold <= 0 || event.Kind != plane.KindExec || event.PID <= 0 ||
		h.indicators.KeepClientMCP || h.clientChecksums == nil {
		return nil
	}
	name, cmdline, resolved := event.Name, event.Cmdline, event.Source == plane.SourceTetragon
	if resolved {
		// Tetragon names argv[0] by the binary it resolved, so neither the
		// process name nor argv[0] says which program ran: the binary must
		// be one of the installed wrappers, by file identity.
		program, args, _ := strings.Cut(cmdline, " ")
		if name = installedWrapper(event.Exe, h.wrapperDirs); name == "" || program != event.Exe {
			return nil
		}
		cmdline = name + " " + args
	}
	prefix, tail, ok := wrapperTail(name, cmdline)
	if !ok {
		return nil
	}
	// A signal the wrapper's own arguments carry is never held, whatever the
	// tail gives: an MCP reference in an env assignment is reported even when
	// the tail names the same package (IN-g55 review 1).
	own := tactics.Observation{
		Kind: string(plane.KindExec), PID: event.PID, Name: event.Name, Cmdline: commandWordCmdline(prefix),
	}
	if _, ok := tactics.Classify(own, h.indicators); ok {
		return nil
	}
	// The wrapper's match must be the tail's own, and the tail run by the
	// verified client must be no match at all.
	child := tactics.Observation{
		Kind: string(plane.KindExec), PID: event.PID, Name: tactics.BaseName(strings.SplitN(tail, " ", 2)[0]),
		Cmdline: commandWordCmdline(tail),
	}
	if asOther, ok := tactics.Classify(child, h.indicators); !ok || asOther.SignalID != match.SignalID {
		return nil
	}
	child.ClaudeClient = true
	if _, ok := tactics.Classify(child, h.indicators); ok {
		return nil
	}
	return &heldWrapper{
		cmdline: event.Cmdline, tail: tail, event: event, lineage: lineage, match: match, at: at, instance: instance,
		depth: 1, resolved: resolved,
	}
}

// wrapperBinaryDirs are where the allowlisted wrappers are installed.
var wrapperBinaryDirs = []string{"/usr/bin", "/bin"}

// installedWrapper is the allowlisted wrapper whose installed binary (in one
// of dirs) the resolved executable path exe is, by image identity: a regular
// file reached without a link that is the same file (device and inode) with
// the same size and modification time as the binary installed under that
// wrapper's name, itself not writable by group or others. A copy of a
// wrapper, a binary only named like one, and a file installed under more
// than one wrapper's name (a multi-call binary, whose resolved path does not
// say which tool ran) are none.
//
// Only a path directly in one of dirs is looked at, so no other path (an
// agent's own binary in a home, perhaps on a slow network file system) is
// ever read under the host plane's lock.
func installedWrapper(exe string, dirs []string) string {
	if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe || !slices.Contains(dirs, filepath.Dir(exe)) {
		return ""
	}
	image, err := os.Lstat(exe)
	if err != nil || !image.Mode().IsRegular() {
		return ""
	}
	found := ""
	for name := range transparentWrappers {
		for _, dir := range dirs {
			installed, err := os.Stat(filepath.Join(dir, name))
			if err != nil || !installed.Mode().IsRegular() || installed.Mode().Perm()&0o022 != 0 ||
				!os.SameFile(image, installed) || image.Size() != installed.Size() ||
				!image.ModTime().Equal(installed.ModTime()) {
				continue
			}
			if found != "" && found != name {
				return ""
			}
			found = name
		}
	}
	return found
}

// runsTail reports a child exec whose argv is the wrapper's tail. A native
// source's command line is that argv as the wrapper passed it. Tetragon's
// names the child's resolved binary in place of argv[0]; there the child
// must be a Tetragon exec whose command line is its own binary and then the
// tail's arguments, exactly.
func (held *heldWrapper) runsTail(event plane.Event) bool {
	if !held.resolved {
		return event.Cmdline == held.tail
	}
	if event.Source != plane.SourceTetragon || event.Exe == "" {
		return false
	}
	want := event.Exe
	if _, args, ok := strings.Cut(held.tail, " "); ok {
		want += " " + args
	}
	return event.Cmdline == want
}

// holdWrapperLocked holds a wrapper record from wrapperRecordLocked until
// its child exec, or records it, with the records linked to it, when the
// holds are full.
func (h *hostPlane) holdWrapperLocked(held *heldWrapper) {
	pid := held.event.PID
	if previous := h.wrappers[pid]; previous != nil {
		h.releaseWrapperLocked(pid, previous)
	}
	if len(h.wrappers)+h.linkedWrappers >= maxHeldWrappers {
		h.finishHeldLocked(held, true)
		return
	}
	if h.wrappers == nil {
		h.wrappers = make(map[int]*heldWrapper)
	}
	held.timer = time.AfterFunc(h.wrapperHold, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.wrappers[pid] == held {
			h.releaseWrapperLocked(pid, held)
		}
	})
	h.wrappers[pid] = held
}

// settleWrappersLocked decides the held wrappers an exec event can be the
// child of: the same pid (an exec in place, or timeout's fork execing) or
// its parent (timeout). The wrapper's record is dropped only when the child
// is the verified client image with the wrapper's argv tail and is not
// reported itself. A child with that tail whose own record is held (holder:
// its release manifest is not cached yet, or it is a transparent wrapper
// itself, at most maxWrapperChain wrappers in all) takes the wrapper with it,
// to be dropped or recorded when that hold ends. Any other child records it
// now.
// A fork that still runs the wrapper decides nothing.
func (h *hostPlane) settleWrappersLocked(event plane.Event, verifiedClient, reported bool, holder *heldWrapper) {
	if event.Kind != plane.KindExec || len(h.wrappers) == 0 {
		return
	}
	for _, pid := range [2]int{event.PID, event.PPID} {
		held := h.wrappers[pid]
		if pid <= 0 || held == nil || event.Cmdline == held.cmdline {
			continue
		}
		delete(h.wrappers, pid)
		switch {
		case !held.runsTail(event):
			h.finishHeldLocked(held, true)
		case verifiedClient && !reported:
			h.finishHeldLocked(held, false)
		case holder != nil && holder.level()+held.depth <= maxWrapperChain:
			held.timer.Stop()
			holder.linked = append(holder.linked, held)
			holder.depth = max(holder.depth, holder.level()+held.depth)
			h.linkedWrappers++
		default:
			h.finishHeldLocked(held, true)
		}
	}
}

func (h *hostPlane) releaseWrapperLocked(pid int, held *heldWrapper) {
	delete(h.wrappers, pid)
	h.finishHeldLocked(held, true)
}

// finishHeldLocked ends a held record and the wrapper records linked to it:
// all are recorded, or all are dropped.
func (h *hostPlane) finishHeldLocked(held *heldWrapper, record bool) {
	if held.timer != nil {
		held.timer.Stop()
	}
	if record {
		h.recordLocked(held.event, held.lineage, held.match, held.at, held.instance)
	}
	for _, linked := range held.linked {
		h.linkedWrappers--
		h.finishHeldLocked(linked, record)
	}
	held.linked = nil
}
