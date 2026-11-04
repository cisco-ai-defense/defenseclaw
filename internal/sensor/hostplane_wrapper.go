// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sensor

import (
	"regexp"
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

// holdWrapperLocked keeps the record of a transparent wrapper exec whose
// match comes from the command it wraps, when that command would not be
// reported as the verified Claude client, until the wrapped exec shows
// whether it is that client. It reports false when the record is to be
// made now.
func (h *hostPlane) holdWrapperLocked(
	event plane.Event, lineage agentchain.Lineage, match tactics.Match, at time.Time, instance agentchain.Instance,
) bool {
	if h.wrapperHold <= 0 || event.Kind != plane.KindExec || event.PID <= 0 ||
		h.indicators.KeepClientMCP || h.clientChecksums == nil {
		return false
	}
	prefix, tail, ok := wrapperTail(event.Name, event.Cmdline)
	if !ok {
		return false
	}
	// A signal the wrapper's own arguments carry is never held, whatever the
	// tail gives: an MCP reference in an env assignment is reported even when
	// the tail names the same package (IN-g55 review 1).
	own := tactics.Observation{
		Kind: string(plane.KindExec), PID: event.PID, Name: event.Name, Cmdline: commandWordCmdline(prefix),
	}
	if _, ok := tactics.Classify(own, h.indicators); ok {
		return false
	}
	// The wrapper's match must be the tail's own, and the tail run by the
	// verified client must be no match at all.
	child := tactics.Observation{
		Kind: string(plane.KindExec), PID: event.PID, Name: tactics.BaseName(strings.SplitN(tail, " ", 2)[0]),
		Cmdline: commandWordCmdline(tail),
	}
	if asOther, ok := tactics.Classify(child, h.indicators); !ok || asOther.SignalID != match.SignalID {
		return false
	}
	child.ClaudeClient = true
	if _, ok := tactics.Classify(child, h.indicators); ok {
		return false
	}
	if previous := h.wrappers[event.PID]; previous != nil {
		h.releaseWrapperLocked(event.PID, previous)
	}
	if len(h.wrappers) >= maxHeldWrappers {
		return false
	}
	if h.wrappers == nil {
		h.wrappers = make(map[int]*heldWrapper)
	}
	held := &heldWrapper{
		cmdline: event.Cmdline, tail: tail, event: event, lineage: lineage, match: match, at: at, instance: instance,
	}
	pid := event.PID
	held.timer = time.AfterFunc(h.wrapperHold, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.wrappers[pid] == held {
			h.releaseWrapperLocked(pid, held)
		}
	})
	h.wrappers[pid] = held
	return true
}

// settleWrappersLocked decides the held wrappers an exec event can be the
// child of: the same pid (an exec in place, or timeout's fork execing) or
// its parent (timeout). The wrapper's record is dropped only when the child
// is the verified client image with the wrapper's argv tail and is not
// reported itself; any other child records it now. A fork that still runs
// the wrapper decides nothing.
func (h *hostPlane) settleWrappersLocked(event plane.Event, verifiedClient, reported bool) {
	for _, pid := range [2]int{event.PID, event.PPID} {
		held := h.wrappers[pid]
		if pid <= 0 || held == nil || event.Cmdline == held.cmdline {
			continue
		}
		if verifiedClient && !reported && event.Cmdline == held.tail {
			held.timer.Stop()
			delete(h.wrappers, pid)
			continue
		}
		h.releaseWrapperLocked(pid, held)
	}
}

func (h *hostPlane) releaseWrapperLocked(pid int, held *heldWrapper) {
	held.timer.Stop()
	delete(h.wrappers, pid)
	h.recordLocked(held.event, held.lineage, held.match, held.at, held.instance)
}
