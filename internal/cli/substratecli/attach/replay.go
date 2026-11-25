// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
)

// Key replay modes (substrate.launcher.key_replay, --key-replay, B3.1).
const (
	// KeyReplayAsk shows the keys typed while disconnected and sends them
	// only when the person presses Enter (the default).
	KeyReplayAsk = "ask"
	// KeyReplayOn sends them as soon as the relay greets the new connection.
	KeyReplayOn = "on"
	// KeyReplayOff never sends them; the person is told how many were lost.
	KeyReplayOff = "off"
)

// Replay limits (D3.1-2): past either one nothing is replayed, because a
// cut-off sequence is worse than none.
const (
	ReplayMaxBytes = 4 << 10
	ReplayMaxAge   = 60 * time.Second
)

// askKey is the key that answers a DefenseClaw ask (Ctrl-\). Keys typed
// while disconnected never answer one, so the buffer ends there.
const askKey = 0x1c

// replayRank orders the modes from the tightest: a launcher flag can only
// lower the cluster value (D3.1-3).
func replayRank(m string) int {
	switch m {
	case KeyReplayOff:
		return 0
	case KeyReplayAsk:
		return 1
	case KeyReplayOn:
		return 2
	}
	return -1
}

// ValidKeyReplay reports whether m is a key replay mode.
func ValidKeyReplay(m string) bool { return replayRank(m) >= 0 }

// TightestKeyReplay returns the tighter of the cluster value and the flag;
// an empty or unknown cluster value counts as the default (ask) and an empty
// flag changes nothing.
func TightestKeyReplay(cluster, flag string) string {
	if !ValidKeyReplay(cluster) {
		cluster = KeyReplayAsk
	}
	if ValidKeyReplay(flag) && replayRank(flag) < replayRank(cluster) {
		return flag
	}
	return cluster
}

// outageBuf holds, in memory only, the input that did not reach the agent
// while the link was down: first the chunks the relay client read but could
// not send (they were typed earlier), then the keys typed during the outage.
// count is every such byte, kept or not; the bytes are kept only within the
// replay limits and up to an ask key. Cleared bytes are zeroed (a typed
// password must not linger).
type outageBuf struct {
	mu     sync.Mutex
	unsent []byte
	typed  []byte
	first  time.Time
	count  int64
	spoilt bool
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (o *outageBuf) addLocked(dst *[]byte, b []byte, now time.Time) {
	o.count += int64(len(b))
	if o.spoilt || len(b) == 0 {
		return
	}
	if bytes.IndexByte(b, askKey) >= 0 {
		o.spoilLocked()
		return
	}
	if len(o.unsent)+len(o.typed)+len(b) > ReplayMaxBytes {
		o.spoilLocked()
		return
	}
	if o.first.IsZero() {
		o.first = now
	}
	*dst = append(*dst, b...)
}

// spoilLocked drops what is kept: nothing of this outage is replayed.
func (o *outageBuf) spoilLocked() {
	o.spoilt = true
	zero(o.unsent)
	zero(o.typed)
	o.unsent, o.typed = nil, nil
}

// addUnsent keeps a chunk the relay client read but could not send. It
// zeroes b (the client's copy) once it is kept.
func (o *outageBuf) addUnsent(b []byte, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.addLocked(&o.unsent, b, now)
	zero(b)
}

// addTyped keeps keys typed while the link was down.
func (o *outageBuf) addTyped(b []byte, now time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.addLocked(&o.typed, b, now)
}

// spoil drops what is kept (the count stays): nothing is replayed.
func (o *outageBuf) spoil() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.spoilLocked()
}

// arrived drops the first n unsent bytes: the relay counts them as
// received, so they reached the agent. When more arrived than is kept
// unsent, what is kept no longer lines up with what is missing, and
// nothing is replayed.
func (o *outageBuf) arrived(n int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.count = max(o.count-n, 0)
	if o.spoilt {
		return
	}
	if n > int64(len(o.unsent)) {
		o.spoilLocked()
		return
	}
	zero(o.unsent[:n])
	o.unsent = o.unsent[n:]
}

// held reports that what was kept so far may still be replayed.
func (o *outageBuf) held() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.spoilt && o.count > 0
}

// pending is how many bytes did not reach the agent so far.
func (o *outageBuf) pending() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.count
}

// take ends the outage: it returns the bytes to replay (nil when nothing may
// be replayed: past a limit, after an ask key, or none kept) and the count
// of every byte that did not reach the agent, and starts again. The caller
// owns the returned bytes and zeroes them after use.
func (o *outageBuf) take(now time.Time) ([]byte, int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := o.count
	var b []byte
	if !o.spoilt && len(o.unsent)+len(o.typed) > 0 && now.Sub(o.first) <= ReplayMaxAge {
		b = make([]byte, 0, len(o.unsent)+len(o.typed))
		b = append(append(b, o.unsent...), o.typed...)
	}
	o.resetLocked()
	return b, n
}

func (o *outageBuf) resetLocked() {
	zero(o.unsent)
	zero(o.typed)
	o.unsent, o.typed = nil, nil
	o.first, o.count, o.spoilt = time.Time{}, 0, false
}

// replayPreviewMax is how much of the kept input the ask line shows.
const replayPreviewMax = 40

// replayPreview shows the kept keys on one line, controls as ^X.
func replayPreview(b []byte) string {
	var sb strings.Builder
	shown := 0
	for len(b) > 0 && shown < replayPreviewMax {
		r, n := utf8.DecodeRune(b)
		b = b[n:]
		shown++
		switch {
		case r == utf8.RuneError && n <= 1:
			sb.WriteString("?")
		case r < 0x20:
			sb.WriteByte('^')
			sb.WriteByte(byte(r) + '@')
		case r == 0x7f:
			sb.WriteString("^?")
		default:
			sb.WriteString(safetext.Clean(string(r)))
		}
	}
	if len(b) > 0 {
		sb.WriteString("...")
	}
	return sb.String()
}

// replayAskText is the line the person answers in ask mode.
func replayAskText(b []byte) string {
	return fmt.Sprintf("%d keys typed while disconnected: \"%s\". Enter sends them, Esc drops them.", len(b), replayPreview(b))
}

// notSentText is the count message when nothing is replayed.
func notSentText(n int64) string {
	return fmt.Sprintf("%d typed character(s) were not sent; type them again.", n)
}
