// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
	"unicode"
)

// Pause is the root break-glass. While it is active no policy is loaded or
// configured in enforce mode, and every enforcing policy moves to monitor
// within seconds (visibility stays). It survives helper restarts, package
// upgrades and Tetragon restarts because it is a file, not helper memory; the
// until-reboot form lives in the runtime directory and does not survive a
// reboot.
type Pause struct {
	Until       time.Time `json:"until,omitempty"`
	UntilReboot bool      `json:"until_reboot,omitempty"`
	SetByUID    int       `json:"set_by_uid"`
	SetAt       time.Time `json:"set_at"`
	Reason      string    `json:"reason,omitempty"`
}

// PauseState is what ReadPause found.
type PauseState struct {
	// Pause is the active pause, if any.
	Pause *Pause `json:"pause,omitempty"`
	// Invalid is set when a pause file exists but cannot be trusted or
	// parsed. It is treated as a pause: the only error that may leave
	// enforcement off.
	Invalid string `json:"invalid,omitempty"`
}

// Active reports whether enforcement must stay off.
func (p PauseState) Active() bool { return p.Pause != nil || p.Invalid != "" }

const maxReasonLen = 256

// NewPause validates a pause request. duration zero means the default (4h);
// the maximum is 7d. untilReboot ignores the duration.
func NewPause(now time.Time, duration time.Duration, untilReboot bool, uid int, reason string) (Pause, error) {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxReasonLen {
		return Pause{}, fmt.Errorf("pause reason is longer than %d bytes", maxReasonLen)
	}
	for _, r := range reason {
		if !unicode.IsPrint(r) {
			return Pause{}, errors.New("pause reason has a non-printable character")
		}
	}
	p := Pause{SetByUID: uid, SetAt: now.UTC(), Reason: reason}
	if untilReboot {
		p.UntilReboot = true
		return p, nil
	}
	if duration == 0 {
		duration = DefaultPauseFor
	}
	if duration < 0 || duration > MaxPauseFor {
		return Pause{}, fmt.Errorf("pause duration must be positive and at most %s", MaxPauseFor)
	}
	p.Until = now.Add(duration).UTC()
	return p, nil
}

// Expired reports whether a timed pause ran out.
func (p Pause) Expired(now time.Time) bool {
	return !p.UntilReboot && !now.Before(p.Until)
}

// WritePause records the pause: durable, or in the runtime directory for
// until-reboot. Only one of the two files exists afterwards.
func WritePause(dirs Dirs, p Pause) error {
	target, other := dirs.Pause(), dirs.RuntimePause()
	if p.UntilReboot {
		target, other = other, target
	}
	if err := writeJSON(target, p); err != nil {
		return err
	}
	if err := os.Remove(other); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ClearPause removes both pause files.
func ClearPause(dirs Dirs) error {
	var first error
	for _, path := range []string{dirs.Pause(), dirs.RuntimePause()} {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

// pauseFileTrusted admits a pause file only when root owns it and nobody else
// can write it: a pause is accepted from root alone. Tests replace it.
var pauseFileTrusted = rootOwnedPrivate

// ReadPause returns the active pause. Expired pauses are ignored. A file that
// is not a trusted regular file, or does not parse, is an Invalid pause.
func ReadPause(dirs Dirs, now time.Time) PauseState {
	var out PauseState
	for _, path := range []string{dirs.Pause(), dirs.RuntimePause()} {
		info, err := os.Lstat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || !pauseFileTrusted(info) {
			out.Invalid = path + ": not a root-owned regular file"
			continue
		}
		var p Pause
		if err := readJSON(path, &p); err != nil || (!p.UntilReboot && p.Until.IsZero()) {
			out.Invalid = path + ": unreadable"
			continue
		}
		if p.Expired(now) {
			continue
		}
		if out.Pause == nil || p.UntilReboot || (!out.Pause.UntilReboot && p.Until.After(out.Pause.Until)) {
			copyP := p
			out.Pause = &copyP
		}
	}
	return out
}

// removeExpiredPause deletes timed pause files that ran out.
func removeExpiredPause(dirs Dirs, now time.Time) {
	for _, path := range []string{dirs.Pause(), dirs.RuntimePause()} {
		var p Pause
		if err := readJSON(path, &p); err == nil && !p.UntilReboot && !p.Until.IsZero() && p.Expired(now) {
			_ = os.Remove(path)
		}
	}
}
