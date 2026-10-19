// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

var treeNames = []string{"tree-parent", "tree-child", "tree-grandchild"}

type heartbeatState struct {
	value         uint64
	size          int64
	modified      unix.Timespec
	device, inode uint64
}

// Held fixed files observe known synthetic writers, not arbitrary processes.
// Finite heartbeat stability corroborates the native terminal/wait evidence;
// it cannot establish universal absence of descendants on its own.
type treeObservation struct {
	work       *os.File // borrowed fixture capability
	ready      []*os.File
	heartbeats []*os.File
	evidence   treeHeartbeatEvidence
}

func (o *treeObservation) close() error {
	var errs []error
	for _, file := range append(o.ready, o.heartbeats...) {
		errs = append(errs, file.Close())
	}
	o.ready, o.heartbeats = nil, nil
	return errors.Join(errs...)
}

func treeFile(file *os.File, maximum int64) (unix.Stat_t, error) {
	var st unix.Stat_t
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Size < 0 || st.Size > maximum {
		return st, errors.New("fixed tree file metadata differed")
	}
	return st, nil
}

func (o *treeObservation) currentEntry(file *os.File, name string) error {
	current, err := openRelative(o.work, name, unix.O_RDONLY)
	if err != nil {
		return errors.New("fixed tree entry was unavailable")
	}
	d, i, one := identity(current)
	hd, hi, two := identity(file)
	if errors.Join(one, two, current.Close()) != nil || d != hd || i != hi {
		return errors.New("fixed tree entry identity changed")
	}
	return nil
}

func (o *treeObservation) snapshot() ([]heartbeatState, error) {
	if len(o.ready) != 3 || len(o.heartbeats) != 3 {
		return nil, errors.New("fixed tree observation inventory differed")
	}
	states := make([]heartbeatState, 3)
	for i, name := range treeNames {
		if st, err := treeFile(o.ready[i], int64(len(sentinel))); err != nil || st.Size != int64(len(sentinel)) {
			return nil, errors.New("fixed tree ready metadata changed")
		}
		marker := make([]byte, len(sentinel)+1)
		n, readErr := o.ready[i].ReadAt(marker, 0)
		if readErr != io.EOF || string(marker[:n]) != sentinel {
			return nil, errors.New("fixed tree ready bytes changed")
		}
		if err := o.currentEntry(o.ready[i], name+".ready"); err != nil {
			return nil, err
		}
		if err := o.currentEntry(o.heartbeats[i], name+".heartbeat"); err != nil {
			return nil, err
		}
		st, err := treeFile(o.heartbeats[i], 16)
		if err != nil {
			return nil, err
		}
		data := make([]byte, 17)
		n, err = o.heartbeats[i].ReadAt(data, 0)
		if err != nil && err != io.EOF {
			return nil, errors.New("fixed heartbeat read failed")
		}
		if n == 0 {
			states[i] = heartbeatState{device: uint64(st.Dev), inode: st.Ino}
			continue
		}
		value, parseErr := strconv.ParseUint(string(data[:n]), 10, 64)
		if n > 16 || parseErr != nil || value == 0 || value > 1000000 || strconv.FormatUint(value, 10) != string(data[:n]) {
			return nil, errors.New("fixed heartbeat bytes differed")
		}
		st, err = treeFile(o.heartbeats[i], 16)
		if err != nil {
			return nil, err
		}
		states[i] = heartbeatState{value, st.Size, st.Mtim, uint64(st.Dev), st.Ino}
	}
	return states, nil
}

func heartbeatProgress(before, after []heartbeatState) bool {
	if len(before) != 3 || len(after) != 3 {
		return false
	}
	for i := range before {
		if before[i].value == 0 || after[i].value <= before[i].value || after[i].modified == before[i].modified || after[i].device != before[i].device || after[i].inode != before[i].inode {
			return false
		}
	}
	return true
}

func (o *treeObservation) beforeCancel(ctx context.Context) error {
	if len(o.ready)+len(o.heartbeats) != 0 {
		return errors.New("fixed tree observation reused")
	}
	for _, name := range treeNames {
		ready, err := openRelative(o.work, name+".ready", unix.O_RDONLY)
		if ready != nil {
			o.ready = append(o.ready, ready)
		}
		if err != nil {
			return errors.New("fixed tree ready file missing")
		}
		if st, err := treeFile(ready, int64(len(sentinel))); err != nil || st.Size != int64(len(sentinel)) {
			return errors.New("fixed tree ready metadata differed")
		}
		data := make([]byte, len(sentinel)+1)
		n, err := ready.ReadAt(data, 0)
		if err != io.EOF || string(data[:n]) != sentinel {
			return errors.New("fixed tree ready bytes differed")
		}
		heartbeat, err := openRelative(o.work, name+".heartbeat", unix.O_RDONLY)
		if heartbeat != nil {
			o.heartbeats = append(o.heartbeats, heartbeat)
		}
		if err != nil {
			return errors.New("fixed tree heartbeat missing")
		}
	}
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	var first []heartbeatState
	for {
		current, err := o.snapshot()
		if err != nil {
			return err
		}
		if len(first) == 0 {
			if current[0].value != 0 && current[1].value != 0 && current[2].value != 0 {
				first = current
				for i := range current {
					o.evidence.Before[i] = current[i].value
				}
			}
		} else if heartbeatProgress(first, current) {
			for i := range current {
				o.evidence.Progressed[i] = current[i].value
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.New("fixed tree progress deadline exceeded")
		case <-ticker.C:
		}
	}
}

func (o *treeObservation) stableBeforeDestroy(ctx context.Context) error {
	o.evidence.StableSamples = 0
	first, err := o.snapshot()
	if err != nil || first[0].value == 0 || first[1].value == 0 || first[2].value == 0 {
		return errors.New("fixed post-terminal heartbeat missing")
	}
	for i := range first {
		o.evidence.Terminal[i] = first[i].value
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for sample := 0; sample < 6; sample++ {
		select {
		case <-ctx.Done():
			return errors.New("fixed heartbeat stability deadline exceeded")
		case <-ticker.C:
		}
		current, err := o.snapshot()
		if err != nil {
			return err
		}
		for i := range first {
			if first[i] != current[i] {
				return errors.New("fixed heartbeat continued after native terminal")
			}
		}
		o.evidence.StableSamples++
	}
	return nil
}
