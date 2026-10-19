// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package bridgeproto

import (
	"math"
	"sync"
)

type Phase string

const (
	PhaseNew        Phase = "new"
	PhasePreparing  Phase = "preparing"
	PhaseReady      Phase = "ready"
	PhaseLaunching  Phase = "launching"
	PhaseRunning    Phase = "running"
	PhaseStopping   Phase = "stopping"
	PhaseExited     Phase = "exited"
	PhaseDestroying Phase = "destroying"
	PhaseDestroyed  Phase = "destroyed"
	PhaseClosed     Phase = "closed"
)

// Conversation checks one session's ordered two-way protocol. It stores no
// stream bytes and starts no worker/queue. A failed admission permanently
// closes it; the supervisor must revoke grants and kill/wait its owned helper
// and workload even if no completion frame can be received. Protocol state is
// correlation, not proof that the native backend actually contained a process.
type Conversation struct {
	mu          sync.Mutex
	binding     Binding
	phase       Phase
	hostSeq     uint64
	bridgeSeq   uint64
	lastRequest uint64
	prepare     uint64
	launch      uint64
	wait        uint64
	destroy     uint64
	terminal    bool
	inputEOF    bool
	exited      bool
	resources   bool
	outputBytes uint64
	outputLimit uint32
}

func NewConversation(binding Binding) (*Conversation, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	return &Conversation{binding: binding, phase: PhaseNew}, nil
}

func (c *Conversation) Phase() Phase {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.phase
}

func (c *Conversation) refuse() error {
	c.phase = PhaseClosed
	return ErrProtocol
}

func (c *Conversation) valid(frame Frame, previous uint64) bool {
	return c.phase != "" && c.phase != PhaseClosed && c.phase != PhaseDestroyed &&
		previous != math.MaxUint64 && frame.Sequence == previous+1 && frame.Binding == c.binding && frame.Validate() == nil
}

func (c *Conversation) Host(frame Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid(frame, c.hostSeq) || frame.Request <= c.lastRequest {
		return c.refuse()
	}
	switch frame.Kind {
	case Prepare:
		if c.phase != PhaseNew {
			return c.refuse()
		}
		c.prepare, c.terminal, c.resources = frame.Request, frame.Plan.Terminal != nil, true
		c.outputLimit = frame.Plan.OutputLimit
		c.phase = PhasePreparing
	case Launch:
		if c.phase != PhaseReady {
			return c.refuse()
		}
		c.launch, c.phase = frame.Request, PhaseLaunching
	case Input:
		if c.phase != PhaseExited && (c.phase != PhaseRunning || c.inputEOF) {
			return c.refuse()
		}
	case InputEOF:
		if c.phase != PhaseExited && (c.phase != PhaseRunning || c.inputEOF) {
			return c.refuse()
		}
		c.inputEOF = true
	case Resize:
		if (c.phase != PhaseRunning && c.phase != PhaseExited) || !c.terminal {
			return c.refuse()
		}
	case Wait:
		if (c.phase != PhaseRunning && c.phase != PhaseStopping && c.phase != PhaseExited) || c.wait != 0 {
			return c.refuse()
		}
		c.wait = frame.Request
	case Cancel:
		if c.phase != PhaseRunning && c.phase != PhaseExited {
			return c.refuse()
		}
		if c.phase != PhaseExited {
			c.phase = PhaseStopping
		}
	case Destroy:
		if c.phase != PhaseReady && c.phase != PhaseRunning && c.phase != PhaseStopping && c.phase != PhaseExited {
			return c.refuse()
		}
		c.destroy, c.phase = frame.Request, PhaseDestroying
	default:
		return c.refuse()
	}
	c.hostSeq, c.lastRequest = frame.Sequence, frame.Request
	return nil
}

func (c *Conversation) Bridge(frame Frame) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.valid(frame, c.bridgeSeq) {
		return c.refuse()
	}
	switch frame.Kind {
	case Prepared:
		if c.phase != PhasePreparing || frame.Request != c.prepare {
			return c.refuse()
		}
		c.phase = PhaseReady
	case Started:
		if c.phase != PhaseLaunching || frame.Request != c.launch {
			return c.refuse()
		}
		c.phase = PhaseRunning
	case Output:
		if c.launch == 0 || c.exited || frame.Request != c.launch ||
			(c.phase != PhaseRunning && c.phase != PhaseStopping && c.phase != PhaseDestroying) ||
			c.terminal && frame.Data.Stream != "stdout" ||
			uint64(len(frame.Data.Bytes)) > uint64(c.outputLimit)-c.outputBytes {
			return c.refuse()
		}
		c.outputBytes += uint64(len(frame.Data.Bytes))
	case Exited:
		// Completion always refers to Launch. A Wait/Cancel/Input may be
		// travelling in the other direction after this event was emitted.
		if c.launch == 0 || c.exited || frame.Request != c.launch ||
			(c.phase != PhaseRunning && c.phase != PhaseStopping && c.phase != PhaseDestroying) {
			return c.refuse()
		}
		c.exited = true
		if c.phase != PhaseDestroying {
			c.phase = PhaseExited
		}
	case Destroyed:
		if c.phase != PhaseDestroying || frame.Request != c.destroy {
			return c.refuse()
		}
		c.phase, c.resources = PhaseDestroyed, false
	case Failed:
		// Failure is terminal and grants nothing, including for a prior
		// fire-and-forget input/resize command. Unknown future IDs refuse.
		if frame.Request > c.lastRequest {
			return c.refuse()
		}
		c.phase = PhaseClosed
	default:
		return c.refuse()
	}
	c.bridgeSeq = frame.Sequence
	return nil
}

// PeerClosed records channel loss. Its return value says preparation/workload
// resources may remain. The caller must always terminate/wait its owned helper;
// a false value never establishes process or descendant cleanup by itself.
func (c *Conversation) PeerClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.phase = PhaseClosed
	return c.resources
}
