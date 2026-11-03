// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"time"
)

// esMessage is the subset of the eslogger JSON envelope this sensor reads.
//
// eslogger emits the full ES message, which is large and version-dependent.
// Decoding only these fields means a macOS release that adds a member cannot
// break the parse.
type esMessage struct {
	EventType int             `json:"event_type"`
	Time      string          `json:"time"`
	Process   esProcess       `json:"process"`
	Event     json.RawMessage `json:"event"`
}

type esProcess struct {
	AuditToken      esAuditToken `json:"audit_token"`
	PPID            int          `json:"ppid"`
	ResponsibleAudi esAuditToken `json:"responsible_audit_token"`
	Executable      esFile       `json:"executable"`
}

type esAuditToken struct {
	PID int `json:"pid"`
	// EUID is the effective uid. A token without one names no account:
	// decoded as a plain int it would read as 0, which is root.
	EUID *int `json:"euid"`
}

type esFile struct {
	Path string `json:"path"`
}

type esEvent struct {
	Exec   *esExec   `json:"exec"`
	Open   *esOpen   `json:"open"`
	Create *esCreate `json:"create"`
	Rename *esRename `json:"rename"`
}

type esExec struct {
	Target esProcess `json:"target"`
	Args   []string  `json:"args"`
}

type esOpen struct {
	File esFile `json:"file"`
}

type esCreate struct {
	Destination struct {
		ExistingFile esFile `json:"existing_file"`
		NewPath      struct {
			Dir      esFile `json:"dir"`
			Filename string `json:"filename"`
		} `json:"new_path"`
	} `json:"destination"`
}

type esRename struct {
	Source esFile `json:"source"`
}

// Endpoint Security event type numbers used here. eslogger emits the numeric
// form, so these must match es_event_type_t in
// <EndpointSecurity/ESTypes.h> exactly -- the enum is positional, and a wrong
// number is not an error anywhere: the event simply never matches and the
// plane goes quiet about a whole tactic class. CREATE and EXIT were wrong for
// exactly that reason, so darwin_test.go asserts these against literals
// rather than against the constants themselves.
const (
	esEventTypeNotifyExec   = 9
	esEventTypeNotifyOpen   = 10
	esEventTypeNotifyCreate = 13
	esEventTypeNotifyExit   = 15
	esEventTypeNotifyRename = 25
)

// translateES turns one eslogger message into a plane event. watched are the
// path prefixes worth reporting; owner names the account of a uid without
// blocking (nil names none). It has no macOS dependency, so it is built and
// tested on every platform.
func translateES(message esMessage, watched []string, owner func(uid int) string) (Event, bool) {
	at := parseESTime(message.Time)
	base := Event{
		PID:            message.Process.AuditToken.PID,
		PPID:           message.Process.PPID,
		ResponsiblePID: message.Process.ResponsibleAudi.PID,
		Name:           filepath.Base(message.Process.Executable.Path),
		At:             at,
	}
	// The account of the process the message is about, from its audit
	// token: a session that exits before the next poll still names who ran
	// it (p0-round GAP-1389).
	base.UID, base.User = esAccount(message.Process.AuditToken, owner)

	var payload esEvent
	if len(message.Event) > 0 {
		if err := json.Unmarshal(message.Event, &payload); err != nil {
			// A message whose event member will not decode carries nothing
			// usable. Dropping it is right; carrying on into the switch with
			// a half-filled payload is how a nil dereference gets reached.
			return Event{}, false
		}
	}

	switch message.EventType {
	case esEventTypeNotifyExec:
		if payload.Exec == nil {
			return Event{}, false
		}
		base.Kind = KindExec
		base.PID = payload.Exec.Target.AuditToken.PID
		// The parent is the exec'ing process's parent, not the exec'ing
		// process itself.
		//
		// In an ES exec message, message.process is the same pid as the
		// target: a fork()ed child that is now replacing its image. Taking
		// its pid as the parent therefore set PPID == PID, which makes the
		// ancestry walk self-referential -- so every child of an agent
		// failed the lineage gate and Plane C on macOS could not attribute
		// anything to anything. Observed live: bash at 77949 spawning curl
		// at 77972 recorded 77972 as its own parent.
		base.PPID = message.Process.PPID
		base.ResponsiblePID = payload.Exec.Target.ResponsibleAudi.PID
		if base.ResponsiblePID == 0 {
			base.ResponsiblePID = base.PPID
		}
		base.Name = filepath.Base(payload.Exec.Target.Executable.Path)
		base.Cmdline = strings.Join(payload.Exec.Args, " ")
		// The new image's account, which a setuid target changes.
		base.UID, base.User = esAccount(payload.Exec.Target.AuditToken, owner)
		return base, true

	case esEventTypeNotifyExit:
		// No payload is needed: the exiting pid is the message's own process,
		// which base already carries.
		base.Kind = KindExit
		return base, true

	case esEventTypeNotifyOpen:
		if payload.Open == nil || !esInteresting(watched, payload.Open.File.Path) {
			return Event{}, false
		}
		base.Kind = KindFileRead
		base.Path = payload.Open.File.Path
		return base, true

	case esEventTypeNotifyCreate:
		if payload.Create == nil {
			return Event{}, false
		}
		path := payload.Create.Destination.ExistingFile.Path
		if path == "" && payload.Create.Destination.NewPath.Filename != "" {
			path = filepath.Join(
				payload.Create.Destination.NewPath.Dir.Path,
				payload.Create.Destination.NewPath.Filename,
			)
		}
		if !esInteresting(watched, path) {
			return Event{}, false
		}
		base.Kind = KindFileWrite
		base.Path = path
		return base, true

	case esEventTypeNotifyRename:
		if payload.Rename == nil || !esInteresting(watched, payload.Rename.Source.Path) {
			return Event{}, false
		}
		base.Kind = KindFileWrite
		base.Path = payload.Rename.Source.Path
		return base, true
	}
	return Event{}, false
}

// esInteresting filters file events down to the watched prefixes. Endpoint
// Security has no path filter, so without this the buffer would be saturated
// by ordinary build and browser traffic within a second.
func esInteresting(watched []string, path string) bool {
	if path == "" {
		return false
	}
	for _, prefix := range watched {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// esAccount is the effective uid an audit token carries and the name of its
// account. Endpoint Security puts the euid in every token; a token without
// one names no account. owner answers from a cache and never blocks the
// event loop, so the name may be empty the first time a uid is seen: the
// poll then names the uid (hostPlaneFindings).
func esAccount(token esAuditToken, owner func(uid int) string) (*int, string) {
	if token.EUID == nil || *token.EUID < 0 {
		return nil, ""
	}
	uid := *token.EUID
	name := ""
	if owner != nil {
		name = owner(uid)
	}
	return &uid, name
}

func parseESTime(value string) time.Time {
	if value == "" {
		return time.Now()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999 -0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Now()
}
