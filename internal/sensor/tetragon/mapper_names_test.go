// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tetragon

import (
	"testing"

	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

func pathArg(p string) *pb.KprobeArgument {
	return &pb.KprobeArgument{Arg: &pb.KprobeArgument_PathArg{PathArg: &pb.KprobePath{Path: p}}}
}

func lsmOf(function string, args ...*pb.KprobeArgument) *pb.GetEventsResponse {
	process := &pb.Process{Pid: u32(9001), Uid: u32(1001), Binary: "/usr/bin/mv", ExecId: "mv-1"}
	return &pb.GetEventsResponse{Event: &pb.GetEventsResponse_ProcessLsm{ProcessLsm: &pb.ProcessLsm{
		Process: process, PolicyName: "defenseclaw-controls-0a1b2c3d", FunctionName: function, Args: args,
		Action: pb.KprobeAction_KPROBE_ACTION_OVERRIDE,
	}}}
}

// A refused rename onto authorized_keys or a hard link to it is a write of
// the authorized keys control, and the event names the protected path, not
// the other one.
func TestMapperNamesTheProtectedPathOfALinkOrRename(t *testing.T) {
	mapper := fixtureMapper(map[string]string{"defenseclaw-controls-0a1b2c3d": "enforce"})
	keys := fixtureHome + "/.ssh/authorized_keys"
	for _, tc := range []struct {
		name     string
		function string
		args     []*pb.KprobeArgument
		want     string
	}{
		{"rename onto", "security_path_rename", []*pb.KprobeArgument{pathArg(fixtureHome + "/tmp.keys"), pathArg(keys)}, keys},
		{"rename away", "security_path_rename", []*pb.KprobeArgument{pathArg(keys), pathArg(fixtureHome + "/old")}, keys},
		{"ssh dir replaced", "security_path_rename", []*pb.KprobeArgument{pathArg(fixtureHome + "/x"), pathArg(fixtureHome + "/.ssh")}, fixtureHome + "/.ssh"},
		{"hard link", "security_path_link", []*pb.KprobeArgument{pathArg(keys), pathArg("/tmp/k")}, keys},
		{"symlink at the name", "security_path_symlink", []*pb.KprobeArgument{pathArg(keys), pathArg(fixtureHome + "/.ssh")}, keys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := mapper.Map(lsmOf(tc.function, tc.args...))
			if len(batch.Events) != 1 {
				t.Fatalf("%d events", len(batch.Events))
			}
			event := batch.Events[0]
			if event.Path != tc.want || event.Control != ControlSSHAuthorizedKeysWrite || event.Kind != plane.KindFileWrite ||
				event.Outcome != plane.OutcomeBlocked {
				t.Fatalf("event %+v", event)
			}
		})
	}
	// A write open of the file maps to the same control.
	open := mapper.Map(lsmOf("security_file_open", &pb.KprobeArgument{Arg: &pb.KprobeArgument_FileArg{FileArg: &pb.KprobeFile{Path: keys}}}))
	if len(open.Events) != 1 || open.Events[0].Control != ControlSSHAuthorizedKeysWrite || open.Events[0].Kind != plane.KindFileWrite {
		t.Fatalf("open %+v", open.Events)
	}
	// The shell profile control is unchanged.
	if got := controlFor(fixtureHome + "/.bashrc"); got != ControlPersistenceWrite {
		t.Fatalf("controlFor(.bashrc) = %s", got)
	}
}
