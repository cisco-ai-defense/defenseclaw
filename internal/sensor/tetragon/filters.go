// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

package tetragon

import (
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// EventTypes are the only events the helper asks for: process exec and
// exit, kprobe and LSM hooks (DefenseClaw's file and connect policies), and
// the two loss signals.
var EventTypes = []pb.EventType{
	pb.EventType_PROCESS_EXEC,
	pb.EventType_PROCESS_EXIT,
	pb.EventType_PROCESS_KPROBE,
	pb.EventType_PROCESS_LSM,
	pb.EventType_PROCESS_THROTTLE,
	pb.EventType_RATE_LIMIT_INFO,
}

// processEventTypes carry process, parent and ancestors.
var processEventTypes = []pb.EventType{
	pb.EventType_PROCESS_EXEC,
	pb.EventType_PROCESS_EXIT,
	pb.EventType_PROCESS_KPROBE,
	pb.EventType_PROCESS_LSM,
}

// ExcludedFields are dropped by Tetragon before an event is sent. Ancestors
// are rebuilt from exec_id instead (they make an event 11-13 KB);
// environment variables can carry tokens; capabilities, namespaces,
// credentials and pod data are not used. binary_properties is kept on the
// process: it is how a setuid exec is seen.
var ExcludedFields = []string{
	"ancestors",
	"process.environment_variables",
	"process.cap",
	"process.ns",
	"process.process_credentials",
	"process.pod",
	"parent.environment_variables",
	"parent.cap",
	"parent.ns",
	"parent.process_credentials",
	"parent.pod",
	"parent.binary_properties",
}

// EventsRequest is the helper's GetEvents request: the event set above and
// the field exclusions. It carries no filter a caller could widen; the
// helper builds it, nobody sends it one.
func EventsRequest() *pb.GetEventsRequest {
	return &pb.GetEventsRequest{
		AllowList: []*pb.Filter{{EventSet: append([]pb.EventType(nil), EventTypes...)}},
		FieldFilters: []*pb.FieldFilter{{
			EventSet: append([]pb.EventType(nil), processEventTypes...),
			Fields:   &fieldmaskpb.FieldMask{Paths: append([]string(nil), ExcludedFields...)},
			Action:   pb.FieldFilterAction_EXCLUDE,
		}},
	}
}
