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

package ateapi

import (
	"testing"

	// The OpenShell SDK options the gateway links. Both registering
	// extension 50000 on the descriptor options made this test binary, and
	// every gateway, panic at init (GAP-0014).
	_ "github.com/NVIDIA/OpenShell/sdk/go/proto/optionsv1"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

func TestStubsRegisterBesideOpenShellOptions(t *testing.T) {
	fd := pb.File_api_ateapi_v1_ateapi_proto
	if got, err := protoregistry.GlobalFiles.FindFileByPath("api/ateapi/v1/ateapi.proto"); err != nil || got != fd {
		t.Fatalf("ateapi.proto is not registered: %v", err)
	}
	if n := fd.Extensions().Len(); n != 0 {
		t.Fatalf("the stubs declare %d extensions; make proto must strip them (strip-options.awk)", n)
	}
	for i := 0; i < fd.Imports().Len(); i++ {
		if p := fd.Imports().Get(i).Path(); p == "google/protobuf/descriptor.proto" {
			t.Fatalf("the stubs still import %s", p)
		}
	}
	// The wire surface is upstream's: the Control service and its methods.
	svc := fd.Services().ByName("Control")
	if svc == nil || svc.Methods().Len() != 42 {
		t.Fatalf("Control service = %v", svc)
	}
	for _, name := range []protoreflect.Name{"GetActor", "ListActors", "UpdateActorEgressPolicy", "CreateTag", "ListAtespaces"} {
		if svc.Methods().ByName(name) == nil {
			t.Errorf("Control.%s is missing", name)
		}
	}
	if fd.Messages().ByName("EgressPolicy").Fields().ByName("rules").Number() != 2 {
		t.Fatal("EgressPolicy.rules moved")
	}
}
