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
	"context"
	"sort"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// Scope is what a session may ask Tetragon to do. The allowlist is fixed at
// compile time and enforced by a client interceptor, so a code path that
// tries anything else fails before a byte is sent.
type Scope int

const (
	// ScopeConsume (mode consume) reads: GetVersion, GetInfo, GetEvents,
	// ListTracingPolicies.
	ScopeConsume Scope = iota + 1
	// ScopePolicy (modes observe and enforce) adds AddTracingPolicy,
	// DeleteTracingPolicy and ConfigureTracingPolicy to the consume set.
	ScopePolicy
	// ScopeCleanup (the startup retire step in off and consume, and
	// --tetragon-cleanup) may only list and delete policies.
	ScopeCleanup
)

func (s Scope) String() string {
	switch s {
	case ScopeConsume:
		return "consume"
	case ScopePolicy:
		return "policy"
	case ScopeCleanup:
		return "cleanup"
	}
	return "none"
}

// ScopeForMode is the session scope of an enterprise.tetragon mode. Off has
// none: in off the helper never connects except for the retire step, which
// asks for ScopeCleanup itself.
func ScopeForMode(mode string) (Scope, bool) {
	switch mode {
	case "consume":
		return ScopeConsume, true
	case "observe", "enforce":
		return ScopePolicy, true
	}
	return 0, false
}

var (
	consumeMethods = []string{
		pb.FineGuidanceSensors_GetVersion_FullMethodName,
		pb.FineGuidanceSensors_GetInfo_FullMethodName,
		pb.FineGuidanceSensors_GetEvents_FullMethodName,
		pb.FineGuidanceSensors_ListTracingPolicies_FullMethodName,
	}
	policyMethods = []string{
		pb.FineGuidanceSensors_AddTracingPolicy_FullMethodName,
		pb.FineGuidanceSensors_DeleteTracingPolicy_FullMethodName,
		pb.FineGuidanceSensors_ConfigureTracingPolicy_FullMethodName,
	}
	cleanupMethods = []string{
		pb.FineGuidanceSensors_ListTracingPolicies_FullMethodName,
		pb.FineGuidanceSensors_DeleteTracingPolicy_FullMethodName,
	}
)

// AllowedMethods is the scope's RPC allowlist, sorted.
func AllowedMethods(scope Scope) []string {
	var methods []string
	switch scope {
	case ScopeConsume:
		methods = append(methods, consumeMethods...)
	case ScopePolicy:
		methods = append(append(methods, consumeMethods...), policyMethods...)
	case ScopeCleanup:
		methods = append(methods, cleanupMethods...)
	}
	sort.Strings(methods)
	return methods
}

// Allows reports whether the scope may call method.
func (s Scope) Allows(method string) bool {
	for _, allowed := range AllowedMethods(s) {
		if allowed == method {
			return true
		}
	}
	return false
}

func (s Scope) refusal(method string) error {
	return status.Errorf(codes.PermissionDenied, "tetragon: %s is not allowed in the %s scope", method, s)
}

func (s Scope) unaryInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if !s.Allows(method) {
			return s.refusal(method)
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

func (s Scope) streamInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if !s.Allows(method) {
			return nil, s.refusal(method)
		}
		return streamer(ctx, desc, cc, method, opts...)
	}
}
