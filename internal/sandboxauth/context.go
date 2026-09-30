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

package sandboxauth

import "context"

type requestContextKey struct{}

type requestScope struct {
	binding Binding
	view    *FSView
}

// WithRequest marks ctx as an authenticated sandbox request for b. Only the
// ingress authentication middleware may call it; its presence is what makes
// hook handlers apply the binding's contract, identity and filesystem view.
// A nil view builds one over the host filesystem.
func WithRequest(ctx context.Context, b Binding, view *FSView) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if view == nil {
		view = NewFSView(b, nil)
	}
	return context.WithValue(ctx, requestContextKey{}, requestScope{binding: cloneBinding(b), view: view})
}

// FromContext returns the authenticated binding of a sandbox request.
func FromContext(ctx context.Context) (Binding, bool) {
	scope, ok := scopeFrom(ctx)
	if !ok {
		return Binding{}, false
	}
	return cloneBinding(scope.binding), true
}

// ViewFromContext returns the filesystem view of a sandbox request. Host
// requests have none, and callers keep their host behaviour.
func ViewFromContext(ctx context.Context) (*FSView, bool) {
	scope, ok := scopeFrom(ctx)
	if !ok {
		return nil, false
	}
	return scope.view, true
}

func scopeFrom(ctx context.Context) (requestScope, bool) {
	if ctx == nil {
		return requestScope{}, false
	}
	scope, ok := ctx.Value(requestContextKey{}).(requestScope)
	return scope, ok
}
