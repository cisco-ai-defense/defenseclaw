// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// The routing reads of the Windows own-status pipe: a standard account of a
// Windows standalone managed computer reads its own routing decisions and
// budgets (defenseclaw routing status, budgets list, explain) the way the
// managed hook socket answers on Linux and macOS. The pipe names the account
// from its client token; the routing handlers answer for that SID only.

type routingPipeCallerKey struct{}

// withRoutingPipeCaller marks a request as the routing read of the account
// sid on the own-status pipe.
func withRoutingPipeCaller(ctx context.Context, sid string) context.Context {
	return context.WithValue(ctx, routingPipeCallerKey{}, sid)
}

// routingPipeCallerFromContext returns the pipe caller's SID.
func routingPipeCallerFromContext(ctx context.Context) (string, bool) {
	sid, ok := ctx.Value(routingPipeCallerKey{}).(string)
	return sid, ok && sid != ""
}

// routingPipeAnswer serves one own routing read of path for sid and returns
// the pipe answer (status and JSON body), nil for a path the pipe does not
// serve.
func (a *APIServer) routingPipeAnswer(ctx context.Context, sid, path string) []byte {
	if sid == "" || !refusalpipe.ValidRoutingReadPath(path) {
		return nil
	}
	req, err := http.NewRequestWithContext(withRoutingPipeCaller(ctx, sid), http.MethodGet, path, nil)
	if err != nil {
		return nil
	}
	mux := http.NewServeMux()
	a.registerRoutingRoutes(mux)
	w := &routingPipeResponse{header: http.Header{}, status: http.StatusOK}
	mux.ServeHTTP(w, req)
	if w.over {
		return refusalpipe.EncodeRoutingAnswer(http.StatusInsufficientStorage, []byte(`{"error":"the routing answer is too large for the pipe; ask for fewer recent decisions"}`))
	}
	return refusalpipe.EncodeRoutingAnswer(w.status, w.body.Bytes())
}

// routingPipeResponse buffers one routing answer, bounded.
type routingPipeResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
	over   bool
}

func (w *routingPipeResponse) Header() http.Header    { return w.header }
func (w *routingPipeResponse) WriteHeader(status int) { w.status = status }
func (w *routingPipeResponse) Write(p []byte) (int, error) {
	if w.body.Len()+len(p) > refusalpipe.MaxRoutingAnswerBytes-256 {
		w.over = true
		return len(p), nil
	}
	return w.body.Write(p)
}
