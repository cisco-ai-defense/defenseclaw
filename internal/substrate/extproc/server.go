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

package extproc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	filterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Server is the ext_proc v3 ExternalProcessor. Envoy opens one stream per
// request.
type Server struct {
	extprocv3.UnimplementedExternalProcessorServer
	eng *Engine
}

// NewServer serves eng.
func NewServer(eng *Engine) *Server { return &Server{eng: eng} }

// overrideMode is the one mode #3817's filter allows an override to: request
// and response headers sent, both bodies buffered, trailers skipped. Envoy
// ignores an override that matches no allowed_override_modes entry, so the
// response body of an inspected request is buffered too.
func overrideMode() *filterv3.ProcessingMode {
	return &filterv3.ProcessingMode{
		RequestHeaderMode:   filterv3.ProcessingMode_SEND,
		ResponseHeaderMode:  filterv3.ProcessingMode_SEND,
		RequestBodyMode:     filterv3.ProcessingMode_BUFFERED,
		ResponseBodyMode:    filterv3.ProcessingMode_BUFFERED,
		RequestTrailerMode:  filterv3.ProcessingMode_SKIP,
		ResponseTrailerMode: filterv3.ProcessingMode_SKIP,
	}
}

type streamState struct {
	req          *Request
	verdict      Verdict
	awaitingBody bool
	finished     bool
}

// Process implements ExternalProcessorServer.
func (s *Server) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	var st streamState
	signal := signalError
	defer func() { s.end(&st, signal) }()
	for {
		msg, err := stream.Recv()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				signal = signalEOF
				return nil
			case status.Code(err) == codes.Canceled:
				signal = signalCanceled
				return nil
			}
			return err
		}
		resp, done := s.handle(stream.Context(), &st, msg)
		if resp != nil {
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// end closes a stream, or handles a response phase while a body is
// awaited. A requested body that never came is recorded with how the
// stream ended (detection weighs the signal, GAP-0045), and the request's
// event says it went on uninspected: the filter already sent it.
func (s *Server) end(st *streamState, signal string) {
	if st.awaitingBody {
		st.awaitingBody = false
		s.eng.body.missed(st.req.Actor.Atespace+"/"+st.req.Actor.Name, signal)
		st.verdict.Alert = true
		st.verdict.Findings = append(st.verdict.Findings, "body_not_received:"+signal)
		s.finish(st)
	}
}

func (s *Server) finish(st *streamState) {
	if st.req != nil && !st.finished {
		st.finished = true
		s.eng.Finish(st.req, st.verdict)
	}
}

func (s *Server) handle(ctx context.Context, st *streamState, msg *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, bool) {
	switch r := msg.Request.(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		if st.req != nil {
			return headersContinue(nil), false
		}
		st.req = s.eng.requestFrom(msg, r.RequestHeaders)
		st.verdict = s.eng.DecideHeaders(ctx, st.req)
		if !st.verdict.Allow {
			s.finish(st)
			return s.eng.immediate(st.req, st.verdict), true
		}
		resp := headersContinue(nil)
		if !st.verdict.OwnHost {
			resp = headersContinue(decisionMutation(decisionValue(st.verdict)))
		}
		if st.verdict.WantBody {
			resp.ModeOverride = overrideMode()
			st.awaitingBody = true
		} else {
			s.finish(st)
		}
		return resp, false
	case *extprocv3.ProcessingRequest_RequestBody:
		if st.awaitingBody && st.req != nil {
			st.awaitingBody = false
			s.eng.body.arrived()
			st.verdict = s.eng.DecideBody(ctx, st.req, st.verdict, r.RequestBody.GetBody())
			s.finish(st)
			if !st.verdict.Allow {
				return s.eng.immediate(st.req, st.verdict), true
			}
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}, false
	case *extprocv3.ProcessingRequest_RequestTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestTrailers{
			RequestTrailers: &extprocv3.TrailersResponse{}}}, false
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		// A response phase before the requested body: the filter ignored
		// the override and sent the request on.
		s.end(st, signalResponse)
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{}}}}, false
	case *extprocv3.ProcessingRequest_ResponseBody:
		s.end(st, signalResponse)
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{}}}}, false
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{}}}, false
	}
	return nil, false
}

func headersContinue(m *extprocv3.HeaderMutation) *extprocv3.ProcessingResponse {
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
		RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{HeaderMutation: m}}}}
}

func decisionMutation(value string) *extprocv3.HeaderMutation {
	return &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{setHeader(DecisionHeader, value)}}
}

func setHeader(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{Header: &corev3.HeaderValue{Key: k, RawValue: []byte(v)},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD}
}

// immediate is the refusal: 403 (503 when the callout could not decide)
// with the DefenseClaw JSON body.
func (e *Engine) immediate(req *Request, v Verdict) *extprocv3.ProcessingResponse {
	code := typev3.StatusCode_Forbidden
	if v.Retryable {
		code = typev3.StatusCode_ServiceUnavailable
	}
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: code},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{
				setHeader("content-type", "application/json"),
				setHeader(DecisionHeader, "block"),
			}},
			Body:    e.refusalBody(req, v),
			Details: "defenseclaw_egress_blocked",
		}}}
}

// requestFrom builds a Request from the first message.
func (e *Engine) requestFrom(msg *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders) *Request {
	req := &Request{ContentLength: -1, EndOfStream: h.GetEndOfStream(), Start: e.now()}
	req.Actor, req.IdentityErr = actorFromAttributes(msg.GetAttributes(), e.cfg.ActorTrustDomain)
	for _, hv := range h.GetHeaders().GetHeaders() {
		v := hv.GetValue()
		if v == "" {
			v = string(hv.GetRawValue())
		}
		name := strings.ToLower(hv.GetKey())
		req.Headers = append(req.Headers, Header{Name: name, Value: v})
		switch name {
		case ":method":
			req.Method = strings.ToUpper(v)
		case ":scheme":
			req.Scheme = v
		case ":authority":
			req.Authority = v
		case ":path":
			req.Path = v
		case "content-length":
			if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && n >= 0 {
				req.ContentLength = n
			}
		case "content-type":
			req.ContentType = v
		case "accept":
			req.Accept = v
		}
	}
	if req.Authority == "" {
		req.Authority = req.header("host")
	}
	if host, _, err := splitAuthority(req.Authority); err == nil {
		req.Host = host
	}
	return req
}

// TLSOptions are the callout's listener credentials.
type TLSOptions struct {
	// Bundle is a PEM file holding the key and chain (the servicedns
	// podCertificate credential bundle), read again on every handshake so
	// rotation needs no restart.
	Bundle string
	// ClientCA verifies the egress gateway's client certificate (the
	// podidentity CA). It is required: without a verified chain any pod
	// could present a self-signed certificate naming the egress SPIFFE ID
	// (GAP-0065).
	ClientCA string
	// Peers are the SPIFFE IDs allowed to connect (Config.EgressPeers).
	Peers []string
}

// ServerTLS builds the listener's TLS config.
func ServerTLS(o TLSOptions) (*tls.Config, error) {
	if o.Bundle == "" {
		return nil, errors.New("extproc: a TLS credential bundle is required")
	}
	if o.ClientCA == "" {
		return nil, errors.New("extproc: a client CA is required to verify the egress gateway (--client-ca)")
	}
	var mu sync.Mutex
	var cached *tls.Certificate
	var cachedMod time.Time
	load := func() (*tls.Certificate, error) {
		st, err := os.Stat(o.Bundle)
		if err != nil {
			return nil, err
		}
		mu.Lock()
		defer mu.Unlock()
		if cached != nil && st.ModTime().Equal(cachedMod) {
			return cached, nil
		}
		b, err := os.ReadFile(o.Bundle)
		if err != nil {
			return nil, err
		}
		c, err := tls.X509KeyPair(b, b)
		if err != nil {
			return nil, err
		}
		cached, cachedMod = &c, st.ModTime()
		return cached, nil
	}
	if _, err := load(); err != nil {
		return nil, fmt.Errorf("extproc: TLS bundle: %w", err)
	}
	peers := map[string]bool{}
	for _, p := range o.Peers {
		peers[p] = true
	}
	pem, err := os.ReadFile(o.ClientCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("extproc: client CA file has no certificates")
	}
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      pool,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return load() },
	}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("extproc: no client certificate")
		}
		for _, u := range cs.PeerCertificates[0].URIs {
			if peers[u.String()] {
				return nil
			}
		}
		return errors.New("extproc: client certificate is not an allowed egress gateway")
	}
	return cfg, nil
}

// NewGRPCServer returns a gRPC server with the processor registered; a nil
// tlsCfg serves plaintext (tests and local development only).
func NewGRPCServer(eng *Engine, tlsCfg *tls.Config, opts ...grpc.ServerOption) *grpc.Server {
	if tlsCfg != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsCfg)))
	}
	g := grpc.NewServer(opts...)
	extprocv3.RegisterExternalProcessorServer(g, NewServer(eng))
	return g
}
