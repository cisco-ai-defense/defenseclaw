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

// Package ateapi is DefenseClaw's client for the Agent Substrate control API
// (substrate.ateapi.v1.Control, vendored from v1.0.0 under
// third_party/substrate). It exposes the calls the Substrate controller,
// gateway and callout need behind the Client interface, authenticates the way
// upstream documents for in-cluster pods (a projected ServiceAccount token, or
// a pod certificate, both reread from disk), verifies ate-api-server against
// the servicedns trust bundle, spreads calls across replicas and rate-limits
// itself. Package ateapifake is an in-memory Client for tests.
package ateapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// Substrate API types, re-exported so callers import one package.
type (
	Actor                = pb.Actor
	ActorState           = pb.ActorState
	ActorStatus          = pb.ActorStatus
	ActorTemplate        = pb.ActorTemplate
	Atespace             = pb.Atespace
	Tag                  = pb.Tag
	TagScope             = pb.TagScope
	TagStatus            = pb.TagStatus
	EgressPolicy         = pb.EgressPolicy
	EgressRule           = pb.EgressRule
	HttpRule             = pb.HttpRule
	HttpsRule            = pb.HttpsRule
	TlsPassthroughRule   = pb.TlsPassthroughRule
	Ports                = pb.Ports
	AllPorts             = pb.AllPorts
	HttpRuleEffects      = pb.HttpRuleEffects
	CredentialHeader     = pb.CredentialHeader
	ActorJwtSource       = pb.ActorJwtSource
	ObjectRef            = pb.ObjectRef
	ResourceMetadata     = pb.ResourceMetadata
	DeleteOptions        = pb.DeleteOptions
	DurabilityMode       = pb.DurabilityMode
	ControlClient        = pb.ControlClient
	ControlServer        = pb.ControlServer
	UnimplementedControl = pb.UnimplementedControlServer
)

// Actor states.
const (
	ActorStateUnspecified = pb.ActorState_ACTOR_STATE_UNSPECIFIED
	ActorStateResuming    = pb.ActorState_ACTOR_STATE_RESUMING
	ActorStateRunning     = pb.ActorState_ACTOR_STATE_RUNNING
	ActorStateSuspending  = pb.ActorState_ACTOR_STATE_SUSPENDING
	ActorStateSuspended   = pb.ActorState_ACTOR_STATE_SUSPENDED
	ActorStateCrashed     = pb.ActorState_ACTOR_STATE_CRASHED
	ActorStateDeleting    = pb.ActorState_ACTOR_STATE_DELETING
	ActorStateReverting   = pb.ActorState_ACTOR_STATE_REVERTING
)

// RegisterControlServer registers a Control implementation on a gRPC server
// (tests and fakes).
func RegisterControlServer(s grpc.ServiceRegistrar, srv ControlServer) {
	pb.RegisterControlServer(s, srv)
}

const (
	// PolicyName is the only name an actor's singleton EgressPolicy may have.
	PolicyName = "default"
	// DefaultAddress is ate-api-server's in-cluster Service (headless; one
	// address per replica).
	DefaultAddress = "api.ate-system.svc:443"
	// DefaultServerName is the TLS name ate-api-server's serving certificate
	// carries, whatever address is dialed.
	DefaultServerName = "api.ate-system.svc"
	// DefaultTokenFile and DefaultCAFile are where the controller chart
	// projects the ServiceAccount token (audience api.ate-system.svc) and the
	// servicedns.podcert.ate.dev/identity trust bundle.
	DefaultTokenFile = "/var/run/ate/token"
	DefaultCAFile    = "/var/run/ate/ca.crt"
	// DefaultCredentialBundle is the projected pod certificate (private key
	// followed by its chain) used when Auth is AuthMTLS.
	DefaultCredentialBundle = "/var/run/ate/credential-bundle.pem"
	// PreviewHeader opts a call in to preview features; the server must
	// also run with the matching --preview gate.
	PreviewHeader = "ate-preview-allowed"
	// MaxPageSize is the page size ate-api-server coerces larger requests to.
	MaxPageSize = 1000
)

// Auth selects how the client authenticates to ate-api-server.
type Auth string

const (
	// AuthServiceAccount sends a bearer token read from TokenFile on every
	// call (the kubelet rotates it). The principal is
	// system:serviceaccount:<namespace>:<name>. It is also how a token from
	// another cluster or a CI identity provider is sent.
	AuthServiceAccount Auth = "serviceaccount"
	// AuthMTLS presents the pod certificate in CredentialBundle, reread on
	// every handshake. The principal is the SPIFFE ID in its URI SAN.
	AuthMTLS Auth = "mtls"
)

// ParseAuth maps a config value to an Auth; empty means serviceaccount.
func ParseAuth(s string) (Auth, error) {
	switch Auth(strings.ToLower(strings.TrimSpace(s))) {
	case "", AuthServiceAccount:
		return AuthServiceAccount, nil
	case AuthMTLS:
		return AuthMTLS, nil
	}
	return "", fmt.Errorf("ateapi: auth %q is not serviceaccount or mtls", s)
}

// ListOptions are the pagination controls of a List call.
type ListOptions struct {
	// PageSize is the requested page size; zero lets the server choose and
	// values above MaxPageSize are coerced by the server.
	PageSize int32
	// PageToken is the NextPageToken of the previous page; empty for the
	// first page.
	PageToken string
}

// Page is one page of a List call. A page may be empty while more remain.
type Page[T any] struct {
	Items         []T
	NextPageToken string
}

// Client is the part of the Substrate control API DefenseClaw uses. All
// methods are safe for concurrent use. Errors keep their gRPC status, so
// IsNotFound, IsConflict and the other helpers below apply.
type Client interface {
	GetActor(ctx context.Context, actor *ObjectRef) (*Actor, error)
	ListActors(ctx context.Context, atespace string, opts ListOptions) (Page[*Actor], error)
	// SuspendActor checkpoints a running actor (asynchronous durability:
	// it returns once the snapshot is on the node).
	SuspendActor(ctx context.Context, actor *ObjectRef) (*Actor, error)

	GetActorEgressPolicy(ctx context.Context, actor *ObjectRef) (*EgressPolicy, error)
	// CreateActorEgressPolicy creates the actor's policy. The policy's
	// metadata atespace and name are filled from actor and PolicyName.
	CreateActorEgressPolicy(ctx context.Context, actor *ObjectRef, policy *EgressPolicy) (*EgressPolicy, error)
	// UpdateActorEgressPolicy replaces the policy; policy.Metadata must
	// carry the uid and version last read (ABORTED otherwise).
	UpdateActorEgressPolicy(ctx context.Context, actor *ObjectRef, policy *EgressPolicy) (*EgressPolicy, error)
	DeleteActorEgressPolicy(ctx context.Context, actor *ObjectRef, opts *DeleteOptions) (*EgressPolicy, error)

	CreateTag(ctx context.Context, tag *Tag) (*Tag, error)
	GetTag(ctx context.Context, tag *ObjectRef) (*Tag, error)

	GetActorTemplate(ctx context.Context, template *ObjectRef) (*ActorTemplate, error)
	ListActorTemplates(ctx context.Context, atespace string, opts ListOptions) (Page[*ActorTemplate], error)

	GetAtespace(ctx context.Context, name string) (*Atespace, error)
	ListAtespaces(ctx context.Context, opts ListOptions) (Page[*Atespace], error)

	Close() error
}

// Options configures New.
type Options struct {
	// Address is host:port of ate-api-server; DefaultAddress when empty.
	Address string
	// ServerName is the TLS name to verify; DefaultServerName when empty.
	ServerName string
	// CAFile is the PEM trust bundle for ate-api-server's serving
	// certificate, reread when it changes (the bundle rotates). Empty means
	// the system roots, for an ate-api-server behind a public certificate.
	CAFile string
	// Auth selects the credential; AuthServiceAccount when empty.
	Auth Auth
	// TokenFile is the bearer token for AuthServiceAccount;
	// DefaultTokenFile when empty.
	TokenFile string
	// CredentialBundle is the pod certificate for AuthMTLS;
	// DefaultCredentialBundle when empty.
	CredentialBundle string
	// Preview sends the Ate-Preview-Allowed header on every call.
	Preview bool
	// ReadQPS/ReadBurst and WriteQPS/WriteBurst are the client-side rate
	// limits for Get/List calls and for every other call. Zero picks the
	// defaults (50/100 reads, 25/50 writes); a negative QPS disables a
	// limiter.
	ReadQPS, WriteQPS     float64
	ReadBurst, WriteBurst int
	// CallTimeout bounds a call whose context has no deadline (10 s when
	// zero).
	CallTimeout time.Duration
	// ContextDialer replaces the network dialer (tests). When set the
	// target is dialed as given, without DNS round robin.
	ContextDialer func(ctx context.Context, addr string) (net.Conn, error)
}

const (
	defaultReadQPS     = 50
	defaultReadBurst   = 100
	defaultWriteQPS    = 25
	defaultWriteBurst  = 50
	defaultCallTimeout = 10 * time.Second
)

// GRPCClient is the Client over a gRPC connection to ate-api-server.
type GRPCClient struct {
	conn  *grpc.ClientConn
	ctl   pb.ControlClient
	read  *rate.Limiter
	write *rate.Limiter
}

var _ Client = (*GRPCClient)(nil)

// New connects to ate-api-server. The connection is lazy: New fails only on
// bad options or unreadable credential files, and calls fail with
// Unavailable while the server can't be reached.
func New(opts Options) (*GRPCClient, error) {
	o, err := opts.withDefaults()
	if err != nil {
		return nil, err
	}
	tc, err := newTLSSource(o.CAFile, o.ServerName, o.Auth, o.CredentialBundle)
	if err != nil {
		return nil, err
	}
	dial := []grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(tc.config())),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	}
	if o.Auth == AuthServiceAccount {
		tok := &tokenSource{path: o.TokenFile}
		if _, err := tok.token(); err != nil {
			return nil, err
		}
		dial = append(dial, grpc.WithPerRPCCredentials(tok))
	}
	c := &GRPCClient{
		read:  limiter(o.ReadQPS, o.ReadBurst),
		write: limiter(o.WriteQPS, o.WriteBurst),
	}
	dial = append(dial, grpc.WithChainUnaryInterceptor(c.interceptor(o.Preview, o.CallTimeout)))
	var target string
	if o.ContextDialer != nil {
		dial = append(dial, grpc.WithContextDialer(o.ContextDialer))
		target = "passthrough:///" + o.Address
	} else {
		// The api Service is headless: DNS returns one address per replica,
		// and upstream asks clients to spread calls across them.
		dial = append(dial, grpc.WithDefaultServiceConfig(`{"loadBalancingConfig":[{"round_robin":{}}]}`))
		target = "dns:///" + o.Address
	}
	conn, err := grpc.NewClient(target, dial...)
	if err != nil {
		return nil, fmt.Errorf("ateapi: connect %s: %w", o.Address, err)
	}
	c.conn = conn
	c.ctl = pb.NewControlClient(conn)
	return c, nil
}

func (o Options) withDefaults() (Options, error) {
	if o.Address == "" {
		o.Address = DefaultAddress
	}
	if _, _, err := net.SplitHostPort(o.Address); err != nil {
		return o, fmt.Errorf("ateapi: address %q: %w", o.Address, err)
	}
	if o.ServerName == "" {
		o.ServerName = DefaultServerName
	}
	auth, err := ParseAuth(string(o.Auth))
	if err != nil {
		return o, err
	}
	o.Auth = auth
	if o.TokenFile == "" {
		o.TokenFile = DefaultTokenFile
	}
	if o.CredentialBundle == "" {
		o.CredentialBundle = DefaultCredentialBundle
	}
	if o.ReadQPS == 0 {
		o.ReadQPS, o.ReadBurst = defaultReadQPS, max(o.ReadBurst, defaultReadBurst)
	}
	if o.WriteQPS == 0 {
		o.WriteQPS, o.WriteBurst = defaultWriteQPS, max(o.WriteBurst, defaultWriteBurst)
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = defaultCallTimeout
	}
	return o, nil
}

func limiter(qps float64, burst int) *rate.Limiter {
	if qps < 0 {
		return nil
	}
	if burst < 1 {
		burst = max(1, int(qps))
	}
	return rate.NewLimiter(rate.Limit(qps), burst)
}

// isRead reports whether a full method name is a Get or List call.
func isRead(method string) bool {
	name := method[strings.LastIndexByte(method, '/')+1:]
	return strings.HasPrefix(name, "Get") || strings.HasPrefix(name, "List")
}

func (c *GRPCClient) interceptor(preview bool, timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		lim := c.write
		if isRead(method) {
			lim = c.read
		}
		if lim != nil {
			if err := lim.Wait(ctx); err != nil {
				if ctx.Err() != nil {
					return status.FromContextError(ctx.Err()).Err()
				}
				// The limiter refuses up front when the wait would pass
				// the deadline.
				return status.Error(codes.DeadlineExceeded, "ateapi: client rate limit wait exceeds the call deadline")
			}
		}
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, timeout)
			defer cancel()
		}
		if preview {
			ctx = metadata.AppendToOutgoingContext(ctx, PreviewHeader, "true")
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// Close closes the connection.
func (c *GRPCClient) Close() error { return c.conn.Close() }

func (c *GRPCClient) GetActor(ctx context.Context, actor *ObjectRef) (*Actor, error) {
	return c.ctl.GetActor(ctx, &pb.GetActorRequest{Actor: actor})
}

func (c *GRPCClient) ListActors(ctx context.Context, atespace string, opts ListOptions) (Page[*Actor], error) {
	resp, err := c.ctl.ListActors(ctx, &pb.ListActorsRequest{Atespace: atespace, Options: listOptions(opts)})
	if err != nil {
		return Page[*Actor]{}, err
	}
	return Page[*Actor]{Items: resp.GetActors(), NextPageToken: resp.GetNextPageToken()}, nil
}

func (c *GRPCClient) SuspendActor(ctx context.Context, actor *ObjectRef) (*Actor, error) {
	resp, err := c.ctl.SuspendActor(ctx, &pb.SuspendActorRequest{
		Actor:   actor,
		Options: &pb.SuspendOptions{Mode: pb.DurabilityMode_DURABILITY_MODE_ASYNCHRONOUS},
	})
	if err != nil {
		return nil, err
	}
	return resp.GetActor(), nil
}

func (c *GRPCClient) GetActorEgressPolicy(ctx context.Context, actor *ObjectRef) (*EgressPolicy, error) {
	return c.ctl.GetActorEgressPolicy(ctx, &pb.GetActorEgressPolicyRequest{Actor: actor, Name: PolicyName})
}

func (c *GRPCClient) CreateActorEgressPolicy(ctx context.Context, actor *ObjectRef, policy *EgressPolicy) (*EgressPolicy, error) {
	return c.ctl.CreateActorEgressPolicy(ctx, &pb.CreateActorEgressPolicyRequest{Actor: actor, EgressPolicy: withPolicyMeta(actor, policy)})
}

func (c *GRPCClient) UpdateActorEgressPolicy(ctx context.Context, actor *ObjectRef, policy *EgressPolicy) (*EgressPolicy, error) {
	if policy.GetMetadata().GetUid() == "" || policy.GetMetadata().GetVersion() == 0 {
		return nil, status.Error(codes.InvalidArgument, "ateapi: UpdateActorEgressPolicy needs the uid and version last read")
	}
	return c.ctl.UpdateActorEgressPolicy(ctx, &pb.UpdateActorEgressPolicyRequest{Actor: actor, EgressPolicy: withPolicyMeta(actor, policy)})
}

func (c *GRPCClient) DeleteActorEgressPolicy(ctx context.Context, actor *ObjectRef, opts *DeleteOptions) (*EgressPolicy, error) {
	return c.ctl.DeleteActorEgressPolicy(ctx, &pb.DeleteActorEgressPolicyRequest{Actor: actor, Name: PolicyName, Options: opts})
}

func (c *GRPCClient) CreateTag(ctx context.Context, tag *Tag) (*Tag, error) {
	return c.ctl.CreateTag(ctx, &pb.CreateTagRequest{Tag: tag})
}

func (c *GRPCClient) GetTag(ctx context.Context, tag *ObjectRef) (*Tag, error) {
	return c.ctl.GetTag(ctx, &pb.GetTagRequest{Tag: tag})
}

func (c *GRPCClient) GetActorTemplate(ctx context.Context, template *ObjectRef) (*ActorTemplate, error) {
	return c.ctl.GetActorTemplate(ctx, &pb.GetActorTemplateRequest{ActorTemplate: template})
}

func (c *GRPCClient) ListActorTemplates(ctx context.Context, atespace string, opts ListOptions) (Page[*ActorTemplate], error) {
	resp, err := c.ctl.ListActorTemplates(ctx, &pb.ListActorTemplatesRequest{Atespace: atespace, Options: listOptions(opts)})
	if err != nil {
		return Page[*ActorTemplate]{}, err
	}
	return Page[*ActorTemplate]{Items: resp.GetActorTemplates(), NextPageToken: resp.GetNextPageToken()}, nil
}

func (c *GRPCClient) GetAtespace(ctx context.Context, name string) (*Atespace, error) {
	return c.ctl.GetAtespace(ctx, &pb.GetAtespaceRequest{Atespace: &pb.ObjectRef{Name: name}})
}

func (c *GRPCClient) ListAtespaces(ctx context.Context, opts ListOptions) (Page[*Atespace], error) {
	resp, err := c.ctl.ListAtespaces(ctx, &pb.ListAtespacesRequest{Options: listOptions(opts)})
	if err != nil {
		return Page[*Atespace]{}, err
	}
	return Page[*Atespace]{Items: resp.GetAtespaces(), NextPageToken: resp.GetNextPageToken()}, nil
}

func listOptions(o ListOptions) *pb.ListOptions {
	if o.PageSize == 0 && o.PageToken == "" {
		return nil
	}
	return &pb.ListOptions{PageSize: o.PageSize, PageToken: o.PageToken}
}

// withPolicyMeta returns policy with its metadata atespace and name set from
// the parent actor, as admission requires. The caller's message is not
// modified.
func withPolicyMeta(actor *ObjectRef, policy *EgressPolicy) *EgressPolicy {
	out := &pb.EgressPolicy{Rules: policy.GetRules(), Metadata: &pb.ResourceMetadata{}}
	if m := policy.GetMetadata(); m != nil {
		out.Metadata.Uid = m.GetUid()
		out.Metadata.Version = m.GetVersion()
	}
	out.Metadata.Atespace = actor.GetAtespace()
	out.Metadata.Name = PolicyName
	return out
}

// Ref builds an ObjectRef.
func Ref(atespace, name string) *ObjectRef { return &pb.ObjectRef{Atespace: atespace, Name: name} }

// RefOf is the ObjectRef of a resource's metadata.
func RefOf(m *ResourceMetadata) *ObjectRef { return Ref(m.GetAtespace(), m.GetName()) }

// Key is "<atespace>/<name>", the form used in logs and maps.
func Key(r *ObjectRef) string { return r.GetAtespace() + "/" + r.GetName() }

// maxPages bounds a ListAll walk, so a server that keeps returning tokens
// can't loop a caller forever (1000 pages of 1000 is a million objects).
const maxPages = 1000

// ErrPagination means a List walk did not end: the server repeated a page
// token or returned more than maxPages pages.
var ErrPagination = errors.New("ateapi: list pagination did not terminate")

// ListAll walks every page of a List call, calling fn on each item in order.
// It stops at the first error from list or fn.
func ListAll[T any](ctx context.Context, pageSize int32, list func(context.Context, ListOptions) (Page[T], error), fn func(T) error) error {
	seen := map[string]bool{}
	opts := ListOptions{PageSize: pageSize}
	for range maxPages {
		page, err := list(ctx, opts)
		if err != nil {
			return err
		}
		for _, item := range page.Items {
			if err := fn(item); err != nil {
				return err
			}
		}
		if page.NextPageToken == "" {
			return nil
		}
		if seen[page.NextPageToken] {
			return ErrPagination
		}
		seen[page.NextPageToken] = true
		opts.PageToken = page.NextPageToken
	}
	return ErrPagination
}

// AllActors lists every actor in atespace ("" for all atespaces).
func AllActors(ctx context.Context, c Client, atespace string, pageSize int32) ([]*Actor, error) {
	var out []*Actor
	err := ListAll(ctx, pageSize, func(ctx context.Context, o ListOptions) (Page[*Actor], error) {
		return c.ListActors(ctx, atespace, o)
	}, func(a *Actor) error { out = append(out, a); return nil })
	return out, err
}

// AllActorTemplates lists every template in atespace ("" for all).
func AllActorTemplates(ctx context.Context, c Client, atespace string, pageSize int32) ([]*ActorTemplate, error) {
	var out []*ActorTemplate
	err := ListAll(ctx, pageSize, func(ctx context.Context, o ListOptions) (Page[*ActorTemplate], error) {
		return c.ListActorTemplates(ctx, atespace, o)
	}, func(t *ActorTemplate) error { out = append(out, t); return nil })
	return out, err
}

// AllAtespaces lists every atespace.
func AllAtespaces(ctx context.Context, c Client, pageSize int32) ([]*Atespace, error) {
	var out []*Atespace
	err := ListAll(ctx, pageSize, c.ListAtespaces, func(a *Atespace) error { out = append(out, a); return nil })
	return out, err
}

// IsNotFound reports a NOT_FOUND status.
func IsNotFound(err error) bool { return status.Code(err) == codes.NotFound }

// IsAlreadyExists reports an ALREADY_EXISTS status (a create that lost a race
// or is a retry).
func IsAlreadyExists(err error) bool { return status.Code(err) == codes.AlreadyExists }

// IsConflict reports ABORTED: a uid/version guard no longer matches, or
// another operation is changing the resource. Re-read and retry.
func IsConflict(err error) bool { return status.Code(err) == codes.Aborted }

// IsRetryable reports a transient failure worth retrying with backoff:
// UNAVAILABLE, RESOURCE_EXHAUSTED, DEADLINE_EXCEEDED or ABORTED.
func IsRetryable(err error) bool {
	switch status.Code(err) {
	case codes.Unavailable, codes.ResourceExhausted, codes.DeadlineExceeded, codes.Aborted:
		return true
	}
	return false
}

// IsAuth reports UNAUTHENTICATED or PERMISSION_DENIED: the credential is
// missing, expired or lacks an access-policy role.
func IsAuth(err error) bool {
	c := status.Code(err)
	return c == codes.Unauthenticated || c == codes.PermissionDenied
}
