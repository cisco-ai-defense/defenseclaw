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
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gopkg.in/yaml.v3"

	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// DialOptions configure Dial.
type DialOptions struct {
	// InfoPath is Tetragon's discovery file (default DefaultInfoPath).
	InfoPath string
	// Scope is what the session may ask for. Required.
	Scope Scope
	// trust is root in production; tests use their own uid.
	trust *trustPolicy
}

// maxEventBytes bounds one received message. An event with ancestors is
// 11-13 KB; a policy list of a busy agent is the largest reply.
const maxEventBytes = 16 << 20

// connectTimeout bounds the pre-check connect.
const connectTimeout = 5 * time.Second

// Client is one checked session to Tetragon.
type Client struct {
	conn    *grpc.ClientConn
	api     pb.FineGuidanceSensorsClient
	scope   Scope
	info    Info
	socket  string
	version Version
}

// Dial opens a session: it reads the info file, refuses anything but a
// root-owned unix socket served by the Tetragon pid, and (in the consume and
// policy scopes) asks GetVersion, refusing a version outside the supported
// window. Every later connect the gRPC channel makes repeats the peer check,
// so a Tetragon restart (a new pid) cannot be followed silently: the session
// fails and the caller dials again, re-reading the info file.
func Dial(ctx context.Context, options DialOptions) (*Client, error) {
	if !supported() {
		return nil, refuse(ReasonUnavailable, nil, "Tetragon is Linux only")
	}
	if options.Scope != ScopeConsume && options.Scope != ScopePolicy && options.Scope != ScopeCleanup {
		return nil, fmt.Errorf("tetragon: no session scope")
	}
	trust := rootTrust
	if options.trust != nil {
		trust = *options.trust
	}
	info, err := readInfo(options.InfoPath, trust)
	if err != nil {
		return nil, err
	}
	socket, ok := info.SocketPath()
	if !ok {
		return nil, refuse(ReasonTCPAPI, nil,
			"Tetragon serves its API on %q, not on an absolute unix socket path; a TCP API lets any local account load kernel policies, so set its server-address to a unix socket", info.ServerAddress)
	}
	if err := trust.checkSocket(socket); err != nil {
		return nil, err
	}

	// Check the peer once before building the channel, so a refusal names
	// its reason instead of surfacing as a generic RPC failure.
	pid := info.PID
	connectPeer := func(ctx context.Context) (net.Conn, error) {
		var dialer net.Dialer
		conn, err := dialer.DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, refuse(ReasonUnavailable, err, "connect %s: %v", socket, err)
		}
		if err := trust.checkPeer(conn, pid); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
	preCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	pre, err := connectPeer(preCtx)
	cancel()
	if err != nil {
		return nil, err
	}
	_ = pre.Close()

	conn, err := grpc.NewClient("passthrough:///tetragon",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return connectPeer(ctx) }),
		grpc.WithUnaryInterceptor(options.Scope.unaryInterceptor()),
		grpc.WithStreamInterceptor(options.Scope.streamInterceptor()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxEventBytes)),
	)
	if err != nil {
		return nil, refuse(ReasonUnavailable, err, "gRPC client: %v", err)
	}
	client := &Client{conn: conn, api: pb.NewFineGuidanceSensorsClient(conn), scope: options.Scope, info: info, socket: socket}
	if options.Scope.Allows(pb.FineGuidanceSensors_GetVersion_FullMethodName) {
		reply, err := client.api.GetVersion(ctx, &pb.GetVersionRequest{})
		if err != nil {
			_ = conn.Close()
			return nil, refuse(ReasonUnavailable, err, "GetVersion: %v", err)
		}
		version, ok := ParseVersion(reply.GetVersion())
		if !ok || !SupportFor(version).Consume {
			_ = conn.Close()
			return nil, refuse(ReasonUnsupportedVersion, nil,
				"Tetragon %q is outside the supported 1.6 and 1.7 releases", reply.GetVersion())
		}
		client.version = version
	}
	return client, nil
}

// Info is the discovery file this session was opened from (its pid
// identifies the Tetragon process).
func (c *Client) Info() Info { return c.info }

// Socket is the unix socket the session uses.
func (c *Client) Socket() string { return c.socket }

// Version is what GetVersion answered (zero in the cleanup scope).
func (c *Client) Version() Version { return c.version }

// Scope is the session's allowlist.
func (c *Client) Scope() Scope { return c.scope }

// Close ends the session.
func (c *Client) Close() error { return c.conn.Close() }

// ServerInfo is GetInfo's answer (Tetragon 1.7 and later).
type ServerInfo struct {
	Version string
	// Probes are Tetragon's feature probes by name (lsm, override, ...).
	Probes map[string]bool
	// Conf is the agent's configuration, values rendered as text.
	Conf map[string]string
}

// KeepSensorsOnExit reports keep-sensors-on-exit, and whether conf said.
// With it set, stopping Tetragon leaves pinned programs enforcing with
// frozen anchors, so enforcement is refused; unknown counts as set.
func (i ServerInfo) KeepSensorsOnExit() (value, known bool) {
	raw, ok := i.Conf["keep-sensors-on-exit"]
	if !ok {
		return true, false
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return true, false
	}
	return parsed, true
}

// Probe reports a feature probe, and whether GetInfo listed it.
func (i ServerInfo) Probe(name string) (enabled, known bool) {
	enabled, known = i.Probes[name]
	return enabled, known
}

// GetInfo asks for the agent's probes and configuration. Tetragon 1.6 has
// no GetInfo; the error then says Unimplemented.
func (c *Client) GetInfo(ctx context.Context) (ServerInfo, error) {
	reply, err := c.api.GetInfo(ctx, &pb.GetInfoRequest{})
	if err != nil {
		return ServerInfo{}, err
	}
	out := ServerInfo{Version: reply.GetVersion(), Probes: map[string]bool{}, Conf: map[string]string{}}
	for _, probe := range reply.GetProbes() {
		out.Probes[probe.GetName()] = probe.GetEnabled().GetValue()
	}
	for _, conf := range reply.GetConf() {
		out.Conf[conf.GetKey()] = anyText(conf.GetValue())
	}
	return out, nil
}

// anyText renders a GetInfo conf value. Tetragon wraps scalars in the
// well-known wrapper types; anything else is rendered as its type name, so
// an unexpected shape reads as unknown rather than as a value.
func anyText(value *anypb.Any) string {
	if value == nil {
		return ""
	}
	message, err := value.UnmarshalNew()
	if err != nil {
		return ""
	}
	switch v := message.(type) {
	case *wrapperspb.BoolValue:
		return strconv.FormatBool(v.GetValue())
	case *wrapperspb.StringValue:
		return v.GetValue()
	case *wrapperspb.Int32Value:
		return strconv.FormatInt(int64(v.GetValue()), 10)
	case *wrapperspb.Int64Value:
		return strconv.FormatInt(v.GetValue(), 10)
	case *wrapperspb.UInt32Value:
		return strconv.FormatUint(uint64(v.GetValue()), 10)
	case *wrapperspb.UInt64Value:
		return strconv.FormatUint(v.GetValue(), 10)
	case *wrapperspb.DoubleValue:
		return strconv.FormatFloat(v.GetValue(), 'g', -1, 64)
	}
	return string(message.ProtoReflect().Descriptor().FullName())
}

// Events opens the event stream with request (see EventsRequest).
func (c *Client) Events(ctx context.Context, request *pb.GetEventsRequest) (pb.FineGuidanceSensors_GetEventsClient, error) {
	return c.api.GetEvents(ctx, request)
}

// ListPolicies lists every loaded TracingPolicy, the customer's included.
func (c *Client) ListPolicies(ctx context.Context) ([]*pb.TracingPolicyStatus, error) {
	reply, err := c.api.ListTracingPolicies(ctx, &pb.ListTracingPoliciesRequest{})
	if err != nil {
		return nil, err
	}
	return reply.GetPolicies(), nil
}

// AddPolicy loads one TracingPolicy YAML document. The document must be a
// cluster-wide TracingPolicy whose name is a DefenseClaw name, so a rendering
// mistake cannot load a policy the cleanup would not retire. It returns the
// name it loaded.
func (c *Client) AddPolicy(ctx context.Context, document []byte) (string, error) {
	var header struct {
		Kind     string `yaml:"kind"`
		Metadata struct {
			Name      string `yaml:"name"`
			Namespace string `yaml:"namespace"`
		} `yaml:"metadata"`
	}
	if err := yaml.Unmarshal(document, &header); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "tetragon: policy YAML: %v", err)
	}
	name := header.Metadata.Name
	if _, ok := OwnPolicyFamily(name); !ok {
		return "", status.Errorf(codes.PermissionDenied, "tetragon: %q is not a DefenseClaw policy name", name)
	}
	if header.Kind != "TracingPolicy" || header.Metadata.Namespace != "" {
		return "", status.Errorf(codes.InvalidArgument,
			"tetragon: %s is a %q in namespace %q; want a cluster-wide TracingPolicy", name, header.Kind, header.Metadata.Namespace)
	}
	if _, err := c.api.AddTracingPolicy(ctx, &pb.AddTracingPolicyRequest{Yaml: string(document)}); err != nil {
		return "", err
	}
	return name, nil
}

// DeletePolicy unloads one policy by name. Only DefenseClaw-owned names may
// be deleted; the caller also requires the name in its own state.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	if _, ok := OwnPolicyFamily(name); !ok {
		return status.Errorf(codes.PermissionDenied, "tetragon: %q is not a DefenseClaw policy name", name)
	}
	_, err := c.api.DeleteTracingPolicy(ctx, &pb.DeleteTracingPolicyRequest{Name: name})
	return err
}

// ConfigurePolicy sets a DefenseClaw policy's mode (and optionally enables
// or disables it).
func (c *Client) ConfigurePolicy(ctx context.Context, name string, mode pb.TracingPolicyMode, enable *bool) error {
	if _, ok := OwnPolicyFamily(name); !ok {
		return status.Errorf(codes.PermissionDenied, "tetragon: %q is not a DefenseClaw policy name", name)
	}
	request := &pb.ConfigureTracingPolicyRequest{Name: name, Mode: &mode}
	if enable != nil {
		request.Enable = enable
	}
	_, err := c.api.ConfigureTracingPolicy(ctx, request)
	return err
}

// ownPolicyName is the only shape of policy name DefenseClaw loads:
// defenseclaw-<family>-<first 8 hex of the rendered YAML's sha256>.
var ownPolicyName = regexp.MustCompile(`^defenseclaw-(observe|connect|controls|controls-burnin)-[0-9a-f]{8}$`)

// OwnPolicyFamily returns the family (observe, connect, controls,
// controls-burnin) of a DefenseClaw policy name. A matching name is only a
// candidate: the helper's own state decides whether DefenseClaw loaded it.
func OwnPolicyFamily(name string) (string, bool) {
	match := ownPolicyName.FindStringSubmatch(name)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// PolicyMode renders a TracingPolicyMode: enforce, monitor, monitor_only or
// unknown. Only enforce enforces.
func PolicyMode(mode pb.TracingPolicyMode) string {
	switch mode {
	case pb.TracingPolicyMode_TP_MODE_ENFORCE:
		return "enforce"
	case pb.TracingPolicyMode_TP_MODE_MONITOR:
		return "monitor"
	case pb.TracingPolicyMode_TP_MODE_MONITOR_ONLY:
		return "monitor_only"
	}
	return "unknown"
}

// PolicyState renders a TracingPolicyState without its TP_STATE_ prefix,
// in lower case (enabled, load_error, ...).
func PolicyState(state pb.TracingPolicyState) string {
	name := strings.TrimPrefix(state.String(), "TP_STATE_")
	if _, known := pb.TracingPolicyState_name[int32(state)]; !known {
		return "unknown"
	}
	return strings.ToLower(name)
}

// Version is a parsed Tetragon release.
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

var versionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion parses GetVersion's answer (v1.7.1, possibly with a suffix).
func ParseVersion(raw string) (Version, bool) {
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return Version{Raw: raw}, false
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	return Version{Major: major, Minor: minor, Patch: patch, Raw: strings.TrimSpace(raw)}, true
}

func (v Version) String() string {
	if v.Raw != "" {
		return v.Raw
	}
	return fmt.Sprintf("v%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// Support is what a Tetragon release can be used for.
type Support struct {
	Consume, Observe, Enforce bool
}

// SupportFor is the support window: 1.7.x for everything (enforcement still
// needs the lsm probe and keep-sensors-on-exit off); 1.6.x consume only,
// because it has neither GetInfo nor TP_MODE_MONITOR_ONLY; anything else
// nothing.
func SupportFor(v Version) Support {
	switch {
	case v.Major == 1 && v.Minor == 7:
		return Support{Consume: true, Observe: true, Enforce: true}
	case v.Major == 1 && v.Minor == 6:
		return Support{Consume: true}
	}
	return Support{}
}
