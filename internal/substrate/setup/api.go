// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// APIOptions say how a hook step reaches ate-api-server.
type APIOptions struct {
	Address    string
	ServerName string
	CAFile     string
	// TokenFile is the bearer token: the pod's projected ServiceAccount
	// token, or the global owner's token for the bootstrap.
	TokenFile string
}

// API is SubstrateAPI over the Substrate v1.0.0 control API. Hook Jobs run
// for seconds, so it reads the token and CA once.
type API struct {
	conn *grpc.ClientConn
	ctl  pb.ControlClient
}

var _ SubstrateAPI = (*API)(nil)

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}
func (bearer) RequireTransportSecurity() bool { return true }

// DialAPI connects to ate-api-server.
func DialAPI(o APIOptions) (*API, error) {
	if o.Address == "" {
		o.Address = ateapi.DefaultAddress
	}
	if o.ServerName == "" {
		o.ServerName = ateapi.DefaultServerName
	}
	token, err := os.ReadFile(o.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("ate-api token: %w", err)
	}
	tok := strings.TrimSpace(string(token))
	if tok == "" || strings.ContainsAny(tok, " \t\r\n") {
		return nil, errors.New("ate-api token file must hold one token")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: o.ServerName}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("ate-api CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ate-api CA: no certificate")
		}
		cfg.RootCAs = pool
	}
	conn, err := grpc.NewClient("dns:///"+o.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithPerRPCCredentials(bearer(tok)))
	if err != nil {
		return nil, fmt.Errorf("ate-api %s: %w", o.Address, err)
	}
	return &API{conn: conn, ctl: pb.NewControlClient(conn)}, nil
}

// Close closes the connection.
func (a *API) Close() error { return a.conn.Close() }

func notFound(err error) bool { return status.Code(err) == codes.NotFound }

// GetAtespace implements SubstrateAPI.
func (a *API) GetAtespace(ctx context.Context, name string) (bool, error) {
	_, err := a.ctl.GetAtespace(ctx, &pb.GetAtespaceRequest{Atespace: &pb.ObjectRef{Name: name}})
	if notFound(err) {
		return false, nil
	}
	return err == nil, err
}

// CreateAtespace implements SubstrateAPI.
func (a *API) CreateAtespace(ctx context.Context, name string) error {
	_, err := a.ctl.CreateAtespace(ctx, &pb.CreateAtespaceRequest{Atespace: &pb.Atespace{Metadata: &pb.ResourceMetadata{Name: name}}})
	return err
}

func fromPB(atespace string, p *pb.AccessPolicy) *AccessPolicy {
	out := &AccessPolicy{Atespace: atespace, UID: p.GetMetadata().GetUid(), Version: p.GetMetadata().GetVersion()}
	for _, b := range p.GetBindings() {
		out.Bindings = append(out.Bindings, Binding{Role: b.GetRole(), Members: append([]string{}, b.GetMembers()...)})
	}
	return out
}

func toPB(p AccessPolicy) *pb.AccessPolicy {
	out := &pb.AccessPolicy{Metadata: &pb.ResourceMetadata{Atespace: p.Atespace, Name: "default", Uid: p.UID, Version: p.Version}}
	for _, b := range p.Bindings {
		out.Bindings = append(out.Bindings, &pb.Binding{Role: b.Role, Members: b.Members})
	}
	return out
}

// GetAccessPolicy implements SubstrateAPI.
func (a *API) GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error) {
	var p *pb.AccessPolicy
	var err error
	if atespace == "" {
		p, err = a.ctl.GetGlobalAccessPolicy(ctx, &pb.GetGlobalAccessPolicyRequest{Name: "default"})
	} else {
		p, err = a.ctl.GetAtespaceAccessPolicy(ctx, &pb.GetAtespaceAccessPolicyRequest{Atespace: &pb.ObjectRef{Name: atespace}, Name: "default"})
	}
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromPB(atespace, p), nil
}

// PutAccessPolicy implements SubstrateAPI.
func (a *API) PutAccessPolicy(ctx context.Context, p AccessPolicy) error {
	msg := toPB(p)
	var err error
	switch {
	case p.Atespace == "" && p.UID == "":
		msg.Metadata.Atespace = ""
		_, err = a.ctl.CreateGlobalAccessPolicy(ctx, &pb.CreateGlobalAccessPolicyRequest{AccessPolicy: msg})
	case p.Atespace == "":
		_, err = a.ctl.UpdateGlobalAccessPolicy(ctx, &pb.UpdateGlobalAccessPolicyRequest{AccessPolicy: msg})
	case p.UID == "":
		_, err = a.ctl.CreateAtespaceAccessPolicy(ctx, &pb.CreateAtespaceAccessPolicyRequest{Atespace: &pb.ObjectRef{Name: p.Atespace}, AccessPolicy: msg})
	default:
		_, err = a.ctl.UpdateAtespaceAccessPolicy(ctx, &pb.UpdateAtespaceAccessPolicyRequest{Atespace: &pb.ObjectRef{Name: p.Atespace}, AccessPolicy: msg})
	}
	return err
}

// ListActors implements SubstrateAPI, following every page.
func (a *API) ListActors(ctx context.Context, atespace string) ([]ActorRef, error) {
	var out []ActorRef
	token := ""
	for range 10000 {
		resp, err := a.ctl.ListActors(ctx, &pb.ListActorsRequest{Atespace: atespace,
			Options: &pb.ListOptions{PageSize: ateapi.MaxPageSize, PageToken: token}})
		if err != nil {
			return nil, err
		}
		for _, act := range resp.GetActors() {
			out = append(out, ActorRef{Atespace: act.GetMetadata().GetAtespace(), Name: act.GetMetadata().GetName()})
		}
		if token = resp.GetNextPageToken(); token == "" {
			return out, nil
		}
	}
	return nil, errors.New("ListActors: too many pages")
}

// GetEgressPolicy implements SubstrateAPI.
func (a *API) GetEgressPolicy(ctx context.Context, r ActorRef) (*EgressPolicy, error) {
	p, err := a.ctl.GetActorEgressPolicy(ctx, &pb.GetActorEgressPolicyRequest{
		Actor: &pb.ObjectRef{Atespace: r.Atespace, Name: r.Name}, Name: ateapi.PolicyName})
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &EgressPolicy{Actor: r}
	for _, rule := range p.GetRules() {
		out.Hostnames = append(out.Hostnames, rule.GetHttp().GetHostnames()...)
		out.Hostnames = append(out.Hostnames, rule.GetHttps().GetHostnames()...)
		out.Hostnames = append(out.Hostnames, rule.GetTlsPassthrough().GetHostnames()...)
	}
	return out, nil
}

// DeleteEgressPolicy implements SubstrateAPI.
func (a *API) DeleteEgressPolicy(ctx context.Context, r ActorRef) error {
	_, err := a.ctl.DeleteActorEgressPolicy(ctx, &pb.DeleteActorEgressPolicyRequest{
		Actor: &pb.ObjectRef{Atespace: r.Atespace, Name: r.Name}, Name: ateapi.PolicyName})
	if notFound(err) {
		return nil
	}
	return err
}
