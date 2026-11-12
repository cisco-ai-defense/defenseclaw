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
	"google.golang.org/grpc/credentials"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// grpcAccess is AccessAPI over A3's vendored control API stubs, for the
// calls ateapi.Client does not have yet (CreateAtespace and the access
// policy RPCs). Remove it once ateapi.Client has them. The bootstrap Job
// runs for seconds, so it reads the token and CA once.
type grpcAccess struct {
	conn *grpc.ClientConn
	ctl  pb.ControlClient
}

type bearer string

func (b bearer) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + string(b)}, nil
}
func (bearer) RequireTransportSecurity() bool { return true }

// DialAccess opens the AccessAPI connection.
func DialAccess(o APIOptions) (AccessAPI, error) {
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
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)), grpc.WithPerRPCCredentials(bearer(tok)))
	if err != nil {
		return nil, fmt.Errorf("ate-api %s: %w", o.Address, err)
	}
	return newGRPCAccess(conn), nil
}

func newGRPCAccess(conn *grpc.ClientConn) *grpcAccess {
	return &grpcAccess{conn: conn, ctl: pb.NewControlClient(conn)}
}

func (g *grpcAccess) Close() error { return g.conn.Close() }

func (g *grpcAccess) CreateAtespace(ctx context.Context, name string) error {
	_, err := g.ctl.CreateAtespace(ctx, &pb.CreateAtespaceRequest{Atespace: &pb.Atespace{Metadata: &pb.ResourceMetadata{Name: name}}})
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

func (g *grpcAccess) GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error) {
	var p *pb.AccessPolicy
	var err error
	if atespace == "" {
		p, err = g.ctl.GetGlobalAccessPolicy(ctx, &pb.GetGlobalAccessPolicyRequest{Name: "default"})
	} else {
		p, err = g.ctl.GetAtespaceAccessPolicy(ctx, &pb.GetAtespaceAccessPolicyRequest{Atespace: &pb.ObjectRef{Name: atespace}, Name: "default"})
	}
	if ateapi.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromPB(atespace, p), nil
}

func (g *grpcAccess) PutAccessPolicy(ctx context.Context, p AccessPolicy) error {
	msg := toPB(p)
	ref := &pb.ObjectRef{Name: p.Atespace}
	var err error
	switch {
	case p.Atespace == "" && p.UID == "":
		_, err = g.ctl.CreateGlobalAccessPolicy(ctx, &pb.CreateGlobalAccessPolicyRequest{AccessPolicy: msg})
	case p.Atespace == "":
		_, err = g.ctl.UpdateGlobalAccessPolicy(ctx, &pb.UpdateGlobalAccessPolicyRequest{AccessPolicy: msg})
	case p.UID == "":
		_, err = g.ctl.CreateAtespaceAccessPolicy(ctx, &pb.CreateAtespaceAccessPolicyRequest{Atespace: ref, AccessPolicy: msg})
	default:
		_, err = g.ctl.UpdateAtespaceAccessPolicy(ctx, &pb.UpdateAtespaceAccessPolicyRequest{Atespace: ref, AccessPolicy: msg})
	}
	return err
}
