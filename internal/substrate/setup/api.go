// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// API is SubstrateAPI over the ateapi client: actors, atespaces, egress
// policies and access policies (the bootstrap writes those with a global
// owner's token).
type API struct {
	Client ateapi.Client
}

var _ SubstrateAPI = (*API)(nil)

// APIOptions say how a hook step reaches ate-api-server.
type APIOptions struct {
	Address    string
	ServerName string
	CAFile     string
	// TokenFile is the bearer token: the pod's projected ServiceAccount
	// token, or the global owner's token for the bootstrap.
	TokenFile string
}

// NewAPI connects the ateapi client.
func NewAPI(o APIOptions) (*API, error) {
	c, err := ateapi.New(ateapi.Options{Address: o.Address, ServerName: o.ServerName, CAFile: o.CAFile,
		Auth: ateapi.AuthServiceAccount, TokenFile: o.TokenFile})
	if err != nil {
		return nil, err
	}
	return &API{Client: c}, nil
}

// Close closes the connection.
func (a *API) Close() error { return a.Client.Close() }

// GetAtespace implements SubstrateAPI.
func (a *API) GetAtespace(ctx context.Context, name string) (bool, error) {
	_, err := a.Client.GetAtespace(ctx, name)
	if ateapi.IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

// CreateAtespace implements SubstrateAPI.
func (a *API) CreateAtespace(ctx context.Context, name string) error {
	_, err := a.Client.CreateAtespace(ctx, name)
	return err
}

// GetAccessPolicy implements SubstrateAPI.
func (a *API) GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error) {
	p, err := a.Client.GetAccessPolicy(ctx, atespace)
	if ateapi.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	out := &AccessPolicy{Atespace: atespace, UID: p.GetMetadata().GetUid(), Version: p.GetMetadata().GetVersion()}
	var bindings []Binding
	for _, b := range p.GetBindings() {
		bindings = append(bindings, Binding{Role: b.GetRole(), Members: append([]string{}, b.GetMembers()...)})
	}
	out.Bindings = mergeRoles(bindings)
	return out, nil
}

// PutAccessPolicy implements SubstrateAPI: create when UID is empty,
// otherwise update with the UID and version preconditions.
func (a *API) PutAccessPolicy(ctx context.Context, p AccessPolicy) error {
	msg := &ateapi.AccessPolicy{Metadata: &ateapi.ResourceMetadata{Uid: p.UID, Version: p.Version}}
	for _, b := range p.Bindings {
		msg.Bindings = append(msg.Bindings, &ateapi.Binding{Role: b.Role, Members: b.Members})
	}
	var err error
	if p.UID == "" {
		_, err = a.Client.CreateAccessPolicy(ctx, p.Atespace, msg)
	} else {
		_, err = a.Client.UpdateAccessPolicy(ctx, p.Atespace, msg)
	}
	return err
}

// ListActors implements SubstrateAPI.
func (a *API) ListActors(ctx context.Context, atespace string) ([]ActorRef, error) {
	actors, err := ateapi.AllActors(ctx, a.Client, atespace, ateapi.MaxPageSize)
	if err != nil {
		return nil, err
	}
	out := make([]ActorRef, 0, len(actors))
	for _, act := range actors {
		out = append(out, ActorRef{Atespace: act.GetMetadata().GetAtespace(), Name: act.GetMetadata().GetName()})
	}
	return out, nil
}

// GetEgressPolicy implements SubstrateAPI.
func (a *API) GetEgressPolicy(ctx context.Context, r ActorRef) (*EgressPolicy, error) {
	p, err := a.Client.GetActorEgressPolicy(ctx, ateapi.Ref(r.Atespace, r.Name))
	if ateapi.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("egress policy of %s: %w", r, err)
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
	_, err := a.Client.DeleteActorEgressPolicy(ctx, ateapi.Ref(r.Atespace, r.Name), nil)
	if ateapi.IsNotFound(err) {
		return nil
	}
	return err
}
