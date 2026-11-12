// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"context"
	"errors"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// AccessAPI is what the bootstrap needs beyond ateapi.Client: creating an
// atespace and reading and writing access policies. ateapi.Client has no
// such calls yet; DialAccess supplies them until it does.
type AccessAPI interface {
	CreateAtespace(ctx context.Context, name string) error
	GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error)
	PutAccessPolicy(ctx context.Context, p AccessPolicy) error
	Close() error
}

// API is SubstrateAPI over the ateapi client (actors, atespaces, egress
// policies) and an AccessAPI (bootstrap only; nil elsewhere).
type API struct {
	Client ateapi.Client
	Access AccessAPI
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
	// WithAccess also opens the AccessAPI (the bootstrap).
	WithAccess bool
}

// NewAPI connects the ateapi client, and the AccessAPI when asked.
func NewAPI(o APIOptions) (*API, error) {
	c, err := ateapi.New(ateapi.Options{Address: o.Address, ServerName: o.ServerName, CAFile: o.CAFile,
		Auth: ateapi.AuthServiceAccount, TokenFile: o.TokenFile})
	if err != nil {
		return nil, err
	}
	api := &API{Client: c}
	if o.WithAccess {
		if api.Access, err = DialAccess(o); err != nil {
			_ = c.Close()
			return nil, err
		}
	}
	return api, nil
}

// Close closes both connections.
func (a *API) Close() error {
	err := a.Client.Close()
	if a.Access != nil {
		err = errors.Join(err, a.Access.Close())
	}
	return err
}

var errNoAccess = errors.New("this step has no access-policy connection (only the bootstrap writes access policies)")

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
	if a.Access == nil {
		return errNoAccess
	}
	return a.Access.CreateAtespace(ctx, name)
}

// GetAccessPolicy implements SubstrateAPI.
func (a *API) GetAccessPolicy(ctx context.Context, atespace string) (*AccessPolicy, error) {
	if a.Access == nil {
		return nil, errNoAccess
	}
	return a.Access.GetAccessPolicy(ctx, atespace)
}

// PutAccessPolicy implements SubstrateAPI.
func (a *API) PutAccessPolicy(ctx context.Context, p AccessPolicy) error {
	if a.Access == nil {
		return errNoAccess
	}
	return a.Access.PutAccessPolicy(ctx, p)
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
