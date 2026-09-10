// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package main

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

// runUnderServiceManager speaks the SCM control protocol when this process
// was started as a Windows service, and runs normally otherwise.
//
// The Service Control Manager expects a service to report Running within a
// few seconds of start and to acknowledge Stop. A plain console binary
// answers neither, so SCM kills it with error 1053 -- observed on Windows
// Server 2025 before this existed. The same binary still runs from a
// console for diagnostics, which is why the mode is detected rather than
// chosen by a flag.
func runUnderServiceManager(ctx context.Context, serve func(context.Context) error) error {
	inService, err := svc.IsWindowsService()
	if err != nil || !inService {
		return serve(ctx)
	}
	return svc.Run("", &helperService{ctx: ctx, serve: serve})
}

type helperService struct {
	ctx   context.Context
	serve func(context.Context) error
}

// Execute is the SCM entry point.
//
// Accepted controls are Stop and Shutdown only. This service has no
// meaningful pause state: the planes either have an event source or they
// report that they do not, and a paused helper would look to the gateway
// exactly like a helper that had gone away.
func (s *helperService) Execute(
	_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status,
) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()

	failed := make(chan error, 1)
	go func() { failed <- s.serve(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepted}
	for {
		select {
		case err := <-failed:
			// The listener stopped on its own. Reporting a non-zero exit
			// code is what lets SCM's restart policy see a crash rather
			// than an orderly stop.
			status <- svc.Status{State: svc.StopPending}
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-failed
				return false, 0
			default:
				// Anything else is not accepted above, so receiving it
				// means SCM and this handler disagree. Ignore rather than
				// act on a control this service never advertised.
			}
		}
	}
}
