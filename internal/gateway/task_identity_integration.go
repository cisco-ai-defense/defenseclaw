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

package gateway

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/taskidentity"
)

const (
	TaskTokenHeader        = "X-DefenseClaw-Task-Token"
	taskTokenEnabledEnv    = "DEFENSECLAW_TASK_TOKEN_ENABLE"
	taskTokenSecretEnv     = "DEFENSECLAW_TASK_TOKEN_SECRET"
	taskTokenIssuerEnv     = "DEFENSECLAW_TASK_TOKEN_ISSUER"
	taskTokenFailClosedEnv = "DEFENSECLAW_TASK_TOKEN_FAIL_CLOSED"
)

type taskIdentityCtxKey struct{}
type taskIdentityErrorCtxKey struct{}

// GatewayTaskIdentity is the task-authority view stored on gateway contexts.
type GatewayTaskIdentity struct {
	TaskID           string
	TaskType         string
	ParentAgentID    string
	TokenID          string
	AllowedResources []string
	Scopes           []string
	AutoRevoke       bool
}

func ContextWithTaskIdentity(ctx context.Context, id GatewayTaskIdentity) context.Context {
	if id.TaskID == "" {
		return ctx
	}
	return context.WithValue(ctx, taskIdentityCtxKey{}, id)
}

func TaskIdentityFromContext(ctx context.Context) GatewayTaskIdentity {
	if ctx == nil {
		return GatewayTaskIdentity{}
	}
	v, _ := ctx.Value(taskIdentityCtxKey{}).(GatewayTaskIdentity)
	return v
}

func ContextWithTaskIdentityError(ctx context.Context, err string) context.Context {
	err = strings.TrimSpace(err)
	if err == "" {
		return ctx
	}
	return context.WithValue(ctx, taskIdentityErrorCtxKey{}, err)
}

func TaskIdentityErrorFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(taskIdentityErrorCtxKey{}).(string)
	return v
}

var (
	taskTokenServiceMu sync.Mutex
	taskTokenService   *taskidentity.Service
	taskTokenRevoker   = taskidentity.NewInMemoryRevoker()
)

func taskIdentityContextFromHeaders(ctx context.Context, h http.Header) context.Context {
	if !envFlag(taskTokenEnabledEnv) {
		return ctx
	}
	raw := strings.TrimSpace(h.Get(TaskTokenHeader))
	if raw == "" {
		raw = authorizationBearer(h.Get("Authorization"))
	}
	if raw == "" {
		return ctx
	}
	svc, err := taskIdentityServiceFromEnv()
	if err != nil {
		return ContextWithTaskIdentityError(ctx, err.Error())
	}
	claims, err := svc.Validate(ctx, raw)
	if err != nil {
		return ContextWithTaskIdentityError(ctx, err.Error())
	}
	id := GatewayTaskIdentity{
		TaskID:           claims.TaskID,
		TaskType:         claims.TaskType,
		ParentAgentID:    claims.ParentAgentID,
		TokenID:          claims.TokenID,
		AllowedResources: append([]string(nil), claims.AllowedResources...),
		Scopes:           append([]string(nil), claims.Scopes...),
		AutoRevoke:       claims.AutoRevoke,
	}
	return ContextWithTaskIdentity(ctx, id)
}

func taskIdentityServiceFromEnv() (*taskidentity.Service, error) {
	taskTokenServiceMu.Lock()
	defer taskTokenServiceMu.Unlock()
	secret := strings.TrimSpace(os.Getenv(taskTokenSecretEnv))
	if secret == "" {
		return nil, taskidentity.ErrEmptyToken
	}
	issuer := strings.TrimSpace(os.Getenv(taskTokenIssuerEnv))
	if issuer == "" {
		issuer = taskidentity.DefaultIssuer
	}
	if taskTokenService != nil {
		return taskTokenService, nil
	}
	svc, err := taskidentity.New(issuer, []byte(secret), taskTokenRevoker)
	if err != nil {
		return nil, err
	}
	taskTokenService = svc
	return svc, nil
}

func setTaskIdentityServiceForTesting(svc *taskidentity.Service) func() {
	taskTokenServiceMu.Lock()
	defer taskTokenServiceMu.Unlock()
	prev := taskTokenService
	taskTokenService = svc
	return func() {
		taskTokenServiceMu.Lock()
		defer taskTokenServiceMu.Unlock()
		taskTokenService = prev
	}
}

func authorizationBearer(v string) string {
	v = strings.TrimSpace(v)
	if len(v) < 7 || !strings.EqualFold(v[:7], "Bearer ") {
		return ""
	}
	return strings.TrimSpace(v[7:])
}

func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func agentControlTaskIdentityContext(ctx context.Context, out map[string]any) {
	id := TaskIdentityFromContext(ctx)
	if id.TaskID != "" {
		out["task_id"] = id.TaskID
		out["task_type"] = id.TaskType
		out["task_parent_agent_id"] = id.ParentAgentID
		out["task_token_id"] = id.TokenID
		out["task_allowed_resources"] = id.AllowedResources
		out["task_scopes"] = id.Scopes
		out["task_auto_revoke"] = id.AutoRevoke
	}
	if err := TaskIdentityErrorFromContext(ctx); err != "" {
		out["task_identity_error"] = err
		out["task_identity_fail_closed"] = envFlag(taskTokenFailClosedEnv)
	}
}
