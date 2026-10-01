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

package sandboxcli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// GatewayService reads and changes the local OpenShell gateway's
// configuration (the compute driver, bind mounts, upstream telemetry),
// restores it, and restarts the gateway on what its files already say.
// Write writes a change without the restart, for a gateway no gateway
// service runs (openshell.GatewayConfigurator.Write), which NoService
// reports.
type GatewayService interface {
	State() (*openshell.GatewayConfigState, error)
	Plan(ctx context.Context, ch openshell.GatewayChanges) (*openshell.GatewayPlan, error)
	Apply(ctx context.Context, plan *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error)
	Write(ctx context.Context, plan *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error)
	Rollback(ctx context.Context, res *openshell.GatewayApplyResult) error
	Restart(ctx context.Context) error
	NoService(ctx context.Context) bool
}

type gatewayService struct {
	app *App
	cfg *openshell.GatewayConfigurator
}

func (g *gatewayService) configurator() *openshell.GatewayConfigurator {
	if g.cfg == nil {
		d := openshell.DiscoverOptions{}
		cli := ""
		if g.app.Cfg != nil {
			d.Gateway = g.app.Cfg.OpenShell.Gateway.Name
			cli = g.app.Cfg.OpenShell.EffectiveBinary()
		}
		g.cfg = &openshell.GatewayConfigurator{Discover: d, CLI: cli}
	}
	return g.cfg
}

func (g *gatewayService) State() (*openshell.GatewayConfigState, error) {
	return g.configurator().Read()
}

func (g *gatewayService) Plan(ctx context.Context, ch openshell.GatewayChanges) (*openshell.GatewayPlan, error) {
	return g.configurator().Plan(ctx, ch)
}

func (g *gatewayService) Apply(ctx context.Context, plan *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error) {
	return g.configurator().Apply(ctx, plan)
}

func (g *gatewayService) Write(ctx context.Context, plan *openshell.GatewayPlan) (*openshell.GatewayApplyResult, error) {
	return g.configurator().Write(ctx, plan)
}

func (g *gatewayService) Rollback(ctx context.Context, res *openshell.GatewayApplyResult) error {
	return g.configurator().Rollback(ctx, res)
}

func (g *gatewayService) Restart(ctx context.Context) error {
	return g.configurator().Restart(ctx)
}

func (g *gatewayService) NoService(ctx context.Context) bool {
	return g.configurator().NoService(ctx)
}

// setupReceipt records what setup changed outside DefenseClaw, so
// teardown can restore it: the gateway files it wrote, with the backup of
// each file from before DefenseClaw's first change and the content hash
// DefenseClaw left.
type setupReceipt struct {
	Version      int            `json:"version"`
	GatewayFiles []receiptFile  `json:"gateway_files,omitempty"`
	Wrappers     []receiptEntry `json:"wrappers,omitempty"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

type receiptFile struct {
	Path string `json:"path"`
	// Backup is the file before DefenseClaw first changed it; empty when
	// DefenseClaw created it.
	Backup string `json:"backup,omitempty"`
	// SHA256 is the content DefenseClaw last wrote.
	SHA256 string `json:"sha256"`
}

type receiptEntry struct {
	Shell string `json:"shell"`
	Path  string `json:"path"`
}

const receiptVersion = 1

func (a *App) receiptPath() string {
	return filepath.Join(a.dataDir(), "sandboxes", "setup-receipt.json")
}

func (a *App) loadReceipt() (*setupReceipt, error) {
	data, err := safefile.ReadRegularFileBounded(a.receiptPath(), 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return &setupReceipt{Version: receiptVersion}, nil
	}
	if err != nil {
		return nil, err
	}
	var r setupReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("%s is damaged: %w", a.receiptPath(), err)
	}
	return &r, nil
}

func (a *App) saveReceipt(r *setupReceipt) error {
	r.Version = receiptVersion
	r.UpdatedAt = a.Now().UTC()
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.receiptPath()), 0o700); err != nil {
		return err
	}
	return safefile.WritePrivate(a.receiptPath(), append(data, '\n'))
}

// recordGatewayApply adds an apply to the receipt, keeping the earliest
// backup of every file.
func (a *App) recordGatewayApply(res *openshell.GatewayApplyResult) error {
	if res == nil || len(res.Files) == 0 {
		return nil
	}
	r, err := a.loadReceipt()
	if err != nil {
		return err
	}
	for _, f := range res.Files {
		sum, err := fileSHA256(f.Path)
		if err != nil {
			return err
		}
		found := false
		for i := range r.GatewayFiles {
			if r.GatewayFiles[i].Path == f.Path {
				r.GatewayFiles[i].SHA256 = sum
				found = true
			}
		}
		if !found {
			r.GatewayFiles = append(r.GatewayFiles, receiptFile{Path: f.Path, Backup: f.Backup, SHA256: sum})
		}
	}
	return a.saveReceipt(r)
}

func fileSHA256(p string) (string, error) {
	data, err := safefile.ReadRegularFileBounded(p, 4<<20)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
