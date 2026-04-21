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

package tui

import (
	"strings"
	"time"

	"charm.land/lipgloss/v2"
)

// ToastLevel controls the styling and auto-dismiss duration of a toast.
type ToastLevel int

const (
	ToastInfo ToastLevel = iota
	ToastSuccess
	ToastWarn
	ToastError
)

const (
	toastInfoTTL    = 4 * time.Second
	toastSuccessTTL = 4 * time.Second
	toastWarnTTL    = 6 * time.Second
	toastErrorTTL   = 8 * time.Second
	maxToasts       = 3
)

type toast struct {
	Level   ToastLevel
	Message string
	Expires time.Time
}

// ToastManager holds a queue of auto-dismissing toast notifications.
type ToastManager struct {
	items []toast
	width int
}

// Push adds a new toast to the queue.
func (tm *ToastManager) Push(level ToastLevel, message string) {
	ttl := toastInfoTTL
	switch level {
	case ToastSuccess:
		ttl = toastSuccessTTL
	case ToastWarn:
		ttl = toastWarnTTL
	case ToastError:
		ttl = toastErrorTTL
	}
	tm.items = append(tm.items, toast{
		Level:   level,
		Message: message,
		Expires: time.Now().Add(ttl),
	})
	if len(tm.items) > maxToasts {
		tm.items = tm.items[len(tm.items)-maxToasts:]
	}
}

// Tick prunes expired toasts. Call on each refresh cycle.
func (tm *ToastManager) Tick() {
	now := time.Now()
	alive := tm.items[:0]
	for _, t := range tm.items {
		if now.Before(t.Expires) {
			alive = append(alive, t)
		}
	}
	tm.items = alive
}

// HasToasts returns true if there are active toasts to render.
func (tm *ToastManager) HasToasts() bool {
	return len(tm.items) > 0
}

// SetWidth updates the rendering width.
func (tm *ToastManager) SetWidth(w int) {
	tm.width = w
}

// View renders all active toasts as stacked 1-line bars.
func (tm *ToastManager) View() string {
	if len(tm.items) == 0 {
		return ""
	}
	var lines []string
	for _, t := range tm.items {
		style := toastStyle(t.Level)
		if tm.width > 0 {
			style = style.Width(tm.width)
		}
		icon := toastIcon(t.Level)
		lines = append(lines, style.Render(" "+icon+" "+t.Message))
	}
	return strings.Join(lines, "\n")
}

func toastStyle(level ToastLevel) lipgloss.Style {
	switch level {
	case ToastSuccess:
		return lipgloss.NewStyle().
			Background(lipgloss.Color("22")).
			Foreground(lipgloss.Color("120"))
	case ToastWarn:
		return lipgloss.NewStyle().
			Background(lipgloss.Color("58")).
			Foreground(lipgloss.Color("226"))
	case ToastError:
		return lipgloss.NewStyle().
			Background(lipgloss.Color("52")).
			Foreground(lipgloss.Color("196"))
	default:
		return lipgloss.NewStyle().
			Background(lipgloss.Color("24")).
			Foreground(lipgloss.Color("81"))
	}
}

func toastIcon(level ToastLevel) string {
	switch level {
	case ToastSuccess:
		return "OK"
	case ToastWarn:
		return "!!"
	case ToastError:
		return "ERR"
	default:
		return "--"
	}
}
