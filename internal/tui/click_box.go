// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import "charm.land/lipgloss/v2"

type clickBox struct {
	id   string
	x, y int
	w, h int
}

func newClickBox(id string, x, y, w, h int) clickBox {
	return clickBox{id: id, x: x, y: y, w: w, h: h}
}

func (b clickBox) contains(x, y int) bool {
	return b.w > 0 && b.h > 0 &&
		x >= b.x && x < b.x+b.w &&
		y >= b.y && y < b.y+b.h
}

func hitClickBox(boxes []clickBox, x, y int) (string, bool) {
	for _, b := range boxes {
		if b.contains(x, y) {
			return b.id, true
		}
	}
	return "", false
}

func centeredRenderedBox(rendered string, screenW, screenH int) clickBox {
	w := lipgloss.Width(rendered)
	h := lipgloss.Height(rendered)
	x := (screenW - w) / 2
	y := (screenH - h) / 2
	if x < 0 {
		x = 0
	}
	if y < 0 {
		y = 0
	}
	return newClickBox("box", x, y, w, h)
}
