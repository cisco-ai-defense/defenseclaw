// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"fmt"
)

// NativeHookFrame is the bounded stdin envelope sent by POSIX shell hooks.
// Values stay off the helper's argv and the connected-peer check still runs
// before the helper writes a byte to the gateway.
type NativeHookFrame struct {
	Path    string
	Body    string
	Headers map[string]string
}

func ReadNativeHookFrame(input []byte) (NativeHookFrame, error) {
	if len(input) == 0 || input[len(input)-1] != 0 {
		return NativeHookFrame{}, fmt.Errorf("native hook frame is incomplete")
	}
	fields := bytes.Split(input[:len(input)-1], []byte{0})
	if len(fields) < 3 || (len(fields)-3)%2 != 0 || string(fields[0]) != "DCPOST1" || len(fields[1]) == 0 {
		return NativeHookFrame{}, fmt.Errorf("native hook frame has invalid fields")
	}
	request := NativeHookFrame{Path: string(fields[1]), Body: string(fields[2]), Headers: make(map[string]string, (len(fields)-3)/2)}
	for i := 3; i < len(fields); i += 2 {
		name, value := fields[i], fields[i+1]
		if len(name) == 0 {
			return NativeHookFrame{}, fmt.Errorf("native hook header name is empty")
		}
		for _, char := range name {
			letter := char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z'
			digit := char >= '0' && char <= '9'
			if !letter && !digit && char != '-' {
				return NativeHookFrame{}, fmt.Errorf("native hook header name is invalid")
			}
		}
		if bytes.ContainsAny(value, "\r\n") {
			return NativeHookFrame{}, fmt.Errorf("native hook header value has a line break")
		}
		request.Headers[string(name)] = string(value)
	}
	return request, nil
}
