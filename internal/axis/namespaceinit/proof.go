// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package namespaceinit bootstraps only the private AXIS child namespaces.
// It grants no provider, policy or executable authority.
package namespaceinit

import (
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
)

const proofSize = 64

type identity struct{ device, inode uint64 }
type proof struct {
	uid, gid   uint32
	namespaces [3]identity // user, mount, PID
}

func (p proof) encode() []byte {
	b := make([]byte, proofSize)
	copy(b, "DCAXNS01")
	binary.LittleEndian.PutUint32(b[8:12], p.uid)
	binary.LittleEndian.PutUint32(b[12:16], p.gid)
	for i, ns := range p.namespaces {
		binary.LittleEndian.PutUint64(b[16+i*16:], ns.device)
		binary.LittleEndian.PutUint64(b[24+i*16:], ns.inode)
	}
	return b
}

func decode(b []byte) (proof, error) {
	var p proof
	if len(b) != proofSize || string(b[:8]) != "DCAXNS01" {
		return p, errors.New("namespace proof format refused")
	}
	p.uid, p.gid = binary.LittleEndian.Uint32(b[8:12]), binary.LittleEndian.Uint32(b[12:16])
	for i := range p.namespaces {
		p.namespaces[i] = identity{binary.LittleEndian.Uint64(b[16+i*16:]), binary.LittleEndian.Uint64(b[24+i*16:])}
		if p.namespaces[i].inode == 0 {
			return proof{}, errors.New("namespace proof identity refused")
		}
	}
	if p.uid == 0 || p.gid == 0 {
		return proof{}, errors.New("namespace proof root identity refused")
	}
	return p, nil
}

func validMap(b []byte, id uint32) bool {
	parts := strings.Fields(string(b))
	if id == 0 || len(parts) != 3 {
		return false
	}
	for i, want := range []uint64{uint64(id), uint64(id), 1} {
		got, err := strconv.ParseUint(parts[i], 10, 32)
		if err != nil || got != want {
			return false
		}
	}
	return true
}

func validNamespaces(parent, child [3]identity, owners [2]identity) bool {
	for i, current := range child {
		if current.inode == 0 || current == parent[i] {
			return false
		}
	}
	return owners[0] == child[0] && owners[1] == child[0]
}

func zeroThreadStatus(data []byte) bool {
	wanted := map[string]bool{"CapInh:": false, "CapPrm:": false, "CapEff:": false, "CapAmb:": false, "NoNewPrivs:": false}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if _, found := wanted[fields[0]]; !found {
			continue
		}
		if len(fields) != 2 || wanted[fields[0]] {
			return false
		}
		base, expected := 16, uint64(0)
		if fields[0] == "NoNewPrivs:" {
			base, expected = 10, 1
		}
		value, err := strconv.ParseUint(fields[1], base, 64)
		if err != nil || value != expected {
			return false
		}
		wanted[fields[0]] = true
	}
	for _, found := range wanted {
		if !found {
			return false
		}
	}
	return true
}

// All mutation is behind identity/owner validation. Neither READY nor protocol
// input is reachable until every thread has relinquished startup capabilities.
type bootstrapOps interface {
	validate() error
	privateMounts() error
	mountProc() error
	dropCaps() error
	verify() error
}

func bootstrap(ops bootstrapOps) error {
	for _, step := range []func() error{ops.validate, ops.privateMounts, ops.mountProc, ops.dropCaps, ops.verify} {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}
