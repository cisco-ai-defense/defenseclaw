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

package policy

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// PolicyRecord holds metadata and binary content for a stored policy version.
type PolicyRecord struct {
	TenantID    uint64    `json:"tenant_id"`
	FleetID     uint64    `json:"fleet_id"`
	Version     uint32    `json:"version"`
	Profile     string    `json:"profile"`
	PolicyBin   []byte    `json:"policy_bin"`
	Signature   []byte    `json:"signature"`
	CreatedAt   time.Time `json:"created_at"`
	Distributed bool      `json:"distributed"`
}

// EmergencyRecord is the last signed command for one tenant/fleet. Its exact
// bytes are retained so a device that was offline can receive the same
// authenticated command after reconnecting.
type EmergencyRecord struct {
	Sequence uint32
	Message  []byte
}

func validateEmergencyChain(sequence, predecessor uint32, message []byte) error {
	if len(message) != EmergencyMsgSize {
		return fmt.Errorf("emergency message must be %d bytes, got %d", EmergencyMsgSize, len(message))
	}
	if got := binary.BigEndian.Uint32(message[0:4]); got != sequence {
		return fmt.Errorf("emergency message sequence %d disagrees with record %d", got, sequence)
	}
	if got := binary.BigEndian.Uint32(message[44:48]); got != predecessor {
		return fmt.Errorf("emergency predecessor %d disagrees with fleet predecessor %d", got, predecessor)
	}
	if sequence <= predecessor {
		return fmt.Errorf("emergency sequence %d is not newer than fleet predecessor %d", sequence, predecessor)
	}
	for _, b := range message[80:112] {
		if b != 0 {
			return fmt.Errorf("emergency signature has nonzero reserved tail")
		}
	}
	return nil
}

// PolicyStore persists policy versions for audit and rollback.
type PolicyStore interface {
	// SavePolicy stores a new policy version. Returns an error if the version
	// already exists for the given tenant/fleet pair.
	SavePolicy(tenantID, fleetID uint64, version uint32, policyBin []byte, signature []byte, profile string) error

	// GetLatestPolicy returns the most recent policy for a tenant/fleet.
	// Returns nil and no error if no policies exist.
	GetLatestPolicy(tenantID, fleetID uint64) (*PolicyRecord, error)

	// GetPolicy returns a specific policy version.
	GetPolicy(tenantID, fleetID uint64, version uint32) (*PolicyRecord, error)

	// ListVersions returns all stored policy versions for a tenant/fleet,
	// ordered by version descending (newest first).
	ListVersions(tenantID, fleetID uint64) ([]PolicyRecord, error)

	// MarkDistributed flags a policy version as having been pushed to devices.
	MarkDistributed(tenantID, fleetID uint64, version uint32) error

	// GetEmergencySeq returns the last persisted emergency broadcast sequence number.
	// Returns 0 if no sequence has been stored yet.
	GetEmergencySeq() (uint32, error)

	// SetEmergencySeq persists the emergency broadcast sequence number so it
	// survives gateway restarts (REQ-31 anti-replay).
	SetEmergencySeq(seq uint32) error

	// SaveEmergency atomically advances the global sequence and appends the
	// fleet's signed command. A broker PUBACK is not device delivery.
	SaveEmergency(tenantID, fleetID uint64, seq uint32, signedMessage []byte) error
	GetLastEmergency(tenantID, fleetID uint64) (*EmergencyRecord, error)
	// GetEmergenciesAfter returns an ordered, bounded page for device catch-up.
	GetEmergenciesAfter(tenantID, fleetID uint64, afterSeq uint32, limit int) ([]EmergencyRecord, error)
}

// fleetKey builds a composite key for the tenant+fleet pair.
func fleetKey(tenantID, fleetID uint64) string {
	return fmt.Sprintf("%d:%d", tenantID, fleetID)
}

// MemoryPolicyStore is an in-memory PolicyStore for development and testing.
type MemoryPolicyStore struct {
	mu           sync.RWMutex
	policies     map[string][]PolicyRecord // keyed by "tenantID:fleetID"
	emergencySeq uint32
	emergencies  map[string][]EmergencyRecord
}

// NewMemoryPolicyStore creates an empty in-memory store.
func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies:    make(map[string][]PolicyRecord),
		emergencies: make(map[string][]EmergencyRecord),
	}
}

func (s *MemoryPolicyStore) SavePolicy(tenantID, fleetID uint64, version uint32, policyBin []byte, signature []byte, profile string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fleetKey(tenantID, fleetID)
	for _, p := range s.policies[key] {
		if p.Version == version {
			return fmt.Errorf("policy version %d already exists for tenant=%d fleet=%d", version, tenantID, fleetID)
		}
	}

	binCopy := make([]byte, len(policyBin))
	copy(binCopy, policyBin)
	sigCopy := make([]byte, len(signature))
	copy(sigCopy, signature)

	record := PolicyRecord{
		TenantID:  tenantID,
		FleetID:   fleetID,
		Version:   version,
		Profile:   profile,
		PolicyBin: binCopy,
		Signature: sigCopy,
		CreatedAt: time.Now(),
	}

	s.policies[key] = append(s.policies[key], record)
	return nil
}

func (s *MemoryPolicyStore) GetLatestPolicy(tenantID, fleetID uint64) (*PolicyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fleetKey(tenantID, fleetID)
	records := s.policies[key]
	if len(records) == 0 {
		return nil, nil
	}

	// Find the highest version
	var latest *PolicyRecord
	for i := range records {
		if latest == nil || records[i].Version > latest.Version {
			latest = &records[i]
		}
	}

	rec := *latest
	rec.PolicyBin = make([]byte, len(latest.PolicyBin))
	copy(rec.PolicyBin, latest.PolicyBin)
	rec.Signature = make([]byte, len(latest.Signature))
	copy(rec.Signature, latest.Signature)
	return &rec, nil
}

func (s *MemoryPolicyStore) GetPolicy(tenantID, fleetID uint64, version uint32) (*PolicyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fleetKey(tenantID, fleetID)
	for _, p := range s.policies[key] {
		if p.Version == version {
			rec := p
			rec.PolicyBin = make([]byte, len(p.PolicyBin))
			copy(rec.PolicyBin, p.PolicyBin)
			rec.Signature = make([]byte, len(p.Signature))
			copy(rec.Signature, p.Signature)
			return &rec, nil
		}
	}
	return nil, nil
}

func (s *MemoryPolicyStore) ListVersions(tenantID, fleetID uint64) ([]PolicyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := fleetKey(tenantID, fleetID)
	records := s.policies[key]

	// Return copies without binary payloads (metadata only) sorted descending
	result := make([]PolicyRecord, len(records))
	for i, p := range records {
		result[i] = PolicyRecord{
			TenantID:    p.TenantID,
			FleetID:     p.FleetID,
			Version:     p.Version,
			Profile:     p.Profile,
			CreatedAt:   p.CreatedAt,
			Distributed: p.Distributed,
		}
	}

	// Sort by version descending (simple insertion sort for small N)
	for i := 1; i < len(result); i++ {
		for j := i; j > 0 && result[j].Version > result[j-1].Version; j-- {
			result[j], result[j-1] = result[j-1], result[j]
		}
	}

	return result, nil
}

func (s *MemoryPolicyStore) MarkDistributed(tenantID, fleetID uint64, version uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := fleetKey(tenantID, fleetID)
	for i := range s.policies[key] {
		if s.policies[key][i].Version == version {
			s.policies[key][i].Distributed = true
			return nil
		}
	}
	return fmt.Errorf("policy version %d not found for tenant=%d fleet=%d", version, tenantID, fleetID)
}

func (s *MemoryPolicyStore) GetEmergencySeq() (uint32, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.emergencySeq, nil
}

func (s *MemoryPolicyStore) SetEmergencySeq(seq uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emergencySeq = seq
	return nil
}

func (s *MemoryPolicyStore) SaveEmergency(tenantID, fleetID uint64, seq uint32, signedMessage []byte) error {
	if len(signedMessage) != EmergencyMsgSize {
		return fmt.Errorf("emergency message must be %d bytes, got %d", EmergencyMsgSize, len(signedMessage))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq <= s.emergencySeq {
		return fmt.Errorf("emergency sequence %d is not newer than %d", seq, s.emergencySeq)
	}
	key := fleetKey(tenantID, fleetID)
	var previous uint32
	if records := s.emergencies[key]; len(records) != 0 {
		previous = records[len(records)-1].Sequence
	}
	if err := validateEmergencyChain(seq, previous, signedMessage); err != nil {
		return err
	}
	s.emergencySeq = seq
	s.emergencies[key] = append(s.emergencies[key], EmergencyRecord{
		Sequence: seq, Message: append([]byte(nil), signedMessage...),
	})
	return nil
}

func (s *MemoryPolicyStore) GetLastEmergency(tenantID, fleetID uint64) (*EmergencyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.emergencies[fleetKey(tenantID, fleetID)]
	if len(records) == 0 {
		return nil, nil
	}
	record := records[len(records)-1]
	record.Message = append([]byte(nil), record.Message...)
	return &record, nil
}

func (s *MemoryPolicyStore) GetEmergenciesAfter(tenantID, fleetID uint64, afterSeq uint32, limit int) ([]EmergencyRecord, error) {
	if limit < 1 || limit > 32 {
		return nil, fmt.Errorf("emergency replay page limit must be 1..32")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.emergencies[fleetKey(tenantID, fleetID)]
	page := make([]EmergencyRecord, 0, limit)
	previous := afterSeq
	for _, record := range records {
		if record.Sequence <= afterSeq {
			continue
		}
		if err := validateEmergencyChain(record.Sequence, previous, record.Message); err != nil {
			return nil, err
		}
		page = append(page, EmergencyRecord{Sequence: record.Sequence, Message: append([]byte(nil), record.Message...)})
		previous = record.Sequence
		if len(page) == limit {
			break
		}
	}
	return page, nil
}
