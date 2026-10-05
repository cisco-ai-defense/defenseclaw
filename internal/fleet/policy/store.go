package policy

import (
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
}

// fleetKey builds a composite key for the tenant+fleet pair.
func fleetKey(tenantID, fleetID uint64) string {
	return fmt.Sprintf("%d:%d", tenantID, fleetID)
}

// MemoryPolicyStore is an in-memory PolicyStore for development and testing.
type MemoryPolicyStore struct {
	mu       sync.RWMutex
	policies map[string][]PolicyRecord // keyed by "tenantID:fleetID"
}

// NewMemoryPolicyStore creates an empty in-memory store.
func NewMemoryPolicyStore() *MemoryPolicyStore {
	return &MemoryPolicyStore{
		policies: make(map[string][]PolicyRecord),
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
