//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"errors"
	"fmt"
	"os"
	"slices"
)

func (r *NSSResolver) platformGroupIDs(account Account) ([]int, error) {
	local, err := LocalAccounts(r.context())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if uid, ok := local[account.Name]; ok && uid == account.UID {
		ids, _, _, err := r.localAccountGroupsWithDirectory(account)
		return ids, err
	} else if ok {
		return r.groupIDsInOwnerService(account)
	}
	// A name may resolve to a different account than the uid did. In that
	// case initgroups must be asked through the service that owns the uid.
	named, nameErr := r.LookupUser(account.Name)
	var mismatch *NameMismatchError
	globalMismatch := nameErr == nil && named.UID != account.UID || errors.As(nameErr, &mismatch)
	if nameErr != nil && !globalMismatch && !IsNotFound(nameErr) {
		return nil, nameErr
	}
	shared, initgroupsServices, err := r.servicesWithDifferentUID(account)
	if err != nil {
		return nil, err
	}
	if len(shared) != 0 {
		return r.groupIDsWithoutSharedNames(account, shared, initgroupsServices)
	}
	if globalMismatch {
		return r.groupIDsInOwnerService(account)
	}
	ids, err := r.rawGroupIDs(account)
	if err != nil {
		return nil, err
	}
	return r.confirmMemberListGroups(account, initgroupsServices, ids)
}

// servicesWithDifferentUID checks the configured passwd and initgroups
// services before a directory account can use a global initgroups answer.
func (r *NSSResolver) servicesWithDifferentUID(account Account) (map[string]bool, []string, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil // glibc defaults to files
	}
	if err != nil {
		return nil, nil, fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	initgroupsServices, err := nssInitgroupsServices()
	if err != nil {
		return nil, nil, err
	}
	services := []string{}
	for _, service := range ParseNSSwitchServices(string(data), "passwd") {
		if _, known := directoryServices[service]; known || service == "files" {
			if validServiceName(service) && !slices.Contains(services, service) {
				services = append(services, service)
			}
		}
	}
	for _, service := range initgroupsServices {
		if service != "files" && service != "compat" && validServiceName(service) && !slices.Contains(services, service) {
			services = append(services, service)
		}
	}
	shared := map[string]bool{}
	for _, service := range services {
		byName, err := r.LookupUserInService(service, account.Name)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if byName.UID != account.UID {
			shared[service] = true
		}
	}
	return shared, initgroupsServices, nil
}

// groupIDsWithoutSharedNames combines only service answers that do not
// resolve this name to another uid.
func (r *NSSResolver) groupIDsWithoutSharedNames(account Account, shared map[string]bool, services []string) ([]int, error) {
	owner, err := r.ownerService(account)
	if err != nil {
		return nil, err
	}
	ids, err := r.groupIDsInService(owner, account.Name)
	if err != nil {
		return nil, err
	}
	if nssReadsLocalGroups(services) && !shared["files"] {
		local, err := localGroupsListing(account.Name)
		if err != nil {
			return nil, err
		}
		ids = append(ids, local...)
	}
	seen := map[string]bool{owner: true}
	for _, service := range services {
		if service == "files" || service == "compat" || !validServiceName(service) || shared[service] || seen[service] {
			continue
		}
		seen[service] = true
		if memberListServices[service] {
			listed, skip, err := r.memberListGroupsOf(service, account)
			if err != nil {
				return nil, err
			}
			if !skip {
				ids = append(ids, listed...)
			}
			continue
		}
		other, err := r.groupIDsInService(service, account.Name)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ids = append(ids, other...)
	}
	ids = withPrimary(ids, account.GID)
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// groupIDsInOwnerService resolves an overlapping name only in the directory
// service that independently confirms both the uid and the name.
func (r *NSSResolver) groupIDsInOwnerService(account Account) ([]int, error) {
	service, err := r.ownerService(account)
	if err != nil {
		return nil, err
	}
	ids, err := r.groupIDsInService(service, account.Name)
	if err != nil {
		return nil, err
	}
	return withPrimary(ids, account.GID), nil
}

func (r *NSSResolver) ownerService(account Account) (string, error) {
	data, err := readSmallFile(nsswitchPath, 1<<20)
	if err != nil {
		return "", fmt.Errorf("unixidentity: read NSS configuration: %w", err)
	}
	for _, service := range ParseNSSwitchServices(string(data), "passwd") {
		if _, known := directoryServices[service]; !known {
			continue
		}
		owner, err := r.LookupUIDInService(service, account.UID)
		if IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		byName, err := r.LookupUserInService(service, account.Name)
		if err != nil {
			return "", err
		}
		if owner.UID != account.UID || byName.UID != account.UID {
			return "", fmt.Errorf("unixidentity: account name and uid resolve to different users in %s", service)
		}
		return service, nil
	}
	return "", fmt.Errorf("unixidentity: no NSS service confirms uid %d for %s", account.UID, account.Name)
}

// groupIDsInService reads a single service's initgroups answer.
func (r *NSSResolver) groupIDsInService(service, name string) ([]int, error) {
	result, err := r.runner(r.context(), r.path, []string{"-s", service, "initgroups", name})
	if err != nil {
		return nil, fmt.Errorf("unixidentity: %s initgroups of %s: %w", service, name, err)
	}
	if result.exitCode == getentExitNotFound {
		return nil, ErrNotFound
	}
	if result.exitCode != getentExitOK {
		return nil, fmt.Errorf("unixidentity: getent -s %s initgroups %s exited %d", service, name, result.exitCode)
	}
	ids, err := ParseInitgroups(string(result.stdout), name)
	if err != nil {
		return nil, fmt.Errorf("unixidentity: %s initgroups of %s: %w", service, name, err)
	}
	return ids, nil
}
