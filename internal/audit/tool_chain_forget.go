// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// ForgetToolChainArtifacts takes the facts about files a workspace undo
// reverted out of the stored chain events of a connector instance, in its
// session and root windows (guardrail.ForgetToolChainArtifacts;
// substrate-1:GAP-0476). forget reports whether the fact about the file
// with that digest, of an event received at that time, is to go. It
// returns how many events changed. Results, receipts and the events'
// places in their windows stay: nothing else ages out of a window.
func (s *Store) ForgetToolChainArtifacts(ctx context.Context, instance ConnectorInstanceID,
	forget func(digest string, received time.Time) bool) (int, error) {
	if err := validateUUIDv7("connector instance id", string(instance)); err != nil {
		return 0, err
	}
	if err := s.ensureToolChainRootTables(ctx); err != nil {
		return 0, err
	}
	n := 0
	for _, set := range []toolChainTableSet{toolChainSessionTables, toolChainRootTables} {
		changed := 0
		err := retryBusyObserved(ctx, "guardrail_chain_forget", s.sqliteBusyObservabilityV8(), func() error {
			release, err := s.acquireReady()
			if err != nil {
				return err
			}
			defer release()
			changed, err = s.forgetToolChainArtifacts(ctx, &ToolChainRepository{tables: set}, instance, forget)
			return err
		})
		if err != nil {
			return n, err
		}
		n += changed
	}
	return n, nil
}

func (s *Store) forgetToolChainArtifacts(ctx context.Context, repo *ToolChainRepository, instance ConnectorInstanceID,
	forget func(digest string, received time.Time) bool) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	rows, err := tx.QueryContext(ctx, repo.sql(`SELECT semantic_event_id, session_value_digest, sequence,
		received_time_unix_nano, parse_status, detection_step_mask, enforcement_step_mask,
		enforcement_join_digests, enforcement_output_join_digests, value_join_digests, projection_fingerprint
		FROM guardrail_chain_events
		WHERE connector_instance_id=? AND (detection_step_mask & ?) != 0
		ORDER BY session_value_digest, sequence`),
		string(instance), int64(guardrail.ToolChainArtifactWriteStepMask()))
	if err != nil {
		return 0, err
	}
	partitions := map[string][]guardrail.ToolChainWindowEvent{}
	var order []string
	stored := map[string]string{}
	for rows.Next() {
		var (
			eventID, session, parseStatus, projectionFP string
			joins, outputJoins, valueJoins              string
			seq, receivedNano                           int64
			detection, enforcement                      uint64
		)
		if err := rows.Scan(&eventID, &session, &seq, &receivedNano, &parseStatus, &detection, &enforcement,
			&joins, &outputJoins, &valueJoins, &projectionFP); err != nil {
			rows.Close()
			return 0, err
		}
		j, jerr := decodeToolChainJoinDigests(joins)
		o, oerr := decodeToolChainJoinDigests(outputJoins)
		v, verr := decodeToolChainValueJoinDigests(valueJoins)
		projection := guardrail.ToolChainProjection{ParseStatus: actionfacts.ParseStatus(parseStatus),
			DetectionStepMask: detection, EnforcementStepMask: enforcement,
			EnforcementJoinDigests: j, EnforcementOutputJoinDigests: o, ValueJoinDigests: v}
		expected, ferr := guardrail.ToolChainProjectionFingerprint(projection)
		if jerr != nil || oerr != nil || verr != nil || ferr != nil || expected != projectionFP || seq < 1 || receivedNano < 1 {
			rows.Close()
			return 0, ErrToolChainIntegrity
		}
		if _, ok := partitions[session]; !ok {
			order = append(order, session)
		}
		partitions[session] = append(partitions[session], guardrail.ToolChainWindowEvent{SemanticEventID: eventID,
			Sequence: uint64(seq), ReceivedAt: time.Unix(0, receivedNano).UTC(), Projection: projection})
		stored[eventID] = projectionFP
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, session := range order {
		changed := guardrail.ForgetToolChainArtifacts(partitions[session], func(digest string, ev guardrail.ToolChainWindowEvent) bool {
			return forget(digest, ev.ReceivedAt)
		})
		for _, ev := range partitions[session] {
			projection, ok := changed[ev.SemanticEventID]
			if !ok {
				continue
			}
			fp, err := guardrail.ToolChainProjectionFingerprint(projection)
			if err != nil {
				return 0, err
			}
			res, err := tx.ExecContext(ctx, repo.sql(`UPDATE guardrail_chain_events SET detection_step_mask=?,
				enforcement_step_mask=?, enforcement_join_digests=?, enforcement_output_join_digests=?,
				projection_fingerprint=? WHERE semantic_event_id=? AND projection_fingerprint=?`),
				projection.DetectionStepMask, projection.EnforcementStepMask,
				encodeToolChainJoinDigests(projection.EnforcementJoinDigests),
				encodeToolChainJoinDigests(projection.EnforcementOutputJoinDigests),
				fp, ev.SemanticEventID, stored[ev.SemanticEventID])
			if err != nil {
				return 0, err
			}
			if k, err := res.RowsAffected(); err != nil || k != 1 {
				return 0, ErrToolChainIntegrity
			}
			n++
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return n, nil
}
