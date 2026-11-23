// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// TestT20SQLClauseVerbsAreNotMutations (DET111 T20 review P2-1): an UPDATE,
// DELETE or TRUNCATE that names an operation inside a clause (a PostgreSQL
// upsert, MySQL ON DUPLICATE KEY UPDATE, a trigger event, a privilege list,
// a row lock) is not an unbounded destructive mutation; statement-level ones
// still are. The upsert row is red at 23ee0d55e2 (update_unbounded, object
// SET).
func TestT20SQLClauseVerbsAreNotMutations(t *testing.T) {
	for _, command := range []string{
		`psql -d production -c "INSERT INTO users (id, v) VALUES (1, 2) ON CONFLICT (id) DO UPDATE SET v = 2;"`,
		`psql -d production -c "INSERT INTO users (id, v) VALUES (1, 2) ON CONFLICT ON CONSTRAINT users_pkey DO UPDATE SET v = EXCLUDED.v;"`,
		`psql -d production -c "CREATE TRIGGER audit BEFORE INSERT OR UPDATE ON users FOR EACH ROW EXECUTE FUNCTION audit();"`,
		`psql -d production -c "CREATE TRIGGER audit AFTER UPDATE OF v ON users FOR EACH ROW EXECUTE FUNCTION audit();"`,
		`psql -d production -c "GRANT SELECT, UPDATE ON users TO app;"`,
		`psql -d production -c "GRANT TRUNCATE ON users TO app;"`,
		`psql -d production -c "REVOKE DELETE ON users FROM app;"`,
		`psql -d production -c "SELECT * FROM users FOR UPDATE;"`,
		`psql -d production -c "ALTER TABLE orders ADD FOREIGN KEY (uid) REFERENCES users (id) ON UPDATE CASCADE;"`,
	} {
		if got := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: command})); len(got) != 0 {
			t.Errorf("clause verb read as a mutation: %q => %#v", command, got)
		}
	}
	for _, c := range []struct {
		command string
		want    SQLMutationOperation
	}{
		{`psql -d production -c "UPDATE users SET v = 2;"`, SQLMutationUpdateUnbounded},
		{`psql -d production -c "UPDATE ONLY users SET v = 2;"`, SQLMutationUpdateUnbounded},
		{`psql -d production -c "WITH s AS (SELECT 1) UPDATE users SET v = 2;"`, SQLMutationUpdateUnbounded},
		{`psql -d production -c "TRUNCATE TABLE users;"`, SQLMutationTruncate},
		{`psql -d production -c "DELETE FROM users;"`, SQLMutationDeleteUnbounded},
	} {
		got := ExactSQLMutations(Analyze(Input{Tool: "shell", Command: c.command}))
		if len(got) != 1 || got[0].Operation != c.want {
			t.Errorf("%q => %#v, want one %s", c.command, got, c.want)
		}
	}
}
