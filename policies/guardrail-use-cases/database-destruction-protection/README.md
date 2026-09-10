# Database destruction protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
static destructive SQL passed directly to supported command-line clients.

The v1 grammar covers `psql`, `mysql`, `mariadb`, `sqlcmd`, and `snowsql`. It
blocks `DELETE FROM` without a `WHERE` clause, `TRUNCATE`, `DROP DATABASE`, and
`DROP SCHEMA`. SQL inside strings or comments is ignored, quoted identifiers are
not treated as keywords, and an ordinary `EXPLAIN DELETE` is not execution
proof. Unterminated quoting, joined short options such as `-cQUERY`, dynamic
shell operands, unsupported client forms, and direct database tools without an
authenticated command schema remain detection-only or out of scope.

For a static multi-statement batch, mutations inside an explicit transaction
that ends in `ROLLBACK` are discarded. A committed mutation or a destructive
statement after the rollback remains blocking. Incomplete or nested transaction
structure is indeterminate and cannot authorize a block.
