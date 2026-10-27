# Database destruction protection

This opt-in guardrail profile extends the embedded balanced defaults and blocks
static destructive SQL passed directly to supported command-line clients or
authenticated structured database tools. It also enables the exact
same-database, same-table chain from a sensitive SQLite read to a later
unbounded delete.

The v1 grammar covers `psql`, `mysql`, `mariadb`, `sqlcmd`, and `snowsql`
(its inline `-q`/`--query`; a query file, like `psql --file`, is not inline). It
blocks `DELETE FROM` without a `WHERE` clause, `TRUNCATE`, `DROP DATABASE`, and
`DROP SCHEMA`. SQL inside strings is ignored and quoted identifiers are not
treated as keywords. Comments are removed before the match, so a comment
neither hides a destructive statement nor creates one. MySQL and MariaDB read
`#` to the end of the line, end a block comment at its first `*/`, and run the
body of an executable comment (`/*!`, `/*M!`, with an optional version), so
that body is matched as SQL. PostgreSQL and SQL Server comments nest when they
balance. An unterminated or unbalanced comment, a nested comment on the other
engines, a MySQL `--` without a following space, and any query with quoted
text stay detection-only.
An ordinary `EXPLAIN DELETE` is not execution proof. Unterminated quoting, joined short options such as `-cQUERY`, dynamic
shell operands, unsupported client forms, and direct database tools without an
authenticated command schema remain detection-only or out of scope. The SQLite
chain additionally requires successful, ordered, value-minimized result and
resource identity; a mismatched database/table, failed read, bounded delete, or
incomplete sequence cannot block.

For a static multi-statement batch, mutations inside an explicit transaction
that ends in `ROLLBACK` are discarded. A committed mutation or a destructive
statement after the rollback remains blocking. Incomplete or nested transaction
structure is indeterminate and cannot authorize a block.
