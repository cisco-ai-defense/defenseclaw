# Contributing to DefenseClaw

Thank you for helping improve DefenseClaw.

## Getting started

1. Clone the repository
2. Build: `make build`
3. Run tests: `make test`

Ensure Go 1.26+ and Python 3.10+ are installed. For scanner integration, install
the external scanners via `defenseclaw init` or manually with
`scripts/setup-scanners.sh`.

## Code style

- **Python**: `ruff` for linting, Click for CLI commands, standard `pyproject.toml` conventions
- **Go**: `gofmt`, clear package boundaries, errors wrapped with `fmt.Errorf` and `%w`
- Run `make lint` before opening a PR (covers both Python and Go)
- Follow the project layout in `CLAUDE.md` (internal packages, Cobra commands, no `os.Exit` outside `main`)

## Pull request process

1. Fork the repository and create a branch for your change
2. Keep commits focused and the diff easy to review
3. Run `make test` (and `make lint` when applicable)
4. Open a pull request with a short description of what changed and why

## DCO sign-off

All commits must include a **Developer Certificate of Origin** sign-off
(for example `Signed-off-by: Your Name <email@example.com>`). Use
`git commit -s` to add the line automatically.
