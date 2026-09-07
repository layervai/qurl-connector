# Contributing

Thanks for helping improve qURL Connector.

## Before opening a change

Open an issue for changes that alter the public package surface, NHP/FRP wire
behavior, persistent state, or release artifacts. Security vulnerabilities
belong in a private [GitHub security advisory](https://github.com/layervai/qurl-connector/security/advisories/new).

Do not commit credentials, private endpoints, cloud account identifiers,
customer data, live deployment snapshots, or operational rollout evidence.
Use reserved example domains and documentation account IDs in tests and docs.

## Development workflow

1. Create a focused branch from current `main`.
2. Keep one production NHP/FRP lifecycle implementation under `pkg/share`.
3. Add hermetic tests for behavior changes, including failure and cancellation
   paths.
4. Run the relevant focused tests while iterating, then the full gates:

   ```bash
   make test
   make test-race
   make lint
   (
   set -e
   qurl_lint_venv=$(mktemp -d)
   trap 'rm -rf -- "$qurl_lint_venv"' EXIT
   python3.13 -m venv "$qurl_lint_venv"
   "$qurl_lint_venv/bin/python" -m pip install --require-hashes -r .github/scripts/requirements-lint.txt
   PYTHON="$qurl_lint_venv/bin/python" make check-python
   )
   make vet
   make verify-deps
   go test ./.github/scripts
   make frpc
   ```

   The Python tests require Python 3.13. On Debian or Ubuntu, install the
   matching `python3.13-venv` package first. The AWS CLI stdin-expansion test
   runs when AWS CLI v2 is available and reports an explicit skip otherwise.
   The manual rotation workflow always requires AWS CLI v2 before it requests
   AWS credentials.

5. Describe user-visible behavior, security impact, and validation in the pull
   request.

Tests must not depend on LayerV credentials or a live LayerV environment.
Deployment smoke and soak automation is maintained separately from this public
source repository. A manual, fail-closed recovery workflow for this module's
Connector fleet can live here when it contains only reviewed, non-secret fixed
slot topology. It must not contain a private endpoint, credential, cloud account
identifier, customer data, or rollout evidence.

The manual recovery also requires the compiled OpenSSL CA file or directory
from the Python runtime. A missing trust store is a hard stop before the first
qURL API request. It reports `no compiled TLS trust store is available`, not a
network failure.

The recovery workflow is Ubuntu/POSIX-only. It uses a POSIX wall-clock alarm and
AWS CLI `file:///dev/stdin` expansion. Do not move it to a non-POSIX runner
without equivalent deadline and decoded-wire tests.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/), such as
`feat(share): renew sessions without route interruption` or
`fix(state): reject a regressed serving epoch`.

Breaking changes use `!` or a `BREAKING CHANGE:` footer. The project is
pre-1.0, so a breaking release increments the minor version.

## Pull request review

Pull requests require passing CI and maintainer review. Automated review is a
last line of defense; authors are expected to simplify and self-review the
entire diff before requesting review.
