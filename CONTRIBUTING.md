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
   make lint-python
   make test-python
   make vet
   make verify-deps
   go test ./.github/scripts
   make frpc
   ```

   The Python tests require Python 3.13 and AWS CLI v2. Install the pinned
   linter in a temporary Python 3.13 virtual environment, then run
   `PYTHON=/path/to/venv/bin/python make lint-python`. On Debian or Ubuntu,
   install the matching `python3.13-venv` package first.

5. Describe user-visible behavior, security impact, and validation in the pull
   request.

Tests must not depend on LayerV credentials or a live LayerV environment.
Deployment smoke and soak automation is maintained separately from this public
source repository. A manual, fail-closed recovery workflow can live here when
it is version-bound to this module and contains only reviewed, non-secret fixed
slot topology. It must not contain a private endpoint, credential, cloud account
identifier, customer data, or rollout evidence.

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
