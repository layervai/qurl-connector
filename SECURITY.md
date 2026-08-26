# Security Policy

## Reporting Security Issues

The LayerV team takes security bugs seriously. To report a security issue,
please use the GitHub Security Advisory
["Report a Vulnerability"](https://github.com/layervai/qurl-connector/security/advisories/new) tab.

We will respond within 48 hours with next steps. Report bugs in third-party
dependencies to the maintainer of the dependency.

## Supply Chain Security

- Releases are public Go module source tags. This repository does not publish a
  customer binary or container artifact; users install the `qurl` CLI from its
  own release channel.
- The FRP fork is pinned to a reviewed public source revision and checksum.
- Dependencies are monitored via Dependabot and govulncheck
- CodeQL runs on all PRs and weekly
