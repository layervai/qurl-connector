# Changelog

## [0.11.5](https://github.com/layervai/qurl-connector/compare/v0.11.4...v0.11.5) (2026-09-03)


### Bug Fixes

* **share:** age refused proxies out of the ceiling; measure the lead from the second route ([#69](https://github.com/layervai/qurl-connector/issues/69)) ([a6423c0](https://github.com/layervai/qurl-connector/commit/a6423c086589ed0c3d201ee7204e676761761200))

## [0.11.4](https://github.com/layervai/qurl-connector/compare/v0.11.3...v0.11.4) (2026-09-03)


### Bug Fixes

* **share:** window NewProxy registration; lead follows measured rate ([#67](https://github.com/layervai/qurl-connector/issues/67)) ([a1ee171](https://github.com/layervai/qurl-connector/commit/a1ee171876bcd861e335b13c08ea5e9da25c76c8))

## [0.11.3](https://github.com/layervai/qurl-connector/compare/v0.11.2...v0.11.3) (2026-09-03)


### Bug Fixes

* **share:** re-fence native session recovery to the current endpoint ([#64](https://github.com/layervai/qurl-connector/issues/64)) ([e7d1c80](https://github.com/layervai/qurl-connector/commit/e7d1c8086c3a10126c630481b2f1d4052be9bb6f))

## [0.11.2](https://github.com/layervai/qurl-connector/compare/v0.11.1...v0.11.2) (2026-09-03)


### Bug Fixes

* **frpc:** own the retirement ledger in the runtime, not the ready block ([#62](https://github.com/layervai/qurl-connector/issues/62)) ([9d4bf32](https://github.com/layervai/qurl-connector/commit/9d4bf32910075d1d251fdbc5b829926d8fe55bc7))

## [0.11.1](https://github.com/layervai/qurl-connector/compare/v0.11.0...v0.11.1) (2026-09-03)


### Bug Fixes

* **frpc:** keep retired routes out of re-admission and probe liveness at the fallback ([#59](https://github.com/layervai/qurl-connector/issues/59)) ([9ae3422](https://github.com/layervai/qurl-connector/commit/9ae3422052711acc8576fe2c99ca8ab77b1db22b))

## [0.11.0](https://github.com/layervai/qurl-connector/compare/v0.10.0...v0.11.0) (2026-09-03)


### ⚠ BREAKING CHANGES

* **frpc:** a revoked route no longer exits the process.

### Bug Fixes

* **frpc:** serve all routes on one Connector session ([#56](https://github.com/layervai/qurl-connector/issues/56)) ([221434c](https://github.com/layervai/qurl-connector/commit/221434c032d4a0489bb905a8091801796dd26743))

## [0.10.0](https://github.com/layervai/qurl-connector/compare/v0.9.0...v0.10.0) (2026-09-03)


### ⚠ BREAKING CHANGES

* **frpc:** startSharedService no longer rejects configs with more than one route. Callers that relied on the one-resource guarantee must not assume a single ResourceRunner per process.

### Features

* **frpc:** serve every configured resource from one Connector process ([#54](https://github.com/layervai/qurl-connector/issues/54)) ([33b89f8](https://github.com/layervai/qurl-connector/commit/33b89f86435374f338a8df48f03f8fe5a2c0d79e))
* **share:** session group runtime serving many routes on one admission ([#55](https://github.com/layervai/qurl-connector/issues/55)) ([f80e729](https://github.com/layervai/qurl-connector/commit/f80e7296f581159577ab9df151af5642d7116be6))


### Continuous Integration

* **deps:** bump age-check-actions reusable to v0.13.0 ([#49](https://github.com/layervai/qurl-connector/issues/49)) ([785c3fd](https://github.com/layervai/qurl-connector/commit/785c3fd5778ed265591bbe2b5bc3372f321695aa))
* **deps:** bump remaining ops-routines-workflows shims to v0.13.0 ([#52](https://github.com/layervai/qurl-connector/issues/52)) ([8595dfe](https://github.com/layervai/qurl-connector/commit/8595dfe7fa0e6045e1b887487ac0049ea60d997f))

## [0.9.0](https://github.com/layervai/qurl-connector/compare/v0.8.13...v0.9.0) (2026-09-01)


### ⚠ BREAKING CHANGES

* **share:** NativeRuntimeConfig and NativeRuntime no longer expose SessionOptions. No separate session-only option channel remains. Configure credential-free UDPOptions for registered-session operations; these retained options also apply to native lifecycle, discovery, assignment refresh, and the account-credential-authenticated device-authorization recovery client.

### Bug Fixes

* **share:** keep registered sessions on native UDP ([#44](https://github.com/layervai/qurl-connector/issues/44)) ([e99252b](https://github.com/layervai/qurl-connector/commit/e99252bbcb74a5cde88e17cef42429d8858f9d75))

## [0.8.13](https://github.com/layervai/qurl-connector/compare/v0.8.12...v0.8.13) (2026-09-01)


### Bug Fixes

* **service:** settle rapid launchd label reuse ([#41](https://github.com/layervai/qurl-connector/issues/41)) ([9fcd76c](https://github.com/layervai/qurl-connector/commit/9fcd76c5fa59a9bfdfee9563b34a02a9f68f6b16))

## [0.8.12](https://github.com/layervai/qurl-connector/compare/v0.8.11...v0.8.12) (2026-09-01)


### Features

* **agent:** relay registered session operations ([#39](https://github.com/layervai/qurl-connector/issues/39)) ([fe8436d](https://github.com/layervai/qurl-connector/commit/fe8436d6c9a00a5530f5ee2fe10ca75af986e6f2))

## [0.8.11](https://github.com/layervai/qurl-connector/compare/v0.8.10...v0.8.11) (2026-09-01)


### Bug Fixes

* resume terminal session retirement ([#37](https://github.com/layervai/qurl-connector/issues/37)) ([df1e388](https://github.com/layervai/qurl-connector/commit/df1e388419b14c412d69469c47b2c4e696b5c1b1))

## [0.8.10](https://github.com/layervai/qurl-connector/compare/v0.8.9...v0.8.10) (2026-08-31)


### Bug Fixes

* **service:** tolerate cold Windows task scheduler ([#30](https://github.com/layervai/qurl-connector/issues/30)) ([17a2464](https://github.com/layervai/qurl-connector/commit/17a24643169e5c18ed5590209c9a8cadd62c1159))

## [0.8.9](https://github.com/layervai/qurl-connector/compare/v0.8.8...v0.8.9) (2026-08-31)


### Bug Fixes

* **agent:** support secure native state on Windows ([#28](https://github.com/layervai/qurl-connector/issues/28)) ([c74e539](https://github.com/layervai/qurl-connector/commit/c74e539fa49037048051dad5a8363daf2c0a8fcc))

## [0.8.8](https://github.com/layervai/qurl-connector/compare/v0.8.7...v0.8.8) (2026-08-31)


### Features

* support native recovery and Linux user daemon ([#26](https://github.com/layervai/qurl-connector/issues/26)) ([7af80c9](https://github.com/layervai/qurl-connector/commit/7af80c9e8b1275636a4363dd342232a7ec01b07f))

## [0.8.7](https://github.com/layervai/qurl-connector/compare/v0.8.6...v0.8.7) (2026-08-30)


### Bug Fixes

* recover native lifecycle transients ([#24](https://github.com/layervai/qurl-connector/issues/24)) ([6775522](https://github.com/layervai/qurl-connector/commit/6775522e1a38fe49cd9bcafe8f1c265963862e12))

## [0.8.6](https://github.com/layervai/qurl-connector/compare/v0.8.5...v0.8.6) (2026-08-29)


### Bug Fixes

* **share:** report bounded session retry failures ([#22](https://github.com/layervai/qurl-connector/issues/22)) ([9c876a1](https://github.com/layervai/qurl-connector/commit/9c876a1cde65c016a009849e54dcaf2e3afee7b5))

## [0.8.5](https://github.com/layervai/qurl-connector/compare/v0.8.4...v0.8.5) (2026-08-29)


### Bug Fixes

* **service:** explain unsafe Windows log recovery ([#20](https://github.com/layervai/qurl-connector/issues/20)) ([02a32c6](https://github.com/layervai/qurl-connector/commit/02a32c65596b832e8d3fe64feb7ec4bdbe7ed7f8))

## [0.8.4](https://github.com/layervai/qurl-connector/compare/v0.8.3...v0.8.4) (2026-08-29)


### Features

* **service:** manage per-user jobs on Windows ([#19](https://github.com/layervai/qurl-connector/issues/19)) ([8856bd4](https://github.com/layervai/qurl-connector/commit/8856bd4b43079bdd1fb20b31e59c9cc152dbf80a))


### Bug Fixes

* **share:** persist native session operations ([#18](https://github.com/layervai/qurl-connector/issues/18)) ([6baecad](https://github.com/layervai/qurl-connector/commit/6baecad67bf3f7d5ae7c8256f1cd7b689498d98a))


### Continuous Integration

* drop Task from the review, keep code search ([#17](https://github.com/layervai/qurl-connector/issues/17)) ([0f61a86](https://github.com/layervai/qurl-connector/commit/0f61a8649c59dd3919b765bff7670450bc568b58))
* enable code search and delegation in the PR review ([#15](https://github.com/layervai/qurl-connector/issues/15)) ([168dca5](https://github.com/layervai/qurl-connector/commit/168dca53cf8b4fdcc07d86679b15f977d82de9e6))

## [0.8.3](https://github.com/layervai/qurl-connector/compare/v0.8.2...v0.8.3) (2026-08-27)


### Bug Fixes

* **share:** preserve successful refresh handoff ([#14](https://github.com/layervai/qurl-connector/issues/14)) ([74bebfc](https://github.com/layervai/qurl-connector/commit/74bebfcd0816b70627fff359d41e9e1734c256e8))


### Continuous Integration

* **deps:** exempt provenance-verified first-party modules from age check ([b7e78ae](https://github.com/layervai/qurl-connector/commit/b7e78ae730cb2fcb996c936f1687a99cd2ed2544))
* move Claude PR review to Opus 5 ([#12](https://github.com/layervai/qurl-connector/issues/12)) ([05b9f86](https://github.com/layervai/qurl-connector/commit/05b9f8651836ad7fa5e4e800e5c7723f81567ff4))

## [0.8.2](https://github.com/layervai/qurl-connector/compare/v0.8.1...v0.8.2) (2026-08-26)


### Bug Fixes

* **share:** recover rejected agent credentials ([#9](https://github.com/layervai/qurl-connector/issues/9)) ([490a717](https://github.com/layervai/qurl-connector/commit/490a7175e045ab15a30fdd7b65c5f3be0c76ac12))

## [0.8.1](https://github.com/layervai/qurl-connector/compare/v0.8.0...v0.8.1) (2026-08-26)


### Bug Fixes

* **share:** bind CRID resource into native knock ([#7](https://github.com/layervai/qurl-connector/issues/7)) ([2ad86da](https://github.com/layervai/qurl-connector/commit/2ad86dafb95a7c3c7f50753b1b79eb5896a1f3c5))

## [0.8.0](https://github.com/layervai/qurl-connector/compare/v0.7.1...v0.8.0) (2026-08-26)


### ⚠ BREAKING CHANGES

* publish CRID lifecycle runtime module

### Features

* publish CRID lifecycle runtime module ([7cd7455](https://github.com/layervai/qurl-connector/commit/7cd7455763b7b6e4d4ed1098d17cd803b192b98a))


### Build System

* **deps:** repin the FRP fork to v1.0.0 ([#5](https://github.com/layervai/qurl-connector/issues/5)) ([e3ba0c0](https://github.com/layervai/qurl-connector/commit/e3ba0c07e3a8c07c8d31c087619197699744cc02))


### Continuous Integration

* align public repository controls ([#6](https://github.com/layervai/qurl-connector/issues/6)) ([df6cbd3](https://github.com/layervai/qurl-connector/commit/df6cbd3ab87af40391d1b7ad83aed61fdce15f50))

## Changelog

The public release history begins with the first release from this repository.
Future entries are maintained by release-please.
