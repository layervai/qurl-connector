# Changelog

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
