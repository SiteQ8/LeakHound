# Changelog

All notable changes to this project are recorded here. The format follows
Keep a Changelog, and the project uses semantic versioning.

## [0.1.0] - 2025

### Added

* First public release.
* Command line interface with `scan`, `rules`, and `version` subcommands.
* Curated rules for private keys, AWS keys, GitHub tokens, Google, Slack,
  Stripe, SendGrid, OpenAI, npm, JSON web tokens, credentials in urls, and
  hardcoded secrets.
* Shannon entropy detector for random looking strings.
* Git history scanning that reads every unique blob once.
* Output in text, json, and SARIF.
* Allow markers, a `.leakhoundignore` file, and glob excludes for tuning.
* Secret masking and stable fingerprints in every report.
* A hook definition for commit time scanning.
* Continuous integration across Python 3.9, 3.11, and 3.12.
