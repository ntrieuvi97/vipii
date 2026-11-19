# Changelog

## [Unreleased]

## [0.3.1] - 2026-11-19

### Fixed
- `/vipii:guard` with an old `vipii` on PATH (no `guard` command) printed a raw argparse error and aborted;
  it now tells the user to upgrade. Errors reported through the slash command no longer fail the `!` shell
  line (exit code 0 with the message), because a failing `!` line aborts the whole skill.

### Added
- `vipii --version`.

## [0.3.0] - 2026-11-19

Alpha. The guard has had no independent review yet.

### Changed
- `vipii guard` now only masks by default: the `MessageDisplay` hook (real values on the user's screen) is
  no longer installed and is off unless `display restored` is set.

### Added
- Settings file `~/.vipii/guard-config.json` and control commands `vipii guard status | enable | disable |
  prompt | display | restore-edits | terms | config | reset | install | uninstall | purge`.
- Slash command skill `guard` (`/vipii:guard <command>` in Claude Code, `/guard` in Antigravity). It runs
  without the model, and the agent is denied from running `vipii guard ...` or reading the config file.

## [0.2.0] - 2026-11-19

Alpha. The guard has had no independent review yet.

### Added
- `vipii guard`: Claude Code hooks that mask tool output (`PostToolUse`), restore placeholders in
  Edit/Write/Bash input, block prompts that contain PII and restore values on screen only.
  `vipii guard --install/--uninstall/--purge`. Known limits are in the README.
- Claude Code plugin and marketplace manifests (`.claude-plugin/`) and an Antigravity plugin
  manifest (`.antigravity-plugin/`); the repo installs as a plugin on both.

### Fixed
- Windows reports a file that another process is replacing as `PermissionError`; the lock, the
  read and the atomic replace now treat it as "busy" and retry instead of failing or treating
  the mapping as corrupt.

## [0.1.0] - 2026-11-19

First public release.

### Added
- Recognizers for Vietnamese PII: `PERSON` (rule-based, accented and unaccented),
  `PHONE_NUMBER`, `NATIONAL_ID` (CCCD with province-code check, CMND with context),
  `TAX_CODE` (MST checksum, branch suffix), `CREDIT_CARD` (IIN + Luhn, Napas 9704),
  `BANK_ACCOUNT`, `ADDRESS`, `LICENSE_PLATE`, `DATE_OF_BIRTH`, `PASSPORT`,
  `SOCIAL_INSURANCE`, `EMAIL`, plus custom secret terms (deny lists).
- Context-word scoring with windows that stop at the nearest number, so a keyword
  belongs to the closest value.
- Anonymizer operators `replace` (consistent placeholders across calls), `mask`, `redact`
  and `hash` (salted); `deanonymize` that tolerates LLM-mangled placeholders.
- CLI `vipii analyze | anonymize | deanonymize`. The mapping file is written atomically
  with mode 0600, and stdin/stdout are UTF-8 on any locale.
- Agent skill `skills/vipii/SKILL.md` (Agent Skills format) that teaches coding agents
  to mask data before it leaves the machine.

### Security hardening (from the independent pre-release review)
- `mask` hides every letter and digit; only long numeric IDs keep their last 4 digits.
- Regexes rewritten to avoid catastrophic backtracking; time is linear (about 1 MB/s on
  normal text, about 4 s/MB worst case measured on dense PII).
- Placeholder-looking text in the input is wrapped as `<VIPII_LITERAL_n>`, so it cannot be
  "restored" to another record's value.
- `hash` uses HMAC-SHA256 (64-bit output) and warns without a secret salt.
- `deanonymize` matches ASCII placeholders only (no Unicode case-folding crash) and leaves
  unknown placeholders untouched.
- CLI: clean errors for a missing or corrupt mapping and for bad `--terms`/`--op`; the
  mapping is fsync'ed before the atomic replace.
- Fail-closed scoring: anti-context only breaks ties and never drops a value; names
  followed by Title-Case words are still masked; cards glued to other numbers are found.
- Unicode spaces and invisible characters (all Unicode `Cf` format characters, Hangul
  fillers, CGJ) are matched as separators, so inserting them no longer hides values in
  the tested cases.

### Known limitations
- Person names are found by rules (no NER model).
- Accuracy has not been measured on an independent labelled dataset.
