# Changelog

## [Unreleased]

### Added
- Claude Code plugin and marketplace manifests (`.claude-plugin/`) and an Antigravity plugin
  manifest (`.antigravity-plugin/`); the repo installs as a plugin on both.

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
