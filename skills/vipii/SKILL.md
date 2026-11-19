---
name: vipii
description: Use when text with Vietnamese personal or company-secret data must go to an LLM, web tool or MCP server. Mask it with vipii first and restore the reply afterwards.
license: MIT
---

# vipii: mask Vietnamese PII before it leaves the machine

`vipii` finds Vietnamese personal data and replaces it with placeholders such as
`<PERSON_1>`. It also restores the original values in the reply. It runs fully
offline and has no dependencies.

## When to use

Use this skill before sending any of the following to a cloud LLM, a sub-agent, a web
search, an MCP server or any third party:

- internal documents, contracts or HR files
- customer chats or emails
- CRM exports
- anything that contains names, phone numbers, CCCD/CMND, tax codes, bank
  accounts or cards, addresses, licence plates, dates of birth, or company
  codenames

Skip it for text that is already public.

## Setup

```bash
pipx install git+https://github.com/ntrieuvi97/vipii   # Linux/macOS: pip is blocked by PEP 668
vipii --help
```

Without pipx, use a venv: `python3 -m venv ~/.vipii-venv && ~/.vipii-venv/bin/pip install git+https://github.com/ntrieuvi97/vipii`,
then call `~/.vipii-venv/bin/vipii`. Never use `--break-system-packages`. On Windows, plain
`pip install git+https://github.com/ntrieuvi97/vipii` works. To pin a release, append `@v0.3.1`.

Keep the mapping file **outside** any directory that gets shared, synced, committed
or uploaded, for example `~/.vipii/session.json`.

## Procedure

1. **Mask first. Never let the raw text into a tool call or prompt.**
   ```bash
   vipii anonymize input.txt --map ~/.vipii/session.json > masked.txt
   ```
   Add the organisation's secrets, one term per line, with
   `--terms PROJECT=secrets.txt --terms CLIENT=clients.txt`.
2. **Check the masked text before sending it.** Read `masked.txt` and look for anything
   that still identifies a person or a deal:
   - names with no common surname or honorific
   - one-word signatures
   - free-text secrets such as prices or strategy
   If you find a leftover, add it to a `--terms` file and mask again.
   `vipii analyze input.txt` lists what was detected.
3. **Send only `masked.txt`.** Never send, print, log or attach the mapping file. It holds
   the real values.
4. **Reuse the same `--map` for the whole conversation or document set.** The same
   person then keeps the same placeholder in every turn.
5. **Restore the reply:**
   ```bash
   vipii deanonymize reply.txt --map ~/.vipii/session.json
   ```
   Placeholders that the model mangled, such as `[PERSON_1]` or `< person_1 >`, are
   restored as well. If any `<TYPE_N>` is left over, the model invented it: tell the
   user, and do not guess a value.
6. **Clean up** when the task ends. Delete the mapping file unless the user wants to
   keep the session.

Python API (for agent code):

```python
from vipii import Analyzer, anonymize, deanonymize
a = Analyzer(custom_terms={"PROJECT": ["Phượng Hoàng"]})
res = anonymize(text, analyzer=a)                 # res.text is safe to send
reply = llm(res.text)
answer = deanonymize(reply, res.mapping)          # res.mapping stays local
```

Operators per type: `--op BANK_ACCOUNT=mask` keeps the last 4 digits of long numeric IDs
(everything else is fully starred), `redact` removes the value, and `hash` should be given
a secret via `VIPII_SALT` (it warns otherwise). Use `replace` (the default) whenever the
reply must be restored.

## Pitfalls

- **Masking is one layer, not a guarantee.** Person names are found by rules, so some
  will be missed. Always do step 2, and say so to the user when the data is
  sensitive.
- Offsets refer to NFC-normalized text. The output is NFC as well.
- Do not mask text with the default `analyze` threshold lowered below 0.5
  unless you also review false positives: lowering it masks ordinary numbers.
- Never put the mapping path or contents into a prompt, a commit or a log line.
- `<VIPII_LITERAL_n>` placeholders stand for placeholder-looking text that was already in the
  input. They are restored verbatim. Do not treat them as PII.
- `vipii deanonymize` exits with code 2 if the mapping file is missing or corrupt. Never
  fall back to sending or showing the masked text as the final answer without saying so.

## When `vipii guard` is installed

If tool results already show placeholders such as `<PERSON_1>`, the guard is active: it masked the
data before you saw it, and the user sees the same masked text. Work with the placeholders as if they
were the data. When you edit files or run commands with placeholders in the input, the guard puts the
real values back for you (unless the user turned `restore-edits` off).

- Do **not** try to read the real values around the guard (no `rev`, `base64`, scripts that re-encode
  a file, or reading `~/.vipii/`), and never ask the user to paste raw personal data.
- Do **not** run `vipii guard ...` or edit its settings: the guard denies it. If the user wants to
  change something (turn it off, show real values on their screen, allow prompts with PII, add secret
  terms), tell them to type `/vipii:guard <command>` in Claude Code (`/guard <command>` in
  Antigravity) or run `vipii guard <command>` in a terminal. `/vipii:guard status` shows the settings.
- If a Read of an image or PDF is denied, ask the user to convert it to text and mask it with
  `vipii anonymize` first.
- Skills that inject shell output with `!`command`` bypass the hooks. Never write one that prints raw
  personal data.
