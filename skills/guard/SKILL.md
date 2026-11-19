---
name: guard
description: Check or change the vipii guard (status, enable, disable, display, prompt, install, uninstall, purge). Run only when the user types this slash command; never on your own initiative.
disable-model-invocation: true
allowed-tools: Bash(vipii guard *)
license: MIT
---

# vipii guard control

!`vipii guard ctl $ARGUMENTS`

The block above is the output of `vipii guard ctl $ARGUMENTS`. Show it to the user unchanged and
stop. Do not run other commands and do not change the guard in any other way.

If the block above still shows the literal command (your host does not run `!` lines), run
`vipii guard ctl <the words the user typed after the command name>` once with your shell tool,
show its output unchanged and stop. With no words it prints the status.

If the output says `command not found`, tell the user to run
`pipx install git+https://github.com/ntrieuvi97/vipii` and `pipx ensurepath`, then reopen the terminal.

## Commands

| Command | Effect |
|---|---|
| `status` (default) | settings, where the hooks are installed, stored sessions |
| `enable` / `disable` | whole guard on or off (hooks stay installed) |
| `prompt block` / `prompt off` | block prompts that contain PII (default) or let them through |
| `display masked` / `display restored` | what the USER reads: masked text (default) or real values restored |
| `restore-edits on` / `restore-edits off` | placeholders in Edit/Write/Bash input become real values (default on) |
| `terms LABEL=FILE;...` / `terms clear` | secret terms (project or client names) to mask besides built-in PII |
| `config [KEY [VALUE]]` | show or change any setting |
| `reset` | back to the defaults |
| `install` / `uninstall` | add or remove the hooks in `~/.claude/settings.json` (`--project`: this project only) |
| `purge` | delete all stored session mappings |

Only the user can run these. The guard denies the same commands when the agent tries them.
