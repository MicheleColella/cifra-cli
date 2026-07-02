---
name: cifra
description: Use when a repo has a .cifra/ vault — Cifra is a Git-backed, zero-trust secrets manager. Covers reading vault state, injecting secrets into commands, syncing with the team, and the AI Privacy Shield rules that keep plaintext out of model context. Triggers on "cifra", ".cifra", "secrets", "API key", ".env file", "inject secrets", "vault recipients".
---

# Cifra

This repo's secrets are managed by **Cifra**. They are encrypted at rest in
`.cifra/secrets.enc` — never plaintext on disk. The Git remote only stores
ciphertext; private keys never leave the machine.

## Security rules (the AI Privacy Shield)

- **NEVER** run `cifra cat` or `cifra export` without `--force` — the PreToolUse
  hook blocks them to keep plaintext out of model context. Don't suggest `--force`
  to work around it.
- **NEVER seal a brand-new secret yourself** — not via `cifra add`/`cifra set`
  in Bash (e.g. `echo value | cifra add KEY`), and there is no MCP tool for it
  either. Doing this requires the plaintext to pass through your own context first,
  which is exactly what the Privacy Shield exists to prevent — the PreToolUse hook
  blocks it in Bash for the same reason. If the user wants to add or update a
  secret, tell them to run `cifra add <KEY>` / `cifra set <KEY>` themselves in
  their own terminal — do not offer to do it "for convenience" and do not suggest
  `--force` to work around the block.
- Prefer `cifra run -- <cmd>` to inject secrets into a child process **in memory**,
  never writing them anywhere.
- Do not print, cat, or log the contents of `.cifra/secrets.enc`.
- Paths registered via `cifra protect add` are blocked from Read/Write/Edit/Bash.

## Common commands

| Goal | Command | Who runs it |
|---|---|---|
| List sealed entries (names only) | `cifra list` | either |
| Seal a new secret | `cifra add <KEY>` | **user only**, in their own terminal |
| Re-seal an existing secret with a new value | `cifra set <KEY>` | **user only**, in their own terminal |
| Run a command with secrets injected in memory | `cifra run -- <cmd>` | either |
| Open a shell with secrets injected | `cifra exec` | user |
| Sync vault with the team via Git | `cifra push` / `cifra pull` | either |
| Rotate a secret (true revocation, no new value needed) | `cifra rotate <KEY>` | either |
| Show recipients | `cifra key list` | either |
| Vault health | `cifra status` | either |
| Manage protected paths | `cifra protect add\|list\|remove <path>` | either |
| Audit log | `cifra audit log show` / `verify` | either |
| Diagnose install | `cifra doctor` | either |
| Unlock the key for passphrase-free use | `cifra agent unlock` | **user only**, in their own terminal |
| Check what's unlocked / lock again | `cifra agent status` / `lock` | either |

## MCP tools (preferred over bash when available)

If the `cifra` MCP server is connected (tools named `cifra_status`,
`cifra_list`, `cifra_rotate`, `cifra_run`, `cifra_protect`,
`cifra_push`, `cifra_pull`), prefer calling those tools directly instead of
the equivalent bash command — parameters go through JSON-Schema validation
instead of a shell string, and tool responses only ever contain metadata
(name, algorithm, recipient count, timestamps), never a secret value.
`cat`/`export`/`data`/`import`/`key *`/**`add`**/**`set`** have no MCP
equivalent, by design — those still go through bash (where the Privacy Shield
hooks apply), or must be run by the user themselves for `add`/`set`.

## Passphrase-free operation (the key-unlock agent)

If the user has run `cifra agent unlock` from their own terminal, commands
needing the private key (`cifra_rotate`, `cifra_run`,
`cifra_protect` encrypt, `push`/`pull`, and `postuse` masking) work with no
passphrase prompt and no `CIFRA_PASSPHRASE` — check `cifra status` /
`cifra doctor` for "Agent unlocked keys" / "Key-unlock agent" to see if
this is active. If a private-key operation fails with a passphrase error and
the user seems to expect it to "just work", suggest `cifra agent unlock`
(run by them, in a real terminal — it prompts interactively) rather than
suggesting they set `CIFRA_PASSPHRASE` in the environment, which is the
less secure, more manual fallback.

## Notes

- `cifra status` / `list` / `audit` / `doctor` are safe, read-only, and never
  expose secret values — use them freely to understand vault state.
- If a command needs a passphrase non-interactively and no agent is unlocked,
  it reads `CIFRA_PASSPHRASE`.
- The binary must be on PATH (installed via the Cifra installer, Homebrew, or
  `go install`). Run `cifra doctor` if commands are not found.
