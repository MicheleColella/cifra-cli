# Envault

> Git-backed, zero-trust secrets manager for developer teams.

Envault encrypts your API keys and tokens directly inside your existing Git repo.
No central vault, no third-party trust, no `.env` files committed in plaintext.
Private keys never leave your machine. Secrets are injected into processes in memory
at runtime — never written to disk.

---

## Why Envault

Most teams leak secrets without realising it:

- `.env` files committed to repos (anyone with clone access has the keys)
- Secrets passed over Slack, email, or copy-paste
- A shared vault that requires trusting a third-party server

Envault is different: it uses your team's existing Git remote as the transport.
Each secret is encrypted end-to-end — only team members who have been granted
access can decrypt. Remove a member from the vault and they lose future access.
No new infrastructure required.

---

## Install

**One-line install** (macOS / Linux, amd64 / arm64) — downloads the latest signed
release, verifies its checksum, and drops `envault` on your `PATH`:

```sh
curl -fsSL https://raw.githubusercontent.com/MicheleColella/envault-cli/main/scripts/install.sh | sh
```

Override the target with `ENVAULT_VERSION=v0.9.0` or `ENVAULT_INSTALL_DIR=~/.local/bin`.

**With Go** (any platform Go supports):

```sh
go install github.com/MicheleColella/envault-cli/cmd/envault@latest
```

**From source:**

```sh
make build && sudo make install   # builds ./envault and installs to /usr/local/bin
```

Releases are cross-compiled in CI and published to [GitHub Releases](https://github.com/MicheleColella/envault-cli/releases)
with a `checksums.txt` signed via keyless [cosign](https://github.com/sigstore/cosign).
Windows binaries are not yet published (pending a Windows keychain backend).

---

## Quick start

The full path from a fresh machine to using Envault both from your terminal
and from Claude Code, without ever retyping a passphrase inside Claude Code.
Run these in order.

### 1. Install the binary

```sh
curl -fsSL https://raw.githubusercontent.com/MicheleColella/envault-cli/main/scripts/install.sh | sh
```

Downloads the latest signed release for your platform, verifies its
checksum, and puts `envault` on your `PATH`. See [Install](#install) below
for alternatives (`go install`, building from source).

```sh
envault doctor
```

Sanity check: confirms the binary is found and the OS keychain backend
works. Recipients/secrets will show 0 until you initialise a vault — that's
expected at this point.

### 2. Initialise a vault in your project

```sh
cd your-project
envault init
```

Creates `.envault/` at the repo root (`config`, `recipients`,
`secrets.enc` — all encrypted; safe, and meant, to be committed to Git).

### 3. Generate your identity key

```sh
envault key new --id you@example.com
```

Generates an X25519 keypair. The private key is sealed in your OS keychain,
itself encrypted at rest under a passphrase **you choose right now** —
remember it (a password manager, not a sticky note). The public key is added
to `.envault/recipients` so the vault can encrypt secrets for you.

### 4. Add a secret

```sh
echo "sk-abc123" | envault add OPENAI_KEY
```

Encrypts the value with a fresh AES-256-GCM data key, wrapped to every
current recipient's public key. The plaintext never touches disk — only
ciphertext goes into `.envault/secrets.enc`.

### 5. Push the encrypted vault to your Git remote

```sh
envault push
```

Stages `.envault/`, commits, and pushes — only ciphertext ever leaves your
machine. A teammate does steps 1–3 with their own identity, you
`envault key import` their public key (or they `key export` it to you),
then they run `envault pull` to get access.

### 6. Install the Claude Code plugin

Type these as **Claude Code slash commands** (not shell commands), in a
Claude Code session opened in your project:

```
/plugin marketplace add MicheleColella/envault-cli
/plugin install envault@envault
```

This enables, for this project only:
- The **AI Privacy Shield** hooks — block `envault cat`/`export`/`add`/`set`
  in Bash, and mask any secret value that leaks into tool output.
- An embedded **MCP server** — Claude calls typed tools (`envault_status`,
  `envault_run`, …) instead of constructing bash commands, so there's no
  shell string to parse and no shell-injection surface.
- A **skill** that teaches Claude the vault workflow and its rules.

Enabling the plugin is reversible (`/plugin uninstall envault`) and scoped
per-project via `.claude/settings.json` (`enabledPlugins`) — never global by
default. It calls the `envault` binary already on your `PATH`; no separate
binary to install. See [Claude Code plugin](#claude-code-plugin) below for
the full component breakdown.

### 7. Unlock the key-unlock agent — once, then Claude Code needs no passphrase

```sh
envault agent unlock
```

Prompts for the passphrase you chose in step 3 (interactively, like any
other envault command), then hands the decrypted key to a small background
agent (ssh-agent-style, listening on `~/.envault/agent.sock`) that keeps it
cached in memory for 8 hours by default (`--ttl` to change). This agent is
**machine-wide**, not tied to this terminal or this project: it keeps
running after you close the terminal, and any Claude Code session opened
afterward — even from a different terminal, even for a different project
where you're also a recipient — finds it automatically.

From now on, until the TTL expires: `envault run`/`rotate`/`protect encrypt`,
`push`/`pull` rewrap, Claude Code's MCP server, and its secret-masking hook
all work with **no** passphrase prompt and no `ENVAULT_PASSPHRASE` needed.
Check what's unlocked with `envault agent status`; clear it early with
`envault agent lock` (or `agent stop` to also kill the background process).

### 8. Use it

```sh
envault run -- npm start
```

or, inside Claude Code, just ask it to do something with your secrets — e.g.
*"run the tests with the vault secrets injected"* — Claude calls the MCP
tools directly, no passphrase involved.

---

## Claude Code plugin

Envault ships as a [Claude Code](https://claude.com/claude-code) plugin — see
step 6 above for the install commands. This section is the deeper reference
for what it actually does.

The MCP server (`envault mcp serve`) exposes typed, JSON-Schema-validated
tools (`envault_status`, `envault_list`, `envault_rotate`, `envault_run`,
`envault_protect`, `envault_push`, `envault_pull`) so Claude calls Envault
directly instead of constructing bash commands — there's no shell string to
parse, so no shell-injection surface, and tool responses carry only metadata
(name, algorithm, recipient count, timestamps), never a secret value. It runs
headless, per Claude Code session, with no persistent daemon. Sealing a
**new** secret (`add`/`set`) is deliberately not exposed to Claude at all,
via MCP or bash — that requires a human to type it in their own terminal, or
the plaintext would have to pass through the model's context first.

Since the MCP server is headless, operations needing your private key
(`rotate`, `run`, `protect encrypt`, `push`/`pull`) normally need
`ENVAULT_PASSPHRASE` set — or, as in step 7 above, `envault agent unlock`
once from your own terminal so a small background agent
(`~/.envault/agent.sock`, ssh-agent-style) supplies the key instead. This is
opt-in and widens the key's exposure window in exchange for convenience;
`envault status`/`doctor` always show whether it's active.

`envault@envault` is `<plugin>@<marketplace>` — both are named `envault` in
[`marketplace.json`](.claude-plugin/marketplace.json).

Enabling the plugin is reversible (`/plugin uninstall envault`) and scoped via
`.claude/settings.json` (`enabledPlugins`). The plugin is **additive** — the CLI
installs above are still the way to use Envault from a plain terminal.

**Packaging decision:** the plugin's hooks call `envault` on your `PATH`; it does
**not** bundle platform-specific binaries. Install the binary once via any method
above, then enable the plugin. Run `envault doctor` if the hooks report the binary
is missing.

---

## Commands

| Command | Description | Status |
|---|---|---|
| `envault init` | Initialise a vault in the current repo | ✅ |
| `envault agent unlock/lock/stop/status` | Unlock your key into a background agent for passphrase-free use (Claude Code MCP, `postuse` masking) | ✅ |
| `envault key new` | Generate an identity key (sealed in OS keychain) | ✅ |
| `envault key list` | List vault recipients | ✅ |
| `envault key export` | Export your public key to share with teammates | ✅ |
| `envault key import` | Add a teammate's public key as a recipient | ✅ |
| `envault key delete` | Remove a recipient from the vault | ✅ |
| `envault key reseal` | Migrate a legacy unencrypted keychain key (or change its passphrase) to the encrypted-at-rest format | ✅ |
| `envault import <file.env>` | Bulk-import from an existing `.env` file | ✅ |
| `envault data store <file>` | Store an arbitrary file (JSON, PEM, binary…) | ✅ |
| `envault add <KEY>` | Add or update a single secret | ✅ |
| `envault set <KEY>` | Re-seal an existing secret with a new value | ✅ |
| `envault rm <KEY>` | Remove a secret from the vault | ✅ |
| `envault list` | List all secrets (names only — no plaintext) | ✅ |
| `envault cat <KEY>` | Decrypt and print a single secret | ✅ |
| `envault export` | Decrypt all env secrets as `export KEY=value` | ✅ |
| `envault rotate <KEY>` | Re-seal a secret with a fresh key for current recipients (true revocation) | ✅ |
| `envault push` | Stage, commit, and push the encrypted vault | ✅ |
| `envault pull` | Fetch and merge the vault; report changes | ✅ |
| `envault run [--only/--except] -- <cmd>` | Inject secrets in memory and run a command (0 bytes to disk) | ✅ |
| `envault exec` | Open `$SHELL` with all env secrets injected | ✅ |
| `envault scan [--staged/--all]` | Scan for secrets (pattern rules + entropy heuristic) | ✅ |
| `envault hook install --git` | Install a pre-commit hook that blocks secret leaks (`--uninstall` to remove) | ✅ |
| `envault protect add <path>` | Mark a path/glob off-limits to AI agents (blocked by the Envault plugin) | ✅ |
| `envault audit log show/verify` | Show or verify the tamper-evident AI access log | ✅ |
| `envault mcp serve [--project <path>] [--dry-run]` | Start the Envault MCP server for Claude Code (JSON-RPC 2.0 over stdio); `--dry-run` prints the tool schemas | ✅ |
| `envault status` | Structured health check of the vault, hooks, and shield | ✅ |
| `envault agent-check` | Verify the AI-agent environment is ready (exit 1 if not) | ✅ |
| `envault doctor` | Diagnose install state, hooks, keychain, and Git remote (no secrets exposed) | ✅ |
| `envault uninstall [--keys]` | Remove the vault and Git hook (`--keys` also clears keychain); `install.sh --uninstall` removes the binary. Claude Code: `/plugin uninstall envault` | ✅ |

> Add `--agent-safe` (alias `--json`) to any command for structured JSON output;
> in this mode `cat`/`export` refuse to print plaintext unless you pass `--force`.

---

## Security model

Envault is designed so that you do not have to trust anyone except your Git remote:

- **End-to-end encryption** — secrets are encrypted on your machine before they are committed. Each secret uses a random data key (AES-256-GCM) wrapped to every recipient's X25519 public key. Only recipients with a matching private key can decrypt.
- **Private keys never leave your machine** — they are sealed in the OS keychain (macOS Keychain via `security`, Linux kernel keyring via `keyctl`) and are never sent anywhere.
- **Private keys are encrypted at rest** — the keychain blob is itself encrypted under a passphrase-derived key (Argon2id → AES-256-GCM), so even a process that reads your keychain gets useless ciphertext without your passphrase. `envault key reseal` migrates a legacy unencrypted key in place.
- **Memory hardening (best-effort)** — DEKs, private keys, and decrypted payloads are pinned against swap and excluded from core dumps while in use (`internal/secmem`). Scope is narrow by design — see [SECURITY.md](SECURITY.md) for the full threat model, including what this does *not* defend against.
- **Durable writes** — the encrypted secrets store is fsynced before the atomic rename that publishes it, so a crash mid-write never corrupts the vault.
- **Zero-trust remote** — the Git remote only ever stores ciphertext. Even if the remote is compromised, no secrets are exposed.
- **No disk writes** — secrets are decrypted in memory and injected directly into the child process. Nothing is written to a temp file.
- **Per-recipient access control** — adding or removing a teammate from the vault controls who can decrypt. `rotate` re-seals a secret with a fresh data key for the current recipients, truly revoking a removed member.
- **Leak prevention** — an optional Git pre-commit hook (`envault hook install --git`) scans the staged diff for `.env` files, private keys, and known API tokens, blocking the commit before a secret ships.
- **AI Privacy Shield** — the [Envault Claude Code plugin](#claude-code-plugin) blocks AI agents from reading protected paths or running `envault cat`/`export`, masks any vault secret that appears in tool output, and records every access in a tamper-evident audit log.
- **Integrity guaranteed** — ciphertext is authenticated; any tampering is detected and rejected before decryption.
- **Key-unlock agent is opt-in and clearly bounded** — `envault agent unlock` trades the "decrypt on demand, clear immediately" norm for a decrypted key cached in memory for a bounded TTL (default 8h), so headless callers (Claude Code) can skip the passphrase. Nothing changes unless you explicitly run it; `envault status`/`doctor` always show whether it's active.

---

## Status

Active development — the full core workflow is implemented end-to-end: init a vault,
manage keys, add/import secrets, push/pull over Git, `envault run -- <cmd>` to inject
secrets in memory, AI-agent integration (Claude Code Privacy Shield), and one-line
install from signed cross-platform releases.

| Milestone | Status |
|---|---|
| v0.1–0.2 — Scaffold, CI, crypto core | ✅ shipped |
| v0.3 — Vault init, key management | ✅ shipped |
| v0.4 — Secret import, add/set/rm, list, cat/export | ✅ shipped |
| v0.5 — Git push / pull, re-wrap & rotation, conflict merge | ✅ shipped |
| v0.6 — Runtime injection (`envault run`, `exec`) | ✅ shipped |
| v0.7 — Git pre-commit hook & secret detection | ✅ shipped |
| v0.8 — Claude Code & AI agent integration (Privacy Shield) | ✅ shipped |
| v0.9.0 — Installer & cross-platform signed releases | ✅ shipped |
| v0.9.1 — Clean uninstall & doctor | ✅ shipped |
| v0.9.2 — Claude Code plugin & marketplace distribution | ✅ shipped |
| v0.9.3 — Embedded MCP server (Claude Code native protocol) | ✅ shipped |
| v0.9.4 — Key-unlock agent (ssh-agent-style, passphrase-free Claude Code UX) | ✅ shipped |
| v0.9.5 — Integration testing (Forgejo container E2E) | ✅ shipped |
| v0.9.6 — Security hardening & coverage | ✅ shipped |
| v0.9.7 — Custom Git merge driver & disaster recovery | 🔜 next |
| v1.0.0 — Stable release | planned |

---

## Requirements

- Go 1.25+
- macOS or Linux
- Git (any version with remote support)

---

## Build

```sh
make build          # static binary → ./envault  (CGO_ENABLED=0)
go test ./...       # run the test suite
```

The binary embeds its version from the latest git tag:

```sh
./envault --version
```

---

## Contributing

The project is in active development. The roadmap is managed internally.
Feel free to open an issue to discuss ideas, report bugs, or ask questions.

---

## License

MIT
