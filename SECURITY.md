# Threat Model

This document states what Cifra defends against, what it does not, and why —
so hardening work (memory locking, at-rest encryption, etc.) can be judged
against a concrete model instead of vague "more security is better" intuition.

## Assets

1. **Secret plaintext** — env var values and files stored in the vault.
2. **Private keys** — X25519 identities, one per team member, kept in the OS
   keychain.
3. **The passphrase** — protects the private key at rest.

## Adversaries considered

| Adversary | Capability |
|---|---|
| A. Git remote compromise | Full read access to everything ever pushed (`.cifra/secrets.enc`, `recipients`). No access to any machine. |
| B. Same-user local process (malware, a compromised dependency, another CLI tool) | Runs as the same OS user as `cifra`. Can read files the user can read, call `security`/`keyctl` without a prompt, read `/proc/<pid>/mem` on the same UID (Linux), inspect a crash dump. |
| C. Attacker with a copy of the disk / a backup | Can read every file, including OS keychain database files, at rest, after the machine is off. |
| D. Attacker with `root` / kernel access | Full memory and disk access on the running machine. |

## What defends what

### (a) Passphrase-encrypted-at-rest private key

The keychain blob is not the raw private key — it is an envelope encrypted
with a key derived from the user's passphrase (Argon2id → AES-256-GCM, see
`internal/keychain/passphrase.go`). This is what stands between **Adversary A**
and **Adversary C** and the private key: reading the raw keychain database
(`security find-generic-password -w`, `keyctl print`, or a stolen disk image)
yields only ciphertext. Without the passphrase, the key does not decrypt.

This is the primary control in this threat model. Everything else here is
narrower in scope.

### (b) Memory locking (`internal/secmem`) — swap and coredump only, nothing more

`secmem.Lock` (`unix.Mlock` + `unix.Madvise(MADV_DONTDUMP)` on Linux) is applied
to buffers holding the DEK, the decrypted private key, and decrypted payloads
while they exist in memory. This defends against exactly two things:

- the plaintext being paged out to swap, where it could outlive the process
  and be read later from the swap file/partition (a **Adversary C** scenario);
- the plaintext appearing in a core dump written after a crash (also
  **Adversary C**, or **B** if the dump is world/group readable).

It does **not** defend against **Adversary B** or **D** reading live process
memory while the key is unlocked — `mlock` only pins pages in RAM, it does not
make them inaccessible to a process with `ptrace`/`/proc/<pid>/mem` rights on
the same machine. Anyone who could attach a debugger to the `cifra` process
could already read the memory with or without `mlock`. Treat this as
"reduces the exposure window and prevents plaintext outliving the process
via swap/coredump," not "encrypts memory."

`mlock` is best-effort: containers commonly cap `RLIMIT_MEMLOCK` at 64 KiB,
under which `Lock` fails. `secmem.Lock` logs and continues rather than
failing the command — a locked-memory guarantee is not worth breaking
`cifra run` inside a container over.

### (c) The non-defendable residual: the passphrase itself, while it is typed

No control in this codebase — or in any passphrase-based system — protects
the passphrase between the moment the user types it and the moment it is
consumed by the KDF. A keylogger, a compromised terminal emulator, or
**Adversary B** reading live process memory during the brief window the
passphrase is held as a Go string/byte slice can all capture it. This residual
is inherent to "a human-memorized secret unlocks a machine-held key" and is
out of scope for this project to close. It is stated here so it is not
mistaken for a gap that `mlock` or keychain encryption should have covered —
they don't, by design, because the passphrase must exist in plaintext
somewhere for the KDF to run.

### (d) `CIFRA_PASSPHRASE` — CI only, never interactive

Setting the passphrase via environment variable is supported for headless CI
runs, where there is no TTY to prompt on and the alternative is skipping
encryption entirely. It should **not** be used on a developer's interactive
machine: environment variables are visible to every same-user process via
`/proc/<pid>/environ` (Linux) or `ps eww`-style inspection, which is a strictly
larger exposure window than a one-time interactive prompt. Prefer the
key-unlock agent (`cifra agent unlock`, TTL-bounded, in-memory only) for the
interactive "no repeated prompts" convenience instead.

## Summary table

| Control | Defends against | Does NOT defend against |
|---|---|---|
| Passphrase-encrypted keychain blob | Passive extraction of the keychain database (A, C) | An attacker who also has the passphrase; live memory reads while unlocked (B, D) |
| `secmem` memory locking | Swap/coredump exposure of plaintext buffers (C, and B for a readable dump) | Live memory reads via debugger/ptrace by a co-resident process (B, D) |
| Key-unlock agent TTL | Bounds how long a decrypted key exists in memory at all | Same residual as the keychain during the unlocked window |
| `CIFRA_PASSPHRASE` | Enables non-interactive CI use | Should not be treated as equivalent-security to an interactive prompt |

Nothing in this project defends against **Adversary D** (root/kernel access).
That has never been a goal — if an attacker has root on your machine, no
userspace program can keep a secret from them while it is in use.
