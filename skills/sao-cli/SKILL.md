---
name: sao-cli
description: Invokes the installed sao client CLI to run remote shell via sao-server, manage TLS SPKI pins in known_hosts, and show agent key material for authorized_keys. Use when the user asks to execute commands on a remote host through sao, add server trust, probe certificate fingerprint, or prepare agent authentication—not for compiling the project from source.
---

# sao CLI — agent playbook

For **agents**: the user wants you to run **`sao` in the terminal** for remote execution or trust setup. This skill assumes **only an installed `sao` binary**—not building from source.

Format aligns with the open [Agent Skills](https://agentskills.io/home) convention.

## 1. Before any `sao` command

1. Run **`command -v sao`** (Windows: **`where sao`**).
2. **If missing or non-zero exit**:
   - Do **not** use `cargo build` / `cargo run` as part of this flow.
   - Tell the user to **install the sao client** (package manager, release artifact, internal distro, etc.) and ensure `sao` is on `PATH`, then retry.
3. **If present**: optionally run **`sao --help`**, then follow the workflows below.

## 2. Subcommands (run in shell)

Replace placeholders: `HOST`, `PORT`, `HEX64` (64-char lowercase hex SPKI fingerprint), remote shell text.

| Goal | Invocation |
|------|--------------|
| Remote exec (subject to server policy) | `sao run [-p PORT] [--accept-new] HOST -- <cmd…>` — default port **8443**; `-p` after `run`. Missing pin: **yes/no** on TTY or **`--accept-new`**. Pin mismatch (cert changed): **yes/no** to replace, or **`--accept-new`** to auto-replace |
| Store SPKI pin in `~/.sao/known_hosts` | `sao trust add HOST PORT HEX64` |
| Read presented cert SPKI on a **trusted network** (no identity guarantee) | `sao trust probe HOST:PORT` |
| Show/create agent key; writes `~/.sao/keys/agent.ed25519.pub` (append its non-comment line to server) | `sao key-fingerprint` |

**Agent behavior**:

- Pick the matching row, execute via **run_terminal_cmd** (or equivalent). Ask the user for **HOST**, optional **PORT** (default 8443), fingerprint, or remote command when unclear.
- Return **stdout/stderr** to the user; on non-zero exit, explain likely causes (auth, policy, network).

## 3. Logical prerequisites (not install steps)

Usually already satisfied by the user/ops:

- **sao-server** running on the target host with TLS reachable.
- **`~/.sao/known_hosts`** contains a pin for `HOST PORT` (`trust add` or admin-supplied fingerprint).
- **`~/.sao/keys/agent.ed25519`** (private) and **`agent.ed25519.pub`** (public line for server) exist, and that **`sao-ed25519 …` line** is on the server **`authorized_keys`**.

If not, guide in order: **key-fingerprint → user adds line on server → trust add (or probe) → run**.

## 4. Safety

- **Production**: do not recommend disabling TLS or plaintext by default.
- **`trust probe`** does not prevent MITM; prefer admin-supplied fingerprint + **`trust add`**.
- Exit **126** / policy-style output → **policy denial**; do not suggest bypass; narrow the command or escalate to ops.
- Wire semantics: **`docs/protocol.md`**. Installing from source: repo **`make install`** (see **README**).

## 5. Troubleshooting

| Symptom | Hint |
|---------|------|
| `command -v sao` fails | Install client and fix `PATH` |
| SPKI / pin errors | Fingerprint must match server cert; renew cert → new `trust add` |
| Auth failure | Server `authorized_keys` must include current agent public key line |
| Connection refused | Address, port, firewall, server listen |
