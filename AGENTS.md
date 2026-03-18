# AGENTS.md

Notes for **AI coding agents** working in this repository. Human readers should start from **README**; this file adds security model and protocol-boundary expectations.

**This repo is implemented in Rust.**

**Wire types and message semantics are defined in [`docs/protocol.md`](docs/protocol.md)**; implementation changes must keep that document in sync.

## Product

**sao** = a **dedicated channel for agents** (separate from human SSH), offering **shell-like execution** under a **fixed low-privilege OS user**, with:

- **Structured audit**: connection and execution events with agreed fields (often via **system logs / journald**).
- **Configurable policy**: every execution is checked by a **server-side policy engine** loaded from config (e.g. deny lists); **concrete rules are not hard-coded in the protocol**—they live in **YAML (or similar) config**.

Compared to “SSH with a restricted user”, the boundary is still **Unix permissions + policy**; sao adds a **dedicated entry**, **fixed audit contract**, **config-driven policy**, and **isolation from sshd exposure**.

## Transport and trust (summary)

- **Default**: **TLS** + server **self-signed cert**; client **pins server public key** (`~/.sao/known_hosts`, analogous to SSH `known_hosts`).
- **Optional**: enterprise CA verification; **plaintext TCP** only for explicit **development** (off by default).
- **Agent identity**: above TLS, **OpenSSH-style `authorized_keys`** multi-algorithm **public-key challenge–response** (`sao-ed25519` / `sao-rsa`, extensible).

Details: [`docs/protocol.md`](docs/protocol.md).

## Protocol vs config (required)

| Protocol / `docs/protocol.md` | Deployment config (e.g. `/etc/sao/config.yaml`) |
|-------------------------------|-----------------------------------------------|
| Frame layout, message types, auth/exec **semantics** | **Deny lists**, path/command patterns, policy-group mapping |
| **Error classes** on reject (e.g. policy) | **Audit verbosity**, log field toggles, quotas, timeouts |
| **`authorized_keys` line format** (type + base64 + optional name) | **Paths** to `authorized_keys`, TLS material; `known_hosts` is client-side |

**Policy text, audit knobs, and sensitive-operation deny lists belong in config, not in the protocol doc.** The protocol only requires: **compliant implementations must apply configured policy before exec and emit audit for the specified events.**

## Workspace and crate naming

- Prefer **`sao-` prefix** (`sao-protocol`, `sao-core`, `sao-server`, `sao-client`).

## Build and run

- **stable Rust**; `cargo build --workspace`; `cargo run -p <crate> -- --help`; release: `cargo build --release` or **`make install`**.

## Code style

Run `cargo fmt` and `cargo clippy -- -D warnings`; use clear naming, `Result` and explicit error types, exhaustive `match`, and keep modules focused. **Wire types match `docs/protocol.md`; rules and deny lists live only in config.**

## Tests

- Unit-test policy parsing, deny rules, frame codec, etc.; integration tests `#[ignore]` for TLS/privilege; prefer `cargo test -p <crate>` then `--workspace` as needed.

## Security and compliance (required)

1. Agents are untrusted; **execution capability** = **`sao` OS user + configured policy**; deny lists are auxiliary, not a substitute for file permissions.
2. Do not encourage permanent root or storing credentials in the repo.
3. Any expansion of attack surface must document mitigations in change notes.

## PR / commits

- Title: `[area] short description`.
- **Protocol or auth semantic changes must update [`docs/protocol.md`](docs/protocol.md).**
- Before merge: `cargo fmt --check`, clippy, `cargo test --workspace` (per CI).

## References

- [agents.md](https://agents.md/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
