# sao

**English** | [中文](README_cn.md)

## Status

**Under active development—not stable.** The wire protocol, APIs, and behavior **may change without notice**. Do **not** rely on it for production or security-critical deployments until the project explicitly reaches a stable release.

## Motivation

The project is inspired by **security incidents where agents were given excessive privileges to operate on servers**—for example reuse of powerful human SSH access or overly broad automation credentials. The goal is to develop a **remote operation protocol and stack purpose-built for agents**: a dedicated path with **low-privilege execution**, **distinct agent identity**, **auditable behavior**, and **configurable policy**, instead of folding agent access into the same channels as human administrators.

**sao** is that channel: shell-like execution under a fixed low-privilege OS user, with auditable events and policy from configuration—separate from human SSH.

- **Wire protocol**: [`docs/protocol.md`](docs/protocol.md) (framing, auth, execution semantics)
- **Contributor / AI agent notes**: [`AGENTS.md`](AGENTS.md)
- **Agent skill** (how to invoke `sao` CLI): [`skills/sao-cli/SKILL.md`](skills/sao-cli/SKILL.md)

## Build and install

**Release build and install to `$(PREFIX)/bin` (default `/usr/local/bin`; often needs `sudo`):**

```bash
make install
# Or user prefix: make install PREFIX="$HOME/.local"
```

| Target | Description |
|--------|-------------|
| `make` / `make release` | `cargo build --release` (`sao` + `sao-server`) |
| `make install` | Install `sao` and `sao-server` |
| `make uninstall` | Remove those binaries |
| `make check` | `fmt` + `clippy -D warnings` + `test` |

For day-to-day development you can still use `cargo build --workspace`, etc.

**MSRV**: Rust **1.87+** recommended; `sao-core` pins `time = 0.3.36` for toolchains below 1.88.

**systemd**: see **deploy/systemd/sao-server.service**. First-trust flow and `known_hosts`: **Quick local try** below and **`docs/protocol.md`**.

## Quick local try

```bash
cp examples/config.yaml ./config.yaml
# Edit authorized_keys: run first
cargo run -p sao-client --bin sao -- key-fingerprint
# Paste the printed sao-ed25519 line into ./authorized_keys
cargo run -p sao-server -- --config config.yaml
# Other terminal: pin SPKI (fingerprint from server log or sao trust probe)
cargo run -p sao-client --bin sao -- trust add 127.0.0.1 8443 <fingerprint>
cargo run -p sao-client --bin sao -- run 127.0.0.1:8443 -- echo hello
```

After `make install`, use `sao` / `sao-server` instead of `cargo run`.

## CLI (`sao`)

| Subcommand | Description |
|------------|-------------|
| `run HOST:PORT -- <cmd>...` | After TLS + pin + auth, remote `bash -lc` |
| `trust probe HOST:PORT` | Print server SPKI fingerprint (trusted network only) |
| `trust add HOST PORT HEX64` | Append pin to `~/.sao/known_hosts` |
| `key-fingerprint` | Create/show agent key and `authorized_keys` line |

## Crates

| Crate | Role |
|-------|------|
| `sao-protocol` | Frame codec (`FrameCodec`) |
| `sao-core` | YAML config, `known_hosts`, policy, `sao-ed25519` auth, SPKI fingerprint |
| `sao-server` | TLS (optional self-signed), session, exec, audit logs |
| `sao-client` | **native-tls** then SPKI pin check, matches protocol |
