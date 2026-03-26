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

## Prerequisites

- **Rust**: stable toolchain, **1.87+** recommended ([rustup](https://rustup.rs/)).
- **Native build deps** (for `openssl-sys` / **native-tls** used by `sao-client`): **pkg-config** (or `pkgconf`) and **OpenSSL development headers**. Install on your distro before `cargo build` / `make`:

| Distribution | Command |
|--------------|---------|
| Debian, Ubuntu | `sudo apt-get update && sudo apt-get install -y pkg-config libssl-dev` |
| Fedora, RHEL 8+, CentOS Stream | `sudo dnf install -y pkgconf-pkg-config openssl-devel` |
| Alpine Linux | `apk add pkgconf openssl-dev` |
| openSUSE / SLE | `sudo zypper install pkg-config libopenssl-devel` |
| Arch Linux | `sudo pacman -S pkgconf openssl` |
| older RHEL / CentOS 7 | `sudo yum install pkgconfig openssl-devel` |

macOS: install OpenSSL via Homebrew if needed (`brew install openssl pkg-config`) and set `PKG_CONFIG_PATH` / `OPENSSL_DIR` as described in the `openssl-sys` crate docs.

## Build and install

**Release build and install to `$(PREFIX)/bin` (default `/usr/local/bin`; often needs `sudo`):**

```bash
make install
# Or user prefix: make install PREFIX="$HOME/.local"
```

| Target | Description |
|--------|-------------|
| `make` / `make release` | `cargo build --release` (`sao` + `sao-server`) |
| `make install` | Install `sao` and `sao-server` binaries |
| `make install-service` | Build, init `/etc/sao`, install binaries + systemd, enable & start (use `NO_START=1` to skip start) |
| `make uninstall` | Remove those binaries |
| `make check` | `fmt` + `clippy -D warnings` + `test` |

For day-to-day development you can still use `cargo build --workspace`, etc.

**MSRV**: Rust **1.87+** recommended; `sao-core` pins `time = 0.3.36` for toolchains below 1.88.

**systemd**: **`make install-service`** — build, init `/etc/sao`, install binaries and systemd unit (read-only exec env), enable and start. Requires **systemd ≥ 226**; aborts otherwise. Uses `ReadOnlyPaths` on ≥ 230, `ProtectSystem=strict` on 226–229. Use `NO_START=1` to skip start until keys are in `/etc/sao/authorized_keys`.

## Quick local try

```bash
cargo run -p sao-server -- init
# Edit .sao/authorized_keys: run first
cargo run -p sao-client --bin sao -- key-fingerprint
# Append the non-comment line from ~/.sao/keys/agent.ed25519.pub into .sao/authorized_keys
cargo run -p sao-server
# Other terminal: pin SPKI (fingerprint from server log or sao trust probe)
cargo run -p sao-client --bin sao -- trust add 127.0.0.1 8443 <fingerprint>
cargo run -p sao-client --bin sao -- run 127.0.0.1 -- echo hello
```

After `make install`, use `sao` / `sao-server` instead of `cargo run`.

## CLI (`sao`)

| Subcommand | Description |
|------------|-------------|
| `run [-p PORT] [--accept-new] HOST -- <cmd>...` | After TLS + pin + auth, remote `bash -lc` (default **8443**). New host or pin mismatch: **yes/no** on TTY, or **`--accept-new`** to auto-save/replace (unsafe on hostile networks). |
| `trust probe HOST:PORT` | Print server SPKI fingerprint (trusted network only) |
| `trust add HOST PORT HEX64` | Append pin to `~/.sao/known_hosts` |
| `key-fingerprint` | Create/show agent key; writes `~/.sao/keys/agent.ed25519.pub` — append its non-comment line to server `authorized_keys` |

## Crates

| Crate | Role |
|-------|------|
| `sao-protocol` | Frame codec (`FrameCodec`) |
| `sao-core` | YAML config, `known_hosts`, policy, `sao-ed25519` auth, SPKI fingerprint |
| `sao-server` | TLS (optional self-signed), session, exec, audit logs |
| `sao-client` | **native-tls** then SPKI pin check, matches protocol |
