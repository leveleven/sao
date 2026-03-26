# sao

[English](README.md) | **中文**

## 项目状态

**仍处于开发阶段，尚未稳定。** 线协议、API 与实现行为 **可能随时变更**。在项目明确发布稳定版之前，**请勿**用于生产环境或对安全性要求极高的场景。

## 背景与目标

本项目灵感来自 **Agent 对服务器操作权限过高** 所引发的各类安全事件（例如与人类管理员共用高权限 SSH、或自动化凭据范围过大）。目标是开发 **专门面向 Agent 的远程操作协议与实现**：在 **低权限执行**、**独立 Agent 身份**、**可审计** 与 **可配置策略** 的前提下提供远端操作能力，而不是把 Agent 接入与人相同的强权限通道。

**sao** 即该通道：在固定低权限 OS 用户下提供类 shell 执行能力，带审计与配置化策略，与人用 SSH 分离。

- **协议**：[`docs/protocol.md`](docs/protocol.md)（帧格式、认证、执行语义）
- **贡献者 / AI Agent 说明**：[`AGENTS.md`](AGENTS.md)
- **Agent 技能**（如何调用 `sao` CLI）：[`skills/sao-cli/SKILL.md`](skills/sao-cli/SKILL.md)

## 环境准备

- **Rust**：稳定版工具链，建议 **1.87+**（见 [rustup](https://rustup.rs/)）。
- **本机编译依赖**（`sao-client` 使用的 **native-tls** / `openssl-sys` 需要）：**pkg-config**（或 `pkgconf`）与 **OpenSSL 开发头文件**。在 `cargo build` / `make` 之前按发行版安装：

| 发行版 | 命令 |
|--------|------|
| Debian、Ubuntu | `sudo apt-get update && sudo apt-get install -y pkg-config libssl-dev` |
| Fedora、RHEL 8+、CentOS Stream | `sudo dnf install -y pkgconf-pkg-config openssl-devel` |
| Alpine Linux | `apk add pkgconf openssl-dev` |
| openSUSE / SLE | `sudo zypper install pkg-config libopenssl-devel` |
| Arch Linux | `sudo pacman -S pkgconf openssl` |
| 旧版 RHEL / CentOS 7 | `sudo yum install pkgconfig openssl-devel` |

macOS：若需可用 Homebrew 安装 OpenSSL（`brew install openssl pkg-config`），并按 `openssl-sys` 文档设置 `PKG_CONFIG_PATH` / `OPENSSL_DIR`。

## 构建与安装

**Release 编译并安装到 `$(PREFIX)/bin`（默认 `/usr/local/bin`，常需 `sudo`）：**

```bash
make install
# 或用户目录：make install PREFIX="$HOME/.local"
```

| 目标 | 说明 |
|------|------|
| `make` / `make release` | `cargo build --release`（sao + sao-server） |
| `make install` | 安装 `sao`、`sao-server` 二进制 |
| `make install-service` | 构建、初始化 `/etc/sao`、安装二进制与 systemd 服务并启动（`NO_START=1` 可延后启动） |
| `make uninstall` | 移除上述二进制 |
| `make check` | `fmt` + `clippy -D warnings` + `test` |

开发调试仍可用 `cargo build --workspace` 等。

**MSRV**：建议 **Rust 1.87+**；`sao-core` 固定 `time = 0.3.36` 以兼容低于 1.88 的工具链。

**systemd**：**`make install-service`** — 构建、初始化 `/etc/sao`、安装二进制与 systemd 单元（执行环境只读）、启用并启动。**要求 systemd ≥ 226**，否则中止。≥ 230 使用 `ReadOnlyPaths`，226–229 使用 `ProtectSystem=strict`。`NO_START=1` 可延后启动。

## 快速本地试跑

```bash
cargo run -p sao-server -- init
# 编辑 .sao/authorized_keys：先运行
cargo run -p sao-client --bin sao -- key-fingerprint
# 将 ~/.sao/keys/agent.ed25519.pub 中的非注释行追加到 .sao/authorized_keys
cargo run -p sao-server
# 另终端：信任 SPKI（用服务端打印的指纹或 trust probe）
cargo run -p sao-client --bin sao -- trust add 127.0.0.1 8443 <指纹>
cargo run -p sao-client --bin sao -- run 127.0.0.1 -- echo hello
```

执行过 **`make install`** 后，可直接使用 **`sao`** / **`sao-server`**，无需 `cargo run`。

## CLI（`sao`）

| 子命令 | 说明 |
|--------|------|
| `run [-p PORT] [--accept-new] HOST -- <cmd>...` | TLS + pin + 认证后远程 `bash -lc`（默认 **8443**）。新主机或 pin 不匹配时，TTY 上 **yes/no** 确认，或 **`--accept-new`** 自动保存/替换（不可信网络有 MITM 风险）。 |
| `trust probe HOST:PORT` | 打印服务端 SPKI 指纹（仅可信网络） |
| `trust add HOST PORT HEX64` | 写入 `~/.sao/known_hosts` |
| `key-fingerprint` | 生成/展示 Agent 密钥；写入 `~/.sao/keys/agent.ed25519.pub` — 将其非注释行追加到服务端 `authorized_keys` |

## 组件

| Crate | 作用 |
|-------|------|
| `sao-protocol` | 帧编解码（`FrameCodec`） |
| `sao-core` | YAML 配置、`known_hosts`、策略、`sao-ed25519` 认证与 SPKI 指纹 |
| `sao-server` | TLS（自签可自动生成）、会话、执行、审计日志 |
| `sao-client` | **native-tls** 握手后校验 SPKI pin，与协议一致 |
