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

## 构建与安装

**Release 编译并安装到 `$(PREFIX)/bin`（默认 `/usr/local/bin`，常需 `sudo`）：**

```bash
make install
# 或用户目录：make install PREFIX="$HOME/.local"
```

| 目标 | 说明 |
|------|------|
| `make` / `make release` | `cargo build --release`（sao + sao-server） |
| `make install` | 安装 `sao`、`sao-server` |
| `make uninstall` | 移除上述二进制 |
| `make check` | `fmt` + `clippy -D warnings` + `test` |

开发调试仍可用 `cargo build --workspace` 等。

**MSRV**：建议 **Rust 1.87+**；`sao-core` 固定 `time = 0.3.36` 以兼容低于 1.88 的工具链。

**systemd**：见 **deploy/systemd/sao-server.service**；首次信任与 pin 见下文「快速本地试跑」与 **`docs/protocol.md`**。

## 快速本地试跑

```bash
cp examples/config.yaml ./config.yaml
# 编辑 authorized_keys：先运行
cargo run -p sao-client --bin sao -- key-fingerprint
# 将输出的 sao-ed25519 行写入 ./authorized_keys
cargo run -p sao-server -- --config config.yaml
# 另终端：信任 SPKI（用服务端打印的指纹或 trust probe）
cargo run -p sao-client --bin sao -- trust add 127.0.0.1 8443 <指纹>
cargo run -p sao-client --bin sao -- run 127.0.0.1:8443 -- echo hello
```

执行过 **`make install`** 后，可直接使用 **`sao`** / **`sao-server`**，无需 `cargo run`。

## CLI（`sao`）

| 子命令 | 说明 |
|--------|------|
| `run HOST:PORT -- <cmd>...` | TLS + pin + 认证后远程 `bash -lc` |
| `trust probe HOST:PORT` | 打印服务端 SPKI 指纹（仅可信网络） |
| `trust add HOST PORT HEX64` | 写入 `~/.sao/known_hosts` |
| `key-fingerprint` | 生成/展示 Agent 公钥与 `authorized_keys` 行 |

## 组件

| Crate | 作用 |
|-------|------|
| `sao-protocol` | 帧编解码（`FrameCodec`） |
| `sao-core` | YAML 配置、`known_hosts`、策略、`sao-ed25519` 认证与 SPKI 指纹 |
| `sao-server` | TLS（自签可自动生成）、会话、执行、审计日志 |
| `sao-client` | **native-tls** 握手后校验 SPKI pin，与协议一致 |
