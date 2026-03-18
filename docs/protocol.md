# sao wire protocol

This document specifies **messages and flows between agents and sao-server**. **Policy tables, deny-list entries, audit field toggles, and numeric limits are supplied by deployment configuration**—not defined here. This spec only requires **policy evaluation before execution**, the **shape of rejections and audit events**, and **`authorized_keys` line syntax** (OpenSSH-style lines, not business policy).

**Version**: this document corresponds to wire **`version` field `0x01`** (see §3).

---

## 1. Goals and non-goals

| In scope | Out of scope (config / ops) |
|----------|-----------------------------|
| Encrypted transport, server identity (TLS + pin or CA) | Concrete deny regexes, path allow lists |
| Agent public-key auth (challenge–response) | Audit to file vs journald only |
| Frame semantics for shell-like execution | `sao` user ulimit, cgroup |
| Frame types for policy denial and exec output | Concrete `policy_group` and YAML field names |

---

## 2. Transport

### 2.1 Default: TLS

- After connect, **TLS handshake must complete** before any frame in §3 is sent.
- **Server certificate**: self-signed or enterprise-CA; paths from config (recommended **`/etc/sao/tls/`**).
- **Client trust** (pick one; implementations should document precedence; **pin before CA** is recommended):
  1. **Public-key pin** (default): `~/.sao/known_hosts` maps `host` + `port` → server cert **SPKI SHA-256** (hex or Base64URL—implementations must pick one and print/store consistently on first trust).
  2. **CA validation**: trust a CA bundle or system roots for enterprise-issued server certs.

**`known_hosts` file format (this implementation)**  
One record per line, whitespace-separated: `host port spki_sha256_hex`. **`host`**: lowercase hostname or literal IP; **`port`**: decimal; **`spki_sha256_hex`**: **64 lowercase hex chars**, SHA-256 over the cert **SubjectPublicKeyInfo** DER. Lines starting with `#` are comments; blank lines ignored. For IPv6, CLI addresses may use `[addr]:port`; the stored `host` may be unbracketed—stay consistent within an implementation.

### 2.2 Optional: plaintext TCP (development only)

- Only when the client **explicitly** enables insecure mode **and** the server config allows it may frames be sent on **non-TLS** TCP.
- **Must not** be the production default; implementations must flag this in docs.

---

## 3. Frame format

All messages are **fixed header + variable body**, **big-endian**, sent consecutively on TLS application data (or plaintext TCP).

| Offset | Length | Field | Description |
|--------|--------|-------|-------------|
| 0 | 3 | `magic` | ASCII `S` `A` `O` (0x53 0x41 0x4F) |
| 3 | 1 | `version` | Protocol version; current **`0x01`** |
| 4 | 1 | `msg_type` | Message type (§4) |
| 5 | 4 | `payload_len` | `uint32_be`, payload byte length |
| 9 | `payload_len` | `payload` | **UTF-8 JSON object** unless noted |

**Constraints**:

- **`payload_len`** must not exceed the implementation **max frame size** (recommended default **1 MiB**, configurable); oversize **must** be rejected or answered with `Error`.
- Unknown **`version`**: **must** reject or return `Error`; no silent downgrade.
- Unknown **`msg_type`**: return `Error` (code §4.3).

---

## 4. Message types and payloads

### 4.1 Authentication (after TLS)

| `msg_type` | Name | Direction | Description |
|------------|------|-----------|-------------|
| `0x01` | `AuthChallenge` | S→C | Server challenge |
| `0x02` | `AuthResponse` | C→S | Client signature |
| `0x03` | `AuthResult` | S→C | Success or failure |

**`AuthChallenge` payload (JSON)**:

```json
{
  "nonce": "<base64>",
  "session_id": "<string>"
}
```

- **`nonce`**: CSPRNG bytes, recommend **≥ 32 bytes**, **unique per connection**.
- **`session_id`**: server session id for audit correlation.

**Bytes to sign (normative)**  

The client **must** sign this exact byte sequence (then encode per algorithm in `signature`):

```text
UTF-8("sao-auth-v1\0") || nonce_raw_bytes || UTF-8(session_id)
```

(`\0` is a single zero byte.) Binds protocol version and session to reduce cross-protocol / cross-session misuse.

**`AuthResponse` payload (JSON)**:

```json
{
  "key_type": "sao-ed25519",
  "fingerprint": "<string>",
  "signature": "<base64>"
}
```

- **`key_type`**: matches first column of `authorized_keys` (§5).
- **`fingerprint`**: locates the key line (implementation-defined; register algorithm in §5.1).
- **`signature`**: signature over §4.1 bytes, raw sig then Base64.

**`AuthResult` payload (JSON)**:

Success:

```json
{
  "ok": true,
  "agent_name": "<optional from keys line>",
  "policy_group": "<string from config mapping>"
}
```

Failure:

```json
{
  "ok": false,
  "reason": "<machine-readable code>",
  "message": "<human-readable>"
}
```

On auth failure the connection **must** be closed.

**Flow**: C connects → S `AuthChallenge` → C `AuthResponse` → S verifies + checks `authorized_keys` → S `AuthResult`; only after `ok: true` may C send execution messages.

---

### 4.2 Execution (after successful auth)

The server **must** evaluate **currently loaded config** policy (including deny rules) **before** starting a child process. If denied, **no child** is started; send `PolicyDenied` and **must** emit an audit event (§6).

| `msg_type` | Name | Direction | Description |
|------------|------|-----------|-------------|
| `0x10` | `ExecShell` | C→S | Request one shell line |
| `0x11` | `StreamStdout` | S→C | stdout chunk |
| `0x12` | `StreamStderr` | S→C | stderr chunk |
| `0x13` | `ExecExit` | S→C | Child exit |
| `0x20` | `PolicyDenied` | S→C | Policy rejection |
| `0xFF` | `Error` | Both | Generic error |

**`ExecShell` payload**:

```json
{
  "shell": "<string>"
}
```

- Server passes **`shell`** to the configured interpreter (e.g. **`bash -lc`**) as the **`sao` (or configured) user**; cwd, env, timeout, limits are **config-only**, not specified here.

**`StreamStdout` / `StreamStderr` payload**:

```json
{
  "data": "<base64>"
}
```

**`ExecExit` payload**:

```json
{
  "exit_code": <integer>,
  "signal": null
}
```

Signal termination may use `exit_code` + `signal`; document in implementation notes.

**`PolicyDenied` payload**:

```json
{
  "code": "POLICY_DENIED",
  "rule_id": "<optional string from config>",
  "message": "<string>"
}
```

**`Error` payload**:

```json
{
  "code": "<string>",
  "message": "<string>"
}
```

---

## 5. `authorized_keys` (agent public keys)

Path from config (e.g. `/etc/sao/authorized_keys`). **One line per key**, same layout as **`~/.ssh/authorized_keys`**:

```text
<sao-key-type> <public_key_base64> [<name ...>]
```

- **sao-key-type**: `sao-<algorithm>`, extensible; implementations **must** support types listed in §5.1; unknown types may be skipped or errored (config-defined).
- **public_key_base64**: encoding per §5.1.
- **name**: optional; **columns after the second to EOL** are comment (may contain spaces); **`policy_group`** is mapped from config by **name** or **fingerprint**, **not** on this line.

Lines starting with `#` are comments; empty lines ignored.

### 5.1 Registered algorithms (initial)

| key_type | Public key Base64 meaning | Signature |
|----------|---------------------------|-----------|
| `sao-ed25519` | 32-byte raw Ed25519 public key, Base64 | Ed25519 over §4.1 bytes |
| `sao-rsa` | PKCS#1 SubjectPublicKeyInfo (RSA) DER, Base64 | RSASSA-PKCS1-v1_5 or PSS (pick one per release and document) |

New algorithms: register **`key_type`**, encoding, and signature field in this table and in release notes.

**fingerprint**: e.g. SHA-256 hex of pubkey material; **`AuthResponse.fingerprint` and `authorized_keys` lookup must match** within an implementation.

---

## 6. Audit (semantic requirements)

The protocol does **not** mandate log file paths; compliant implementations **must** emit **structured logs** (recommended **stderr / journald**) with at least these **logical fields** (names may map to JSON keys):

| Event | Suggested fields |
|-------|------------------|
| Auth success/failure | `session_id`, `key_type`, `fingerprint` or `agent_name`, `ok`, `reason` |
| Policy denial | `session_id`, `rule_id`, `exec_preview` or hash—**no full secrets** |
| Exec start/end | `session_id`, `exit_code`, command digest (hash or truncation) |

Whether to log **full shell lines** is **config**. Field toggles, sampling, retention—all **config**.

---

## 7. Compliance checklist (summary)

1. TLS by default; plaintext only explicit insecure.  
2. Auth order: `AuthChallenge` → `AuthResponse` → `AuthResult`; signature covers §4.1 bytes.  
3. **Every** `ExecShell` **preceded** by configured policy; on deny: `PolicyDenied` + audit.  
4. Child runs as **`sao`** (or configured low-privilege user).  
5. Frame size cap; unknown version/type → error handling.  
6. **Policy and deny-list content come only from config.**

---

## 8. Reference flow

```text
Client                          Server
   |---- TLS ---------------------->|
   |<---- AuthChallenge ------------|
   |----- AuthResponse ------------>|
   |<---- AuthResult (ok) ----------|
   |----- ExecShell -------------->|
   |     (policy pass → bash -lc)   |
   |<---- StreamStdout/Stderr ------|
   |<---- ExecExit -----------------|
```

---

*On incompatible changes: bump wire `version` or document a new port; maintain a changelog at the top of this file.*
