//! Config, known_hosts, authorized_keys, auth signing, policy (`docs/protocol.md`).

pub mod agent_key;
mod auth_message;
pub mod authorized_keys;
pub mod config;
mod error;
pub mod known_hosts;
pub mod policy;
pub mod spki;

pub use agent_key::{load_or_create_signing_key, sign_auth_message};
pub use auth_message::signing_bytes;
pub use authorized_keys::{
    find_key, load_authorized_keys, verify_ed25519_signature, AuthorizedKey, KEY_TYPE_ED25519,
};
pub use error::CoreError;
pub use policy::check_shell;

pub use sao_protocol::{
    msg_type, Frame, FrameCodec, ProtocolError, DEFAULT_MAX_PAYLOAD_LEN, HEADER_LEN, MAGIC, VERSION,
};
