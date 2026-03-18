//! [`FrameCodec`] over any async byte stream (TLS, TCP, in-memory duplex).

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::frame::DEFAULT_MAX_PAYLOAD_LEN;
use crate::frame::{parse_header, write_header, Frame, HEADER_LEN};
use crate::ProtocolError;
use crate::VERSION;

/// Async SAO frame reader/writer.
///
/// Works on `tokio::net::TcpStream`, `tokio_rustls` TLS streams, or `tokio::io::duplex` for tests.
pub struct FrameCodec<S> {
    inner: S,
    max_payload_len: u32,
}

impl<S> FrameCodec<S> {
    /// New codec with default max payload ([`DEFAULT_MAX_PAYLOAD_LEN`]).
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            max_payload_len: DEFAULT_MAX_PAYLOAD_LEN,
        }
    }

    /// New codec with a custom maximum payload length (bytes).
    pub fn with_max_payload_len(inner: S, max_payload_len: u32) -> Self {
        Self {
            inner,
            max_payload_len,
        }
    }

    pub fn max_payload_len(&self) -> u32 {
        self.max_payload_len
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> FrameCodec<S> {
    /// Read one full frame. Validates magic, version, and payload bounds.
    pub async fn read_frame(&mut self) -> Result<Frame, ProtocolError> {
        let mut hdr = [0u8; HEADER_LEN];
        self.inner
            .read_exact(&mut hdr)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => ProtocolError::UnexpectedEof,
                _ => ProtocolError::Io(e),
            })?;
        let (_version, msg_type, payload_len) = parse_header(&hdr)?;
        if payload_len > self.max_payload_len {
            return Err(ProtocolError::PayloadTooLarge {
                len: payload_len,
                max: self.max_payload_len,
            });
        }
        let len = usize::try_from(payload_len)
            .map_err(|_| ProtocolError::PayloadLengthOverflow { len: payload_len })?;
        let mut payload = vec![0u8; len];
        if len > 0 {
            self.inner
                .read_exact(&mut payload)
                .await
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::UnexpectedEof => ProtocolError::UnexpectedEof,
                    _ => ProtocolError::Io(e),
                })?;
        }
        Ok(Frame { msg_type, payload })
    }
}

impl<S: AsyncWrite + Unpin> FrameCodec<S> {
    /// Write one frame (`version` = [`VERSION`]).
    pub async fn write_frame(&mut self, msg_type: u8, payload: &[u8]) -> Result<(), ProtocolError> {
        let len_u32 = u32::try_from(payload.len()).map_err(|_| ProtocolError::PayloadTooLarge {
            len: u32::MAX,
            max: self.max_payload_len,
        })?;
        if len_u32 > self.max_payload_len {
            return Err(ProtocolError::PayloadTooLarge {
                len: len_u32,
                max: self.max_payload_len,
            });
        }
        let mut hdr = [0u8; HEADER_LEN];
        write_header(&mut hdr, VERSION, msg_type, len_u32);
        self.inner.write_all(&hdr).await?;
        self.inner.write_all(payload).await?;
        self.inner.flush().await?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> FrameCodec<S> {
    pub async fn write_frame_read_frame(
        &mut self,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<Frame, ProtocolError> {
        self.write_frame(msg_type, payload).await?;
        self.read_frame().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg_type;

    #[tokio::test]
    async fn roundtrip_over_duplex() {
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut ca = FrameCodec::new(a);
        let mut cb = FrameCodec::new(b);
        let body = br#"{"nonce":"eA==","session_id":"s1"}"#;
        ca.write_frame(msg_type::AUTH_CHALLENGE, body)
            .await
            .unwrap();
        let f = cb.read_frame().await.unwrap();
        assert_eq!(f.msg_type, msg_type::AUTH_CHALLENGE);
        assert_eq!(f.payload, body);
    }

    #[tokio::test]
    async fn payload_too_large_rejected_on_read() {
        let (a, b) = tokio::io::duplex(1024);
        let mut ca = FrameCodec::with_max_payload_len(a, 10);
        let mut cb = FrameCodec::with_max_payload_len(b, 10);
        // 11 bytes payload — allowed on wire by writer if we bypass check; writer enforces max.
        // So we write raw bytes to simulate peer sending huge length.
        let mut hdr = [0u8; HEADER_LEN];
        write_header(&mut hdr, VERSION, msg_type::ERROR, 11);
        use tokio::io::AsyncWriteExt;
        ca.get_mut().write_all(&hdr).await.unwrap();
        ca.get_mut().write_all(&[0u8; 11]).await.unwrap();
        ca.get_mut().flush().await.unwrap();
        let err = cb.read_frame().await.unwrap_err();
        match err {
            ProtocolError::PayloadTooLarge { len: 11, max: 10 } => {}
            e => panic!("expected PayloadTooLarge, got {e:?}"),
        }
    }

    #[tokio::test]
    async fn bad_magic_fails() {
        let (a, b) = tokio::io::duplex(256);
        let mut ca = FrameCodec::new(a);
        let mut cb = FrameCodec::new(b);
        ca.get_mut().write_all(b"XXX").await.unwrap();
        ca.get_mut()
            .write_all(&[VERSION, 1, 0, 0, 0, 0])
            .await
            .unwrap();
        let err = cb.read_frame().await.unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidMagic));
    }

    #[tokio::test]
    async fn wrong_version_fails() {
        let (a, b) = tokio::io::duplex(256);
        let mut ca = FrameCodec::new(a);
        let mut cb = FrameCodec::new(b);
        let mut hdr = [0u8; HEADER_LEN];
        write_header(&mut hdr, 0xFF, msg_type::ERROR, 0);
        ca.get_mut().write_all(&hdr).await.unwrap();
        let err = cb.read_frame().await.unwrap_err();
        assert!(matches!(
            err,
            ProtocolError::UnsupportedVersion { got: 0xFF }
        ));
    }
}
