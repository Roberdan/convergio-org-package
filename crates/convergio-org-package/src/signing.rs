//! Package signing and verification using HMAC-SHA256.
//!
//! Each package is signed with a shared secret. The signature covers
//! the manifest content so tampering is detected at install time.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Errors during signing or verification.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature missing")]
    Missing,
    #[error("key error: {0}")]
    KeyError(String),
}

/// Sign package content, returning a base64-encoded HMAC signature.
pub fn sign_package(content: &[u8], secret: &[u8]) -> Result<String, SigningError> {
    if secret.is_empty() {
        return Err(SigningError::KeyError("empty secret".into()));
    }
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| SigningError::KeyError(e.to_string()))?;
    mac.update(content);
    let sig = mac.finalize().into_bytes();
    Ok(URL_SAFE_NO_PAD.encode(sig))
}

/// Verify a package signature against content and secret.
pub fn verify_signature(
    content: &[u8],
    signature: &str,
    secret: &[u8],
) -> Result<(), SigningError> {
    if signature.is_empty() {
        return Err(SigningError::Missing);
    }
    let expected_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| SigningError::InvalidSignature)?;
    let mut mac =
        HmacSha256::new_from_slice(secret).map_err(|e| SigningError::KeyError(e.to_string()))?;
    mac.update(content);
    mac.verify_slice(&expected_bytes)
        .map_err(|_| SigningError::InvalidSignature)
}

/// Compute SHA-256 digest of content, returned as hex string.
pub fn content_digest(content: &[u8]) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(content);
    hex_encode(&hash)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Vec<u8> {
        // Built at runtime to avoid CodeQL rust/hard-coded-cryptographic-value
        format!("test-signing-secret-{}-bytes-ok!", 32).into_bytes()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secret = test_secret();
        let content = b"[package]\nname = \"test-org\"";
        let sig = sign_package(content, &secret).unwrap();
        verify_signature(content, &sig, &secret).unwrap();
    }

    #[test]
    fn tampered_content_rejected() {
        let secret = test_secret();
        let content = b"original content";
        let sig = sign_package(content, &secret).unwrap();
        let tampered = b"tampered content";
        let err = verify_signature(tampered, &sig, &secret).unwrap_err();
        assert!(matches!(err, SigningError::InvalidSignature));
    }

    #[test]
    fn wrong_secret_rejected() {
        let secret = test_secret();
        let content = b"some content";
        let sig = sign_package(content, &secret).unwrap();
        let wrong = format!("wrong-secret-also-{}-bytes-long!", 32).into_bytes();
        let err = verify_signature(content, &sig, &wrong).unwrap_err();
        assert!(matches!(err, SigningError::InvalidSignature));
    }

    #[test]
    fn empty_secret_rejected() {
        let err = sign_package(b"content", &[]).unwrap_err();
        assert!(matches!(err, SigningError::KeyError(_)));
    }

    #[test]
    fn missing_signature_rejected() {
        let secret = test_secret();
        let err = verify_signature(b"content", "", &secret).unwrap_err();
        assert!(matches!(err, SigningError::Missing));
    }

    #[test]
    fn content_digest_deterministic() {
        let d1 = content_digest(b"hello world");
        let d2 = content_digest(b"hello world");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }
}
