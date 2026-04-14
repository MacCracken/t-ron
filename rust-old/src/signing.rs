//! Policy signature verification using sigil.
//!
//! Verifies Ed25519 signatures on policy files before loading them,
//! ensuring only trusted policy sources are accepted. Requires the
//! `signing` feature.

use crate::TRonError;
use ed25519_dalek::VerifyingKey;
use std::path::Path;

/// Verifier that holds trusted public keys for policy signature checking.
pub struct PolicyVerifier {
    trusted_keys: Vec<VerifyingKey>,
}

impl PolicyVerifier {
    /// Create a verifier with the given trusted public keys.
    #[must_use]
    pub fn new(trusted_keys: Vec<VerifyingKey>) -> Self {
        Self { trusted_keys }
    }

    /// Add a trusted public key.
    pub fn add_key(&mut self, key: VerifyingKey) {
        self.trusted_keys.push(key);
    }

    /// Number of trusted keys.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.trusted_keys.len()
    }

    /// Verify a policy file's detached signature and return the TOML content.
    ///
    /// Expects a signature file at `{path}.sig` alongside the policy file.
    /// Tries each trusted key — succeeds if any key validates the signature.
    pub fn verify_and_read(&self, path: &Path) -> Result<String, TRonError> {
        if self.trusted_keys.is_empty() {
            return Err(TRonError::Signature("no trusted keys configured".into()));
        }

        let content = std::fs::read(path)
            .map_err(|e| TRonError::Signature(format!("failed to read policy file: {e}")))?;

        let sig_path = path.with_extension("toml.sig");
        let signature = std::fs::read(&sig_path).map_err(|e| {
            TRonError::Signature(format!(
                "signature file '{}' not found: {e}",
                sig_path.display()
            ))
        })?;

        for key in &self.trusted_keys {
            if sigil::trust::verify_signature(&content, &signature, key).is_ok() {
                tracing::info!(
                    path = %path.display(),
                    "policy signature verified"
                );
                return String::from_utf8(content)
                    .map_err(|e| TRonError::Signature(format!("policy not valid UTF-8: {e}")));
            }
        }

        Err(TRonError::Signature(
            "policy signature verification failed: no trusted key matched".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_signed_policy(
        content: &[u8],
    ) -> (ed25519_dalek::SigningKey, VerifyingKey, Vec<u8>) {
        let (sk, vk, _kid) = sigil::trust::generate_keypair();
        let sig = sigil::trust::sign_data(content, &sk);
        (sk, vk, sig)
    }

    #[test]
    fn verify_valid_signature() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.toml");
        let sig_path = dir.path().join("policy.toml.sig");

        let content = b"[agent.\"test\"]\nallow = [\"*\"]\n";
        std::fs::write(&policy_path, content).unwrap();

        let (_sk, vk, sig) = generate_signed_policy(content);
        std::fs::write(&sig_path, &sig).unwrap();

        let verifier = PolicyVerifier::new(vec![vk]);
        let result = verifier.verify_and_read(&policy_path);
        assert!(result.is_ok());
        assert!(result.unwrap().contains("[agent.\"test\"]"));
    }

    #[test]
    fn reject_tampered_content() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.toml");
        let sig_path = dir.path().join("policy.toml.sig");

        let original = b"[agent.\"test\"]\nallow = [\"*\"]\n";
        let (_sk, vk, sig) = generate_signed_policy(original);

        // Write tampered content but original signature
        std::fs::write(&policy_path, b"[agent.\"evil\"]\nallow = [\"*\"]\n").unwrap();
        std::fs::write(&sig_path, &sig).unwrap();

        let verifier = PolicyVerifier::new(vec![vk]);
        assert!(verifier.verify_and_read(&policy_path).is_err());
    }

    #[test]
    fn reject_unknown_key() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.toml");
        let sig_path = dir.path().join("policy.toml.sig");

        let content = b"[agent.\"test\"]\nallow = [\"*\"]\n";
        std::fs::write(&policy_path, content).unwrap();

        // Sign with one keypair
        let (_sk, _vk, sig) = generate_signed_policy(content);
        std::fs::write(&sig_path, &sig).unwrap();

        // Verify with a different keypair
        let (_sk2, vk2, _kid2) = sigil::trust::generate_keypair();
        let verifier = PolicyVerifier::new(vec![vk2]);
        assert!(verifier.verify_and_read(&policy_path).is_err());
    }

    #[test]
    fn reject_missing_signature_file() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.toml");
        std::fs::write(&policy_path, b"content").unwrap();
        // No .sig file

        let (_sk, vk, _kid) = sigil::trust::generate_keypair();
        let verifier = PolicyVerifier::new(vec![vk]);
        let err = verifier.verify_and_read(&policy_path).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn reject_no_trusted_keys() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.toml");
        std::fs::write(&policy_path, b"content").unwrap();

        let verifier = PolicyVerifier::new(vec![]);
        let err = verifier.verify_and_read(&policy_path).unwrap_err();
        assert!(err.to_string().contains("no trusted keys"));
    }
}
