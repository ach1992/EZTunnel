//! Official update-file verification only. Never gates startup or peer sessions.
use ed25519_dalek::{Signature, VerifyingKey};

/// This fork fetches only its own published releases, not upstream binaries.
pub const REPOSITORY: &str = "ach1992/EZTunnel";
pub const TRAILER_LEN: usize = 72;
const MAGIC: &[u8; 4] = b"EZT1";
/// The fork's release signing key is embedded by the official build workflow.
/// Developer builds without this variable cannot accept release updates, by design.
/// The upstream maintainer's key is not trusted by this distribution.
const FORK_KEY_ID: u8 = 1;
const FORK_PUBLIC_KEY: Option<&str> = option_env!("EZTUNNEL_RELEASE_PUBLIC_KEY_HEX");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Verified,
    Unsigned,
    Invalid,
}

pub fn verify_bytes(bytes: &[u8]) -> Outcome {
    #[cfg(test)]
    if let Some(public) = TEST_KEY.with(|key| *key.borrow()) {
        return verify_with(bytes, |id| (id == 239).then_some(public));
    }
    verify_with(bytes, |id| (id == FORK_KEY_ID)
        .then_some(FORK_PUBLIC_KEY).flatten()
        .and_then(|text| hex::decode(text).ok()?.try_into().ok()))
}

#[cfg(test)]
thread_local! {
    static TEST_KEY: std::cell::RefCell<Option<[u8; 32]>> = const { std::cell::RefCell::new(None) };
}

/// Test-only fixture authority scoped to this thread, with restoration on panic.
#[cfg(test)]
pub(crate) fn with_fixture_authority<T>(public: [u8; 32], run: impl FnOnce() -> T) -> T {
    struct Restore(Option<[u8; 32]>);
    impl Drop for Restore {
        fn drop(&mut self) { TEST_KEY.with(|key| *key.borrow_mut() = self.0); }
    }
    let previous = TEST_KEY.with(|key| key.replace(Some(public)));
    let _restore = Restore(previous);
    run()
}

fn verify_with(bytes: &[u8], key: impl FnOnce(u8) -> Option<[u8; 32]>) -> Outcome {
    let Some(body_len) = bytes.len().checked_sub(TRAILER_LEN) else { return Outcome::Unsigned; };
    let (body, trailer) = bytes.split_at(body_len);
    if &trailer[..4] != MAGIC { return Outcome::Unsigned; }
    if trailer[69..] != [0; 3] { return Outcome::Invalid; }
    let Some(public) = key(trailer[4]).and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok()) else { return Outcome::Invalid; };
    let signature = Signature::from_bytes(trailer[5..69].try_into().expect("trailer length checked"));
    if public.verify_strict(blake3::hash(body).as_bytes(), &signature).is_ok() {
        Outcome::Verified
    } else {
        Outcome::Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn exact_candidate_signature_requires_body_key_id_and_canonical_trailer() {
        // Public deterministic fixture authority, unrelated to any production key.
        let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
        let mut bytes = b"dummy release body".to_vec();
        let signature = key.sign(blake3::hash(&bytes).as_bytes());
        bytes.extend_from_slice(MAGIC);
        bytes.push(7);
        bytes.extend_from_slice(&signature.to_bytes());
        bytes.extend_from_slice(&[0; 3]);
        let check = |bytes: &[u8]| verify_with(bytes, |id| (id == 7).then_some(key.verifying_key().to_bytes()));
        assert_eq!(check(&bytes), Outcome::Verified);
        assert_eq!(verify_bytes(&bytes), Outcome::Invalid);
        for position in [0, bytes.len() - 68, bytes.len() - 5, bytes.len() - 1] {
            let mut changed = bytes.clone();
            changed[position] ^= 1;
            assert_eq!(check(&changed), Outcome::Invalid);
        }
        assert_eq!(check(b"unsigned custom executable"), Outcome::Unsigned);
        bytes.push(0);
        assert_ne!(check(&bytes), Outcome::Verified);
    }
}
