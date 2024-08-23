use super::hasher;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub type SHA256Hash = [u8; 32];

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SHA256;

impl hasher::Hasher for SHA256 {
    type Out = SHA256Hash;

    const LENGTH: usize = 32;

    fn hash(x: &[u8]) -> Self::Out {
        let mut hasher = Sha256::new();
        hasher.update(x);
        let digest = hasher.finalize();

        digest.into()
    }
}
