use serde::{Deserialize, Serialize};

use crate::types::hashing::hasher;

#[derive(Debug, Serialize, Deserialize)]
pub struct Header<H: hasher::Hasher> {
    pub previous_block_hash: H::Out,
    pub tx_hash: H::Out,
    pub version: u32,
    pub height: u32,
    pub timestamp: u32,

    pub nonce: u32,
    pub difficulty: u8,
}

impl<H: hasher::Hasher> Header<H> {
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization failed")
    }
}
