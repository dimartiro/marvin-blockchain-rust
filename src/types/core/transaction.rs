use crate::{
    crypto::keys::{PublicKey, SignatureWrapper},
    types::hashing::hasher::{self, Hasher},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Transaction<H: hasher::Hasher> {
    pub from: Option<PublicKey>,
    pub to: Option<PublicKey>,
    pub value: u64,
    pub data: Vec<u8>,
    pub signature: Option<SignatureWrapper>,
    pub nonce: u64, // What are we want to achieve with tx nonce?

    // Cached version of the transaction hash
    pub hash: Option<H::Out>,
}

impl<H: Hasher> Transaction<H> {
    pub fn new(data: Vec<u8>) -> Self {
        Transaction {
            data,
            nonce: rand::random::<u64>(),
            from: Default::default(),
            to: Default::default(),
            value: Default::default(),
            signature: Default::default(),
            hash: Default::default(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Serialization failed")
    }

    /// Calculate the hash of the transaction
    pub fn hash(&self) -> Option<H::Out> {
        if let Some(hash) = &self.hash {
            return Some(hash.clone());
        }

        let bytes = self.to_bytes();
        Some(H::hash(&bytes))
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }

    pub fn decode(data: &[u8]) -> Self {
        bincode::deserialize::<Transaction<H>>(data).unwrap()
    }
}
