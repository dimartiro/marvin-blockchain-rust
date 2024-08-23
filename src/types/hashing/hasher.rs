use core::hash;

use serde::{Deserialize, Serialize};

pub trait Hasher {
    type Out: AsRef<[u8]>
        + Default
        + core::cmp::Ord
        + PartialEq
        + Eq
        + hash::Hash
        + Clone
        + Copy
        + for<'a> Deserialize<'a>
        + Serialize;
    const LENGTH: usize;

    fn hash(x: &[u8]) -> Self::Out;
}
