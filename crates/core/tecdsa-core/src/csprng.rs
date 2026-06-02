// SPDX-License-Identifier: MIT OR Apache-2.0
use rand_core::{CryptoRng, OsRng, RngCore};

pub struct Csprng(OsRng);

impl Csprng {
    #[must_use]
    pub fn new() -> Self {
        Self(OsRng)
    }
}

impl Default for Csprng {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for Csprng {
    type Target = OsRng;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Csprng {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl RngCore for Csprng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for Csprng {}
