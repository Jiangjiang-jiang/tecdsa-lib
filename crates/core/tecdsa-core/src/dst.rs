// SPDX-License-Identifier: MIT OR Apache-2.0
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dst(&'static [u8]);

impl Dst {
    #[must_use]
    pub const fn new(tag: &'static [u8]) -> Self {
        Self(tag)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}
