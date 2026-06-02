// SPDX-License-Identifier: MIT OR Apache-2.0
/// Abstraction over transcript primitives for Fiat-Shamir transforms.
pub trait TranscriptProtocol {
    /// Append a labeled message to the transcript.
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);

    /// Squeeze a challenge of `len` bytes from the transcript.
    fn challenge_bytes(&mut self, label: &'static [u8], len: usize) -> Vec<u8>;
}

/// A Merlin (STROBE-based) transcript.
pub struct MerlinTranscript(merlin::Transcript);

impl MerlinTranscript {
    /// Create a new transcript with the given domain label.
    ///
    /// `merlin::Transcript::new` requires a `&'static [u8]` label, so callers
    /// that want a runtime domain must use [`MerlinTranscript::new_dynamic`].
    #[must_use]
    pub fn new(domain: &'static [u8]) -> Self {
        Self(merlin::Transcript::new(domain))
    }

    /// Create a new transcript absorbing an arbitrary runtime domain via an
    /// initial `append_message` call rather than as the static label.
    #[must_use]
    pub fn new_dynamic(domain: &[u8]) -> Self {
        let mut t = Self(merlin::Transcript::new(b"tecdsa-fs"));
        t.0.append_message(b"domain", domain);
        t
    }
}

impl TranscriptProtocol for MerlinTranscript {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
        self.0.append_message(label, message);
    }

    fn challenge_bytes(&mut self, label: &'static [u8], len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        self.0.challenge_bytes(label, &mut buf);
        buf
    }
}
