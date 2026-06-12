pub trait TranscriptProtocol {
    fn append_message(&mut self, label: &'static [u8], message: &[u8]);

    fn challenge_bytes(&mut self, label: &'static [u8], len: usize) -> Vec<u8>;
}

pub struct MerlinTranscript(merlin::Transcript);

impl MerlinTranscript {
    #[must_use]
    pub fn new(domain: &'static [u8]) -> Self {
        Self(merlin::Transcript::new(domain))
    }

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
