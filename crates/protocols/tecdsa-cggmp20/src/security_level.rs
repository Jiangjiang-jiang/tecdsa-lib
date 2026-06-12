pub trait Cggmp20SecurityParams: Send + Sync + 'static {
    const RSA_PRIME_BITS: u32;
    const RSA_MODULUS_BITS: u32;
    const EPSILON: usize;
    const ELL: usize;
    const ELL_PRIME: usize;
    const KAPPA: usize;
}

#[derive(Debug, Clone, Copy)]
pub struct SecurityLevel128;

impl Cggmp20SecurityParams for SecurityLevel128 {
    const RSA_PRIME_BITS: u32 = 1536;
    const RSA_MODULUS_BITS: u32 = 3071;
    const EPSILON: usize = 512;
    const ELL: usize = 256;
    const ELL_PRIME: usize = 1280;
    const KAPPA: usize = 256;
}
