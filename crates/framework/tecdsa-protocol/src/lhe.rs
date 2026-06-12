pub trait LheScheme: 'static {
    type Setup;

    type PublicKey;

    type SecretKey;

    type Ciphertext: Clone + Send;

    type Error: std::error::Error + Send + Sync;

    fn encrypt(
        setup: &mut Self::Setup,
        pk: &Self::PublicKey,
        plaintext: &str,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn decrypt(
        setup: &mut Self::Setup,
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<String, Self::Error>;

    fn homo_add(
        setup: &mut Self::Setup,
        c1: &Self::Ciphertext,
        c2: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext, Self::Error>;

    fn homo_scalar_mul(
        setup: &mut Self::Setup,
        scalar: &str,
        ct: &Self::Ciphertext,
    ) -> Result<Self::Ciphertext, Self::Error>;
}

pub mod he_mta {
    use super::LheScheme;

    pub struct AliceState<L: LheScheme> {
        pub a_decimal: String,
        pub ciphertext: L::Ciphertext,
    }

    pub struct BobOutput<L: LheScheme> {
        pub c_alpha: L::Ciphertext,
        pub beta_decimal: String,
    }

    pub fn alice_step1<L: LheScheme>(
        setup: &mut L::Setup,
        pk: &L::PublicKey,
        a_decimal: &str,
    ) -> Result<AliceState<L>, L::Error> {
        let ciphertext = L::encrypt(setup, pk, a_decimal)?;
        Ok(AliceState {
            a_decimal: a_decimal.to_string(),
            ciphertext,
        })
    }

    pub fn bob_step<L: LheScheme>(
        setup: &mut L::Setup,
        pk_alice: &L::PublicKey,
        c_a: &L::Ciphertext,
        b_decimal: &str,
        neg_beta_decimal: &str,
    ) -> Result<BobOutput<L>, L::Error> {
        let b_times_ca = L::homo_scalar_mul(setup, b_decimal, c_a)?;
        let enc_neg_beta = L::encrypt(setup, pk_alice, neg_beta_decimal)?;
        let c_alpha = L::homo_add(setup, &b_times_ca, &enc_neg_beta)?;

        Ok(BobOutput {
            c_alpha,
            beta_decimal: neg_beta_decimal.to_string(),
        })
    }

    pub fn alice_step2<L: LheScheme>(
        setup: &mut L::Setup,
        sk: &L::SecretKey,
        c_alpha: &L::Ciphertext,
    ) -> Result<String, L::Error> {
        L::decrypt(setup, sk, c_alpha)
    }
}
