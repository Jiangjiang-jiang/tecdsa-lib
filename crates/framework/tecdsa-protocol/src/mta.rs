use rand_core::CryptoRngCore;

pub struct MtaShares {
    pub alpha: Vec<u8>,
    pub beta: Vec<u8>,
}

pub trait MtA: Sized + 'static {
    type Setup: Clone;

    type SenderState;

    type SenderMsg;

    type ReceiverMsg;

    type Error: core::fmt::Debug + core::fmt::Display;

    fn sender_encrypt(
        setup: &Self::Setup,
        b_bytes: &[u8],
        q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SenderMsg, Self::SenderState), Self::Error>;

    fn receiver_compute(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>), Self::Error>;

    fn sender_decrypt(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        receiver_msg: &Self::ReceiverMsg,
    ) -> Result<Vec<u8>, Self::Error>;
}

pub trait MtAWithCheck: MtA {
    type CheckProof;

    #[allow(clippy::type_complexity)]
    fn receiver_compute_with_check(
        setup: &Self::Setup,
        a_bytes: &[u8],
        q_bytes: &[u8],
        sender_msg: &Self::SenderMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ReceiverMsg, Vec<u8>, Self::CheckProof), Self::Error>;

    fn verify_check(
        setup: &Self::Setup,
        state: &Self::SenderState,
        q_bytes: &[u8],
        beta_bytes: &[u8],
        check_proof: &Self::CheckProof,
        aux_bytes: &[u8],
    ) -> Result<bool, Self::Error>;
}

pub trait MtAInteractive: Sized + 'static {
    type Setup: Clone;
    type SenderState;
    type ReceiverState;
    type InitMsg;
    type ResponseMsg;
    type ComputeMsg;
    type Error: core::fmt::Debug + core::fmt::Display;

    fn sender_init(
        setup: &Self::Setup,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::InitMsg, Self::SenderState), Self::Error>;

    fn receiver_respond(
        setup: &Self::Setup,
        b_bytes: &[u8],
        q_bytes: &[u8],
        init_msg: &Self::InitMsg,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ResponseMsg, Self::ReceiverState), Self::Error>;

    fn sender_compute(
        state: Self::SenderState,
        a_bytes: &[u8],
        q_bytes: &[u8],
        response_msg: &Self::ResponseMsg,
    ) -> Result<(Self::ComputeMsg, Vec<u8>), Self::Error>;

    fn receiver_finish(
        state: Self::ReceiverState,
        compute_msg: &Self::ComputeMsg,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

pub trait MtABroadcast: Sized + 'static {
    type Setup: Clone;
    type Encoding: Clone;
    type State;
    type Error: core::fmt::Debug + core::fmt::Display;

    fn encode(
        setup: &Self::Setup,
        input_bytes: &[u8],
        q_bytes: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Encoding, Self::State), Self::Error>;

    fn decode(
        setup: &Self::Setup,
        other_encoding: &Self::Encoding,
        my_state: &Self::State,
        q_bytes: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}
