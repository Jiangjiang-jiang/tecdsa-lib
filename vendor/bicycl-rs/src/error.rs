use thiserror::Error;

/// All errors that can be returned by this crate.
///
/// The variants fall into two categories:
/// - **Rust-side conversion errors** (`NulByte`, `Utf8`): problems converting
///   data before or after FFI calls.
/// - **C library status codes** (all other variants): direct mappings of the
///   `bicycl_status_t` enum returned by the C API.
/// - **`Unknown`**: a status code not recognised by this version of the crate.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    #[error("NUL byte in input string")]
    NulByte(#[from] std::ffi::NulError),

    #[error("UTF-8 error in FFI response")]
    Utf8(#[from] std::str::Utf8Error),

    /// The C library returned `BICYCL_ERR_NULL_PTR`, meaning the **caller**
    /// passed a null pointer into the C API.  This should not occur under
    /// normal use of the safe Rust wrappers.
    #[error("BICYCL null pointer")]
    NullPtr,

    #[error("BICYCL invalid argument")]
    InvalidArgument,

    #[error("BICYCL allocation failed")]
    AllocationFailed,

    #[error("BICYCL internal error")]
    Internal,

    #[error("BICYCL output buffer too small")]
    BufferTooSmall,

    #[error("BICYCL parse error")]
    Parse,

    #[error("BICYCL invalid protocol state")]
    InvalidState,

    #[error("BICYCL verification failed")]
    VerifyFailed,

    #[error("BICYCL protocol aborted")]
    ProtocolAbort,

    #[error("BICYCL core math/runtime module error")]
    Core,

    #[error("BICYCL Paillier module error")]
    Paillier,

    #[error("BICYCL Joye-Libert module error")]
    JoyeLibert,

    #[error("BICYCL CL_HSMqk module error")]
    ClHsmqk,

    #[error("BICYCL CL_HSM2k module error")]
    ClHsm2k,

    #[error("BICYCL ECDSA module error")]
    Ecdsa,

    #[error("BICYCL TwoPartyECDSA module error")]
    TwoPartyEcdsa,

    #[error("BICYCL CL threshold module error")]
    ClThreshold,

    #[error("BICYCL CL DLog proof module error")]
    ClDlog,

    #[error("BICYCL threshold ECDSA module error")]
    ThresholdEcdsa,

    #[error("unknown BICYCL error code: {0}")]
    Unknown(i32),
}

pub type Result<T> = core::result::Result<T, Error>;

impl Error {
    pub(crate) fn from_status(status: bicycl_rs_sys::bicycl_status_t) -> Self {
        match status {
            bicycl_rs_sys::bicycl_status_t::BICYCL_OK => Self::Unknown(0),
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_NULL_PTR => Self::NullPtr,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_INVALID_ARGUMENT => Self::InvalidArgument,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_ALLOCATION_FAILED => Self::AllocationFailed,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_INTERNAL => Self::Internal,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_BUFFER_TOO_SMALL => Self::BufferTooSmall,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_PARSE => Self::Parse,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_INVALID_STATE => Self::InvalidState,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_VERIFY_FAILED => Self::VerifyFailed,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_PROTOCOL_ABORT => Self::ProtocolAbort,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_CORE => Self::Core,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_PAILLIER => Self::Paillier,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_JOYE_LIBERT => Self::JoyeLibert,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_CL_HSMQK => Self::ClHsmqk,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_CL_HSM2K => Self::ClHsm2k,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_ECDSA => Self::Ecdsa,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_TWO_PARTY_ECDSA => Self::TwoPartyEcdsa,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_CL_THRESHOLD => Self::ClThreshold,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_CL_DLOG => Self::ClDlog,
            bicycl_rs_sys::bicycl_status_t::BICYCL_ERR_THRESHOLD_ECDSA => Self::ThresholdEcdsa,
            _ => Self::Unknown(status as i32),
        }
    }
}
