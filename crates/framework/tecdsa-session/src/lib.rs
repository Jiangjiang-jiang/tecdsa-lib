#![forbid(unsafe_code)]

pub mod checkpoint;
pub mod config;
pub mod error;
pub mod metrics;
pub(crate) mod runner;
pub mod sync_session;

pub use checkpoint::{Checkpointable, SessionCheckpoint};
pub use config::{RetryPolicy, SessionRunConfig};
pub use error::SessionError;
pub use metrics::SessionMetrics;
pub use sync_session::{run_multi_party_sync, SyncSession};

#[cfg(feature = "async")]
pub mod async_session;
#[cfg(feature = "async")]
pub mod async_transport;

#[cfg(feature = "async")]
pub use async_session::AsyncSession;
#[cfg(feature = "async")]
pub use async_transport::AsyncTransport;
