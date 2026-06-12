#![allow(clippy::doc_markdown)]

use serde::{Deserialize, Serialize};
use tecdsa_joye_libert::mta::{JlMtaReceiverMsg, JlMtaSenderMsg};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Xal23PresignMsg {
    R1Broadcast(R1BroadcastPayload),
    R1P2p(R1P2pPayload),
    R2Broadcast(R2BroadcastPayload),
    R2P2p(R2P2pPayload),
    R3Broadcast(R3BroadcastPayload),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1BroadcastPayload {
    pub commitment: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1P2pPayload {
    pub gamma_sender_msg: JlMtaSenderMsg,
    pub w_sender_msg: JlMtaSenderMsg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2BroadcastPayload {
    pub gamma_point_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R2P2pPayload {
    pub gamma_receiver_msg: JlMtaReceiverMsg,
    pub w_receiver_msg: JlMtaReceiverMsg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R3BroadcastPayload {
    pub delta_i_bytes: Vec<u8>,
}
