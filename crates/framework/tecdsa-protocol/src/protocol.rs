use elliptic_curve::{sec1::ModulusSize, FieldBytesSize};
use tecdsa_curve::TecdsaCurve;
use zeroize::Zeroize;

use crate::state_machine::StateMachine;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseMode {
    Interactive,
    Local,
    SimulationWrapper,
    DerivedSplit,
    NotApplicable,
}

impl PhaseMode {
    pub fn is_main_table_eligible(self) -> bool {
        matches!(self, Self::Interactive | Self::Local | Self::DerivedSplit)
    }

    pub fn is_wire_eligible(self) -> bool {
        matches!(self, Self::Interactive)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseModes {
    pub keygen: PhaseMode,
    pub aux: PhaseMode,
    pub presign: PhaseMode,
    pub sign: PhaseMode,
    pub refresh: PhaseMode,
}

#[derive(Debug, Clone, Copy)]
pub struct PhaseEligibility {
    pub keygen: bool,
    pub presign: bool,
    pub sign: bool,
}

impl PhaseModes {
    pub fn main_table_eligibility(&self) -> PhaseEligibility {
        PhaseEligibility {
            keygen: self.keygen.is_main_table_eligible(),
            presign: self.presign.is_main_table_eligible(),
            sign: self.sign.is_main_table_eligible(),
        }
    }

    pub fn wire_table_eligibility(&self) -> PhaseEligibility {
        PhaseEligibility {
            keygen: self.keygen.is_wire_eligible(),
            presign: self.presign.is_wire_eligible(),
            sign: self.sign.is_wire_eligible(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProtocolMetadata {
    pub name: &'static str,
    pub version: &'static str,
    pub primitive: &'static str,
    pub signing_rounds_paper: u16,
    pub signing_rounds_impl: u16,
    pub security_model: &'static str,
    pub presign_rounds: u16,
    pub online_sign_rounds: u16,
    pub keygen_rounds: u16,
    pub mta_variant: &'static str,
    pub has_refresh: bool,
    pub phase_modes: PhaseModes,
    pub main_table: PhaseEligibility,
    pub wire_table: PhaseEligibility,
}

pub trait Protocol: 'static
where
    FieldBytesSize<Self::Curve>: ModulusSize,
{
    type Curve: TecdsaCurve;

    type KeyShare: Zeroize + Send;
    type PublicKey: Send;
    type AuxInfo: Send;
    type Presignature: Send;
    type Signature: Send;

    type KeyGen: StateMachine<Output = Self::KeyShare>;
    type AuxGen: StateMachine<Output = Self::AuxInfo>;
    type Presign: StateMachine<Output = Self::Presignature>;
    type Sign: StateMachine<Output = Self::Signature>;

    type Refresh: StateMachine<Output = Self::KeyShare>;

    const METADATA: ProtocolMetadata;
}
