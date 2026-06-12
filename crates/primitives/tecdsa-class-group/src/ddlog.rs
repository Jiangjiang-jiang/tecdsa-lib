use rug::{integer::Order, Integer};

use crate::cl::{ClResult, ClSetup, Qfi};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdLogLabel {
    value: Vec<u8>,
}

impl DdLogLabel {
    #[must_use]
    pub fn new(value: Vec<u8>) -> Self {
        Self { value }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    #[must_use]
    pub fn to_integer(&self) -> Integer {
        Integer::from_digits(&self.value, Order::Msf)
    }

    #[must_use]
    pub fn from_integer(v: &Integer) -> Self {
        Self {
            value: v.to_digits::<u8>(Order::Msf),
        }
    }

    #[must_use]
    pub fn zero() -> Self {
        Self { value: vec![0u8] }
    }
}

pub fn ddlog_label(setup: &ClSetup, element: &Qfi) -> ClResult<DdLogLabel> {
    let mut label_elt = setup.cl().to_cl_delta_k(element);
    setup.cl().from_cl_delta_k_to_cl_delta(&mut label_elt);

    label_elt.neg();
    let alpha = setup.compose(element, &label_elt)?;

    #[allow(non_snake_case)]
    let dlog = setup.dlog_in_F_bytes(&alpha)?;
    Ok(DdLogLabel::new(dlog))
}

pub fn ddlog_verify_power_of_f(setup: &ClSetup, m_bytes: &[u8]) -> ClResult<bool> {
    let fm = setup.power_of_f_bytes(m_bytes)?;
    let label = ddlog_label(setup, &fm)?;
    let label_val = Integer::from_digits(label.as_bytes(), Order::Msf);
    let m_val = Integer::from_digits(m_bytes, Order::Msf);
    Ok(label_val == m_val)
}
