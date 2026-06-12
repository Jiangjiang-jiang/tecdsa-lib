use elliptic_curve::sec1::ToSec1Point;
use fast_paillier::backend::Integer;
use rug::Integer as RugInteger;
use tecdsa_curve::TecdsaCurve;

pub trait BridgeCurve: TecdsaCurve
where
    elliptic_curve::FieldBytesSize<Self>: elliptic_curve::sec1::ModulusSize,
{
    type GE: generic_ec::Curve;
}

impl BridgeCurve for k256::Secp256k1 {
    type GE = generic_ec::curves::Secp256k1;
}

#[must_use]
pub fn scalar_to_ge(s: &k256::Scalar) -> generic_ec::Scalar<generic_ec::curves::Secp256k1> {
    let repr = elliptic_curve::PrimeField::to_repr(s);
    let bytes: &[u8] = repr.as_ref();
    generic_ec::Scalar::from_be_bytes_mod_order(bytes)
}

#[must_use]
pub fn point_to_ge(p: &k256::ProjectivePoint) -> generic_ec::Point<generic_ec::curves::Secp256k1> {
    let affine = k256::AffinePoint::from(*p);
    let sec1 = affine.to_sec1_point(true);
    generic_ec::Point::from_bytes(sec1.as_bytes()).expect("valid SEC1 point must decode")
}

#[must_use]
pub fn dynint_to_integer(d: &RugInteger) -> Integer {
    let n = d.significant_digits::<u8>();
    let mut buf = vec![0u8; n];
    d.write_digits(&mut buf, rug::integer::Order::Msf);
    Integer::from_bytes_msf(&buf)
}

#[must_use]
pub fn pedersen_to_aux(
    params: &tecdsa_pedersen_mod::PedersenModParams,
) -> paillier_zk::paillier_encryption_in_range::Aux {
    paillier_zk::paillier_encryption_in_range::Aux {
        s: dynint_to_integer(&params.s),
        t: dynint_to_integer(&params.t),
        rsa_modulo: dynint_to_integer(&params.n),
        multiexp: None,
        crt: None,
    }
}
