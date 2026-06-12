use rand_core::OsRng;
use tecdsa_ot::base_ot::{BaseOtReceiver, BaseOtSender, MSG_LEN};

#[test]
fn base_ot_choice_zero_gets_m0() {
    let mut rng = OsRng;
    let m0 = [0x11_u8; MSG_LEN];
    let m1 = [0x22_u8; MSG_LEN];

    let (sender, setup) = BaseOtSender::setup(&mut rng);
    let (receiver, response) =
        BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
    let payload = sender
        .encrypt(&response, &m0, &m1)
        .expect("encrypt should succeed");
    let result = receiver.decrypt(&payload);

    assert_eq!(result, m0, "receiver with choice=0 should get m0");
}

#[test]
fn base_ot_choice_one_gets_m1() {
    let mut rng = OsRng;
    let m0 = [0x11_u8; MSG_LEN];
    let m1 = [0x22_u8; MSG_LEN];

    let (sender, setup) = BaseOtSender::setup(&mut rng);
    let (receiver, response) =
        BaseOtReceiver::choose(&setup, true, &mut rng).expect("choose should succeed");
    let payload = sender
        .encrypt(&response, &m0, &m1)
        .expect("encrypt should succeed");
    let result = receiver.decrypt(&payload);

    assert_eq!(result, m1, "receiver with choice=1 should get m1");
}

#[test]
fn base_ot_random_messages_both_choices() {
    let mut rng = OsRng;

    for choice in [false, true] {
        let mut m0 = [0u8; MSG_LEN];
        let mut m1 = [0u8; MSG_LEN];
        rng.fill_bytes(&mut m0);
        rng.fill_bytes(&mut m1);

        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, choice, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        let expected = if choice { m1 } else { m0 };
        assert_eq!(result, expected);
    }
}

#[test]
fn base_ot_multiple_independent_sessions() {
    let mut rng = OsRng;

    for _ in 0..5 {
        let mut m0 = [0u8; MSG_LEN];
        let mut m1 = [0u8; MSG_LEN];
        rng.fill_bytes(&mut m0);
        rng.fill_bytes(&mut m1);

        let choice = rand::random::<bool>();
        let (sender, setup) = BaseOtSender::setup(&mut rng);
        let (receiver, response) =
            BaseOtReceiver::choose(&setup, choice, &mut rng).expect("choose should succeed");
        let payload = sender
            .encrypt(&response, &m0, &m1)
            .expect("encrypt should succeed");
        let result = receiver.decrypt(&payload);

        let expected = if choice { m1 } else { m0 };
        assert_eq!(result, expected);
    }
}

#[test]
fn base_ot_different_senders_produce_different_payloads() {
    let mut rng = OsRng;
    let m0 = [0xAA_u8; MSG_LEN];
    let m1 = [0xBB_u8; MSG_LEN];

    let (sender1, setup1) = BaseOtSender::setup(&mut rng);
    let (sender2, setup2) = BaseOtSender::setup(&mut rng);

    let (_receiver1, response1) =
        BaseOtReceiver::choose(&setup1, false, &mut rng).expect("choose should succeed");
    let (_receiver2, response2) =
        BaseOtReceiver::choose(&setup2, false, &mut rng).expect("choose should succeed");

    let payload1 = sender1
        .encrypt(&response1, &m0, &m1)
        .expect("encrypt should succeed");
    let payload2 = sender2
        .encrypt(&response2, &m0, &m1)
        .expect("encrypt should succeed");

    assert_ne!(payload1.ct0, payload2.ct0);
}

#[test]
fn base_ot_receiver_cannot_get_both_messages() {
    let mut rng = OsRng;
    let m0 = *b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let m1 = *b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let (sender, setup) = BaseOtSender::setup(&mut rng);
    let (receiver, response) =
        BaseOtReceiver::choose(&setup, false, &mut rng).expect("choose should succeed");
    let payload = sender
        .encrypt(&response, &m0, &m1)
        .expect("encrypt should succeed");

    let got = receiver.decrypt(&payload);
    assert_eq!(got, m0);

    let bad_decrypt = payload.ct1;
    assert_ne!(bad_decrypt, m1, "ct1 alone should not reveal m1");
}

use rand_core::RngCore;
