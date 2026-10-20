use adln_networking::protocol::*;
use adln_networking::{ConnectionId, GameId};

#[test]
fn header_has_a_stable_little_endian_layout_and_no_game_routing_fields() {
    let packet = Packet {
        kind: Kind::Data,
        connection: ConnectionId(0x0807060504030201),
        token: ConnectionToken::from_bytes([0xa5; 16]),
        sequence: 0x11223344,
        channel: 0x5566,
        payload: vec![0, 255, 42],
    };
    let bytes = packet.encode().unwrap();
    assert_eq!(
        &bytes[..16],
        &[65, 68, 76, 78, 1, 6, 3, 0, 1, 2, 3, 4, 5, 6, 7, 8]
    );
    assert_eq!(&bytes[16..32], &[0xa5; 16]);
    assert_eq!(
        &bytes[32..],
        &[0x44, 0x33, 0x22, 0x11, 0x66, 0x55, 0, 0, 0, 255, 42]
    );
    assert_eq!(Packet::decode(&bytes), Ok(packet.clone()));
    assert!(
        !format!("{packet:?}").contains("165"),
        "Debug must redact the token"
    );
}

#[test]
fn rejects_truncation_trailing_bytes_old_protocol_unknown_kinds_and_reserved_fields() {
    let packet = Packet {
        kind: Kind::Ping,
        connection: ConnectionId(1),
        token: ConnectionToken::from_bytes([7; 16]),
        sequence: 1,
        channel: 0,
        payload: vec![],
    };
    let bytes = packet.encode().unwrap();
    for length in 0..bytes.len() {
        assert_eq!(Packet::decode(&bytes[..length]), Err(ProtocolError::Length));
    }
    for (offset, value, error) in [
        (0, b'O', ProtocolError::Version),
        (4, 0, ProtocolError::Version),
        (5, 0, ProtocolError::Kind),
        (5, 8, ProtocolError::Kind),
        (6, 1, ProtocolError::Length),
        (38, 1, ProtocolError::Reserved),
        (39, 1, ProtocolError::Reserved),
    ] {
        let mut invalid = bytes.clone();
        invalid[offset] = value;
        assert_eq!(Packet::decode(&invalid), Err(error));
    }
    let mut extra = bytes;
    extra.push(0);
    assert!(Packet::decode(&extra).is_err());
    let maximum = Packet {
        payload: vec![0xff; MAX_PAYLOAD],
        ..packet
    };
    assert_eq!(
        Packet::decode(&maximum.encode().unwrap()),
        Ok(maximum.clone())
    );
    assert_eq!(
        Packet {
            payload: vec![0; MAX_PAYLOAD + 1],
            ..maximum
        }
        .encode(),
        Err(ProtocolError::Length)
    );
}

#[test]
fn handshake_carries_application_compatibility_and_only_implemented_transport_features() {
    let hello = Hello {
        game: GameId(17),
        application_version: 9,
        nonce: u64::MAX,
        required_features: FEATURE_RELIABLE,
    };
    assert_eq!(hello.encode().len(), Hello::SIZE);
    assert_eq!(Hello::decode(&hello.encode()), Ok(hello));
    let welcome = Welcome {
        game: GameId(17),
        application_version: 9,
        nonce: u64::MAX,
        idle_timeout_ms: 15000,
        heartbeat_interval_ms: 1000,
        max_payload: 1024,
        channels: 16,
        features: SUPPORTED_FEATURES,
    };
    assert_eq!(welcome.encode().len(), Welcome::SIZE);
    assert_eq!(Welcome::decode(&welcome.encode()), Ok(welcome));
    assert_eq!(welcome.features, 0);
    for code in [
        RejectCode::Game,
        RejectCode::ApplicationVersion,
        RejectCode::Features,
        RejectCode::Capacity,
        RejectCode::EndpointInUse,
    ] {
        let reject = Reject { nonce: 123, code };
        assert_eq!(Reject::decode(&reject.encode()), Ok(reject));
    }
    for length in 0..Welcome::SIZE {
        assert!(Welcome::decode(&welcome.encode()[..length]).is_err());
    }
    let mut reject = Reject {
        nonce: 1,
        code: RejectCode::Game,
    }
    .encode();
    reject[8] = 255;
    assert_eq!(Reject::decode(&reject), Err(ProtocolError::Kind));
}

#[test]
fn arbitrary_input_never_panics_and_successful_decodes_round_trip() {
    use rand::{RngCore, SeedableRng, rngs::StdRng};
    let mut random = StdRng::seed_from_u64(0x41444c4e);
    for length in 0..=HEADER_SIZE + MAX_PAYLOAD + 8 {
        let mut bytes = vec![0; length];
        random.fill_bytes(&mut bytes);
        if length >= HEADER_SIZE {
            bytes[..4].copy_from_slice(&MAGIC);
            bytes[4] = VERSION;
            bytes[5] = Kind::Data as u8;
            bytes[6..8].copy_from_slice(&((length - HEADER_SIZE) as u16).to_le_bytes());
            bytes[38..40].fill(0);
        }
        if let Ok(packet) = Packet::decode(&bytes) {
            assert_eq!(packet.encode().unwrap(), bytes);
        }
    }
}
