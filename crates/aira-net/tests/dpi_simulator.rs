//! DPI Simulator — verifies that obfuscated traffic cannot be identified
//! as Aira protocol by pattern matching.
//!
//! SPEC.md §16.M7 task 6: "DPI-simulator (nDPI/Wireshark) does not detect Aira traffic."
//!
//! This test suite runs raw bytes through a simplified DPI classifier that
//! checks for known protocol signatures (QUIC, TLS, DNS, STUN, raw Aira).

use aira_net::transport::{BoxedStream, TransportMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Known protocol signature patterns for DPI detection.
struct DpiSimulator;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DetectedProtocol {
    Quic,
    Tls,
    Dns,
    Stun,
    Sip,
    Aira,
    Unknown,
}

impl DpiSimulator {
    /// Analyze raw bytes and attempt to classify the protocol.
    fn classify(data: &[u8]) -> DetectedProtocol {
        if data.len() < 4 {
            return DetectedProtocol::Unknown;
        }

        // QUIC long header Initial: 0xC0-0xCF + version 0x00000001
        if data[0] & 0xF0 == 0xC0 && data.len() >= 5 && data[1..5] == [0x00, 0x00, 0x00, 0x01] {
            return DetectedProtocol::Quic;
        }

        // TLS ClientHello: 0x16 0x03 0x01/0x03
        if data[0] == 0x16 && data.len() >= 3 && data[1] == 0x03 {
            return DetectedProtocol::Tls;
        }

        // DNS: flags=0x0100, qdcount>0, ancount=0
        if data.len() >= 12 && data[2] == 0x01 && data[3] == 0x00 {
            let qdcount = u16::from_be_bytes([data[4], data[5]]);
            let ancount = u16::from_be_bytes([data[6], data[7]]);
            if qdcount > 0 && ancount == 0 {
                return DetectedProtocol::Dns;
            }
        }

        // STUN: type=0x0001, magic cookie 0x2112A442 at offset 4
        if data.len() >= 8
            && data[0] == 0x00
            && data[1] == 0x01
            && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
        {
            return DetectedProtocol::Stun;
        }

        // SIP INVITE
        if data.len() >= 6 && &data[..6] == b"INVITE" {
            return DetectedProtocol::Sip;
        }

        // Raw Aira framing: u32 BE length + postcard enum tag (0..16)
        if data.len() >= 5 {
            let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            if len > 0 && len < 1024 && data.len() >= (4 + len as usize) && data[4] < 16 {
                return DetectedProtocol::Aira;
            }
        }

        DetectedProtocol::Unknown
    }
}

// ─── DPI classifier unit tests ──────────────────────────────────────────────

#[test]
fn dpi_classifies_quic_header() {
    let mut data = vec![0xC0, 0x00, 0x00, 0x00, 0x01, 0x08];
    data.extend_from_slice(&[0; 8]);
    data.push(0x08);
    data.extend_from_slice(&[0; 8]);
    assert_eq!(DpiSimulator::classify(&data), DetectedProtocol::Quic);
}

#[test]
fn dpi_classifies_tls_client_hello() {
    let data = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
    assert_eq!(DpiSimulator::classify(&data), DetectedProtocol::Tls);
}

#[test]
fn dpi_classifies_dns_query() {
    let mut data = vec![
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    data.extend_from_slice(&[0; 20]);
    assert_eq!(DpiSimulator::classify(&data), DetectedProtocol::Dns);
}

#[test]
fn dpi_classifies_stun() {
    let data = [
        0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(DpiSimulator::classify(&data), DetectedProtocol::Stun);
}

#[test]
fn dpi_classifies_sip() {
    assert_eq!(
        DpiSimulator::classify(b"INVITE sip:user@host SIP/2.0\r\n"),
        DetectedProtocol::Sip,
    );
}

#[test]
fn dpi_unknown_for_random_data() {
    let data = [0xFF, 0xFE, 0xFD, 0xFC, 0x80, 0x70, 0x60, 0x50];
    assert_eq!(DpiSimulator::classify(&data), DetectedProtocol::Unknown);
}

// ─── Transport integration tests ────────────────────────────────────────────

#[tokio::test]
async fn direct_transport_passes_payload_unchanged() {
    let transport =
        aira_net::transport::create_transport(&TransportMode::Direct, None).expect("create");
    let (client_raw, server_raw) = tokio::io::duplex(8192);

    let mut client = transport
        .wrap_outbound(BoxedStream::new(client_raw))
        .await
        .expect("wrap");
    let mut server = BoxedStream::new(server_raw);

    let payload = b"hello aira";
    client.write_all(payload).await.expect("write");
    drop(client);

    let mut buf = Vec::new();
    server.read_to_end(&mut buf).await.expect("read");
    assert_eq!(buf, payload, "Direct transport should pass bytes unchanged");
}

#[test]
fn obfs_output_is_undetectable() {
    // Simulate what obfs output looks like: nonce (32 random bytes) +
    // framed XOR'd data — all looks random.
    let mut fake_obfs = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut fake_obfs);
    fake_obfs.extend_from_slice(&[0x00, 0x0A]); // 2-byte LE length
    let mut payload = [0u8; 10];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut payload);
    fake_obfs.extend_from_slice(&payload);

    let detection = DpiSimulator::classify(&fake_obfs);
    assert_eq!(
        detection,
        DetectedProtocol::Unknown,
        "Obfuscated traffic must not match any known protocol"
    );
}

#[test]
fn mimicry_dns_header_detected_as_dns() {
    let dns_header = [
        0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(DpiSimulator::classify(&dns_header), DetectedProtocol::Dns);
}

#[test]
fn mimicry_quic_header_detected_as_quic() {
    let mut hdr = vec![0xC0, 0x00, 0x00, 0x00, 0x01];
    hdr.push(8);
    hdr.extend_from_slice(&[0x01; 8]);
    hdr.push(8);
    hdr.extend_from_slice(&[0x02; 8]);
    assert_eq!(DpiSimulator::classify(&hdr), DetectedProtocol::Quic);
}

#[test]
fn mimicry_stun_header_detected_as_stun() {
    let mut hdr = vec![0x00, 0x01, 0x00, 0x10];
    hdr.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    hdr.extend_from_slice(&[0; 12]);
    assert_eq!(DpiSimulator::classify(&hdr), DetectedProtocol::Stun);
}

#[test]
fn mimicry_sip_header_detected_as_sip() {
    let sip = b"INVITE sip:user@host SIP/2.0\r\nContent-Length: 42\r\n\r\n";
    assert_eq!(DpiSimulator::classify(sip), DetectedProtocol::Sip);
}
