use chrono::{DateTime, Utc};
use pnet::packet::tcp::TcpFlags;
use serde::Serialize;
use std::net::IpAddr;

#[derive(Serialize)]
pub struct Fingerprint {
    pub hostname: String,
    pub timestamp: DateTime<Utc>,
    pub ip_address: IpAddr,
    pub muonfp_fingerprint: String,
}

impl Fingerprint {
    pub fn new(
        hostname: String,
        ip: IpAddr,
        window_size: u16,
        options: String,
        mss: String,
        window_scale: String,
    ) -> Self {
        let muonfp_fingerprint = format!("{}:{}:{}:{}", window_size, options, mss, window_scale);
        Fingerprint {
            hostname,
            timestamp: Utc::now(),
            ip_address: ip,
            muonfp_fingerprint,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

pub fn extract_tcp_options(tcp_payload: &[u8]) -> Option<(String, String, String)> {
    if tcp_payload.len() < 20 {
        return None;
    }

    let tcp_header_length = ((tcp_payload[12] >> 4) as usize) * 4;
    if !(20..=tcp_payload.len()).contains(&tcp_header_length) {
        return None;
    }

    let mut options_str = String::new();
    let mut mss = String::new();
    let mut window_scale = String::new();

    let options_slice = &tcp_payload[20..tcp_header_length];

    let mut i = 0;
    while i < options_slice.len() {
        let kind = options_slice[i];
        match kind {
            0 => {
                options_str.push_str("0-");
                break;
            }
            1 => {
                options_str.push_str("1-");
                i += 1;
            }
            2 => {
                if options_slice.len() >= i + 4 {
                    mss = u16::from_be_bytes([options_slice[i + 2], options_slice[i + 3]])
                        .to_string();
                }
                options_str.push_str("2-");
                i += 4;
            }
            3 => {
                if options_slice.len() >= i + 3 {
                    window_scale = options_slice[i + 2].to_string();
                }
                options_str.push_str("3-");
                i += 3;
            }
            _ => {
                options_str.push_str(&format!("{}-", kind));
                if options_slice.len() > i + 1 {
                    let length = options_slice[i + 1] as usize;
                    if length < 2 {
                        break;
                    }
                    i += length;
                } else {
                    break;
                }
            }
        }
    }

    Some((
        options_str.trim_end_matches('-').to_string(),
        mss,
        window_scale,
    ))
}

pub fn is_syn_packet(tcp_flags: u8, is_incoming: bool) -> bool {
    let is_syn = tcp_flags & TcpFlags::SYN != 0;
    let is_ack = tcp_flags & TcpFlags::ACK != 0;
    (is_incoming && is_syn && !is_ack) || (!is_incoming && is_syn && is_ack)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_header(header_words: u8, options: &[u8]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[12] = header_words << 4;
        packet.extend_from_slice(options);
        packet
    }

    #[test]
    fn extracts_options_in_wire_order() {
        let packet = tcp_header(8, &[2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 0]);
        let (options, mss, window_scale) = extract_tcp_options(&packet).expect("valid TCP header");

        assert_eq!(options, "2-4-8");
        assert_eq!(mss, "1460");
        assert_eq!(window_scale, "");
    }

    #[test]
    fn extracts_window_scale_and_nops() {
        let packet = tcp_header(7, &[1, 3, 3, 8, 0, 0, 0, 0]);
        let (options, mss, window_scale) = extract_tcp_options(&packet).expect("valid TCP header");

        assert_eq!(options, "1-3-0");
        assert_eq!(mss, "");
        assert_eq!(window_scale, "8");
    }

    #[test]
    fn accepts_header_without_options() {
        let packet = tcp_header(5, &[]);
        assert_eq!(
            extract_tcp_options(&packet),
            Some((String::new(), String::new(), String::new()))
        );
    }

    #[test]
    fn rejects_short_or_invalid_header_lengths() {
        assert_eq!(extract_tcp_options(&[0_u8; 19]), None);
        assert_eq!(extract_tcp_options(&tcp_header(4, &[])), None);
        assert_eq!(extract_tcp_options(&tcp_header(15, &[])), None);
    }

    #[test]
    fn identifies_only_handshake_syn_packets() {
        assert!(is_syn_packet(TcpFlags::SYN, true));
        assert!(is_syn_packet(TcpFlags::SYN | TcpFlags::ACK, false));
        assert!(!is_syn_packet(TcpFlags::SYN | TcpFlags::ACK, true));
        assert!(!is_syn_packet(TcpFlags::ACK, false));
    }

    #[test]
    fn fingerprint_json_is_valid() {
        let fingerprint = Fingerprint::new(
            "sensor".to_string(),
            "192.0.2.10".parse().expect("valid address"),
            65_535,
            "2-4-8-1-3".to_string(),
            "1460".to_string(),
            "8".to_string(),
        );

        let json = fingerprint.to_json().expect("serializable fingerprint");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert_eq!(value["hostname"], "sensor");
        assert_eq!(value["ip_address"], "192.0.2.10");
        assert_eq!(value["muonfp_fingerprint"], "65535:2-4-8-1-3:1460:8");
    }
}
