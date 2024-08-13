use std::net::IpAddr;
use pnet::packet::tcp::TcpFlags;

pub struct Fingerprint {
    pub ip: IpAddr,
    pub window_size: u16,
    pub options: String,
    pub mss: String,
    pub window_scale: String,
}

impl Fingerprint {
    pub fn new(ip: IpAddr, window_size: u16, options: String, mss: String, window_scale: String) -> Self {
        Fingerprint {
            ip,
            window_size,
            options,
            mss,
            window_scale,
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}\n",
            self.ip,
            self.window_size,
            self.options,
            self.mss,
            self.window_scale
        )
    }
}

pub fn extract_tcp_options(tcp_payload: &[u8]) -> (String, String, String) {
    let mut options_str = String::new();
    let mut mss = String::new();
    let mut window_scale = String::new();

    let tcp_header_length = ((tcp_payload[12] >> 4) as usize) * 4;
    let options_slice = &tcp_payload[20..tcp_header_length];

    let mut i = 0;
    while i < options_slice.len() {
        let kind = options_slice[i];
        match kind {
            0 => {
                options_str.push_str("0-");
                break;
            },
            1 => {
                options_str.push_str("1-");
                i += 1;
            },
            2 => {
                if options_slice.len() >= i + 4 {
                    mss = u16::from_be_bytes([options_slice[i+2], options_slice[i+3]]).to_string();
                }
                options_str.push_str("2-");
                i += 4;
            },
            3 => {
                if options_slice.len() >= i + 3 {
                    window_scale = options_slice[i+2].to_string();
                }
                options_str.push_str("3-");
                i += 3;
            },
            _ => {
                options_str.push_str(&format!("{}-", kind));
                if options_slice.len() > i + 1 {
                    let length = options_slice[i + 1] as usize;
                    if length < 2 { break; }
                    i += length;
                } else {
                    break;
                }
            },
        }
    }

    (options_str.trim_end_matches('-').to_string(), mss, window_scale)
}

pub fn is_syn_packet(tcp_flags: u8, is_incoming: bool) -> bool {
    let is_syn = tcp_flags & TcpFlags::SYN as u8 != 0;
    let is_ack = tcp_flags & TcpFlags::ACK as u8 != 0;
    (is_incoming && is_syn && !is_ack) || (!is_incoming && is_syn && is_ack)
}