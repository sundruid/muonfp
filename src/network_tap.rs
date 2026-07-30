use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::IpAddr;

pub struct NetworkTap {
    rx: Box<dyn datalink::DataLinkReceiver>,
    pub local_ips: HashSet<IpAddr>,
    pub interface_name: String,
}

impl NetworkTap {
    pub fn new(interface_name: &str) -> io::Result<Self> {
        let interfaces = datalink::interfaces();
        let requested_name = if interface_name.eq_ignore_ascii_case("auto") {
            default_route_interface().or_else(|| {
                let mut candidates = interfaces
                    .iter()
                    .filter(|interface| {
                        interface.is_up()
                            && !interface.is_loopback()
                            && interface
                                .ips
                                .iter()
                                .any(|network| !network.ip().is_loopback())
                    })
                    .map(|interface| interface.name.clone())
                    .collect::<Vec<_>>();
                candidates.sort();
                candidates.into_iter().next()
            })
        } else {
            Some(interface_name.to_string())
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no active non-loopback network interface was found",
            )
        })?;

        let interface = interfaces
            .into_iter()
            .find(|interface| interface.name == requested_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("network interface {requested_name} not found"),
                )
            })?;
        let selected_interface_name = interface.name.clone();
        let local_ips: HashSet<IpAddr> = interface
            .ips
            .iter()
            .map(|ip_network| ip_network.ip())
            .collect();
        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(io::Error::other("unhandled datalink channel type")),
            Err(error) => {
                return Err(io::Error::other(format!(
                    "error creating datalink channel: {error}"
                )))
            }
        };
        Ok(NetworkTap {
            rx,
            local_ips,
            interface_name: selected_interface_name,
        })
    }

    pub fn next_packet(&mut self) -> io::Result<EthernetPacket<'_>> {
        match self.rx.next() {
            Ok(packet) => EthernetPacket::new(packet)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short Ethernet frame")),
            Err(error) => Err(io::Error::other(format!("failed to read packet: {error}"))),
        }
    }
}

fn default_route_interface() -> Option<String> {
    let route_table = fs::read_to_string("/proc/net/route").ok()?;
    route_table.lines().skip(1).find_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.get(1) == Some(&"00000000") {
            fields.first().map(|name| (*name).to_string())
        } else {
            None
        }
    })
}

pub fn pcap_global_header() -> [u8; 24] {
    [
        0xd4, 0xc3, 0xb2, 0xa1, // Magic number
        0x02, 0x00, 0x04, 0x00, // Version major and minor
        0x00, 0x00, 0x00, 0x00, // Thiszone (GMT)
        0x00, 0x00, 0x00, 0x00, // Sigfigs
        0xff, 0xff, 0x00, 0x00, // Snaplen
        0x01, 0x00, 0x00, 0x00, // Network (Ethernet)
    ]
}

pub fn pcap_packet_header(packet_length: u32) -> [u8; 16] {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards");
    let secs = timestamp.as_secs() as u32;
    let usecs = timestamp.subsec_micros();
    [
        (secs & 0xff) as u8,
        ((secs >> 8) & 0xff) as u8,
        ((secs >> 16) & 0xff) as u8,
        ((secs >> 24) & 0xff) as u8,
        (usecs & 0xff) as u8,
        ((usecs >> 8) & 0xff) as u8,
        ((usecs >> 16) & 0xff) as u8,
        ((usecs >> 24) & 0xff) as u8,
        (packet_length & 0xff) as u8,
        ((packet_length >> 8) & 0xff) as u8,
        ((packet_length >> 16) & 0xff) as u8,
        ((packet_length >> 24) & 0xff) as u8,
        (packet_length & 0xff) as u8,
        ((packet_length >> 8) & 0xff) as u8,
        ((packet_length >> 16) & 0xff) as u8,
        ((packet_length >> 24) & 0xff) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pcap_global_header_has_expected_format() {
        let header = pcap_global_header();
        assert_eq!(&header[0..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        assert_eq!(&header[20..24], &[1, 0, 0, 0]);
    }

    #[test]
    fn pcap_packet_header_records_lengths() {
        let header = pcap_packet_header(1500);
        assert_eq!(u32::from_le_bytes(header[8..12].try_into().unwrap()), 1500);
        assert_eq!(u32::from_le_bytes(header[12..16].try_into().unwrap()), 1500);
    }
}
