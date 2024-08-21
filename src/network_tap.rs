use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use std::io;
use std::net::IpAddr;
use std::collections::HashSet;

pub struct NetworkTap {
    rx: Box<dyn datalink::DataLinkReceiver>,
    pub local_ips: HashSet<IpAddr>,
}

impl NetworkTap {
    pub fn new(interface_name: &str) -> io::Result<Self> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == interface_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("Network interface {} not found", interface_name)))?;
        let local_ips: HashSet<IpAddr> = interface
            .ips
            .iter()
            .map(|ip_network| ip_network.ip())
            .collect();
        let (_, rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(io::Error::new(io::ErrorKind::Other, "Unhandled channel type")),
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("Error creating datalink channel: {}", e))),
        };
        Ok(NetworkTap { rx, local_ips })
    }

    pub fn next_packet(&mut self) -> io::Result<EthernetPacket> {
        match self.rx.next() {
            Ok(packet) => Ok(EthernetPacket::new(packet).unwrap()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("Failed to read packet: {}", e))),
        }
    }
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
    let usecs = timestamp.subsec_micros() as u32;
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