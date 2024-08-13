use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::EthernetPacket, ipv4::Ipv4Packet, Packet};
use std::collections::HashSet;
use std::env;
use std::fs::read_to_string;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

mod fingerprint;
mod rotating_writer;
use fingerprint::{Fingerprint, extract_tcp_options, is_syn_packet};
use rotating_writer::RotatingFileWriter;

struct Config {
    interface: String,
    fingerprints_dir: String,
    pcap_dir: String,
    max_file_size: u64,
}

fn read_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_paths = [
        PathBuf::from("muonfp.conf"),
        PathBuf::from("/etc/muonfp.conf"),
        env::current_exe()?.with_file_name("muonfp.conf"),
    ];

    let config_content = config_paths.iter()
        .find_map(|path| {
            match read_to_string(path) {
                Ok(content) => {
                    println!("Using config file: {}", path.display());
                    Some(content)
                },
                Err(_) => None,
            }
        })
        .ok_or("Could not find or read muonfp.conf. Looked in current directory, /etc/, and next to the executable.")?;

    let mut interface = String::new();
    let mut fingerprints_dir = String::new();
    let mut pcap_dir = String::new();
    let mut max_file_size = 100 * 1024 * 1024; // Default to 100MB

    for line in config_content.lines() {
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() == 2 {
            match parts[0].trim() {
                "interface" => interface = parts[1].trim().to_string(),
                "fingerprints" => fingerprints_dir = parts[1].trim().to_string(),
                "pcap" => pcap_dir = parts[1].trim().to_string(),
                "max_file_size" => max_file_size = parts[1].trim().parse::<u64>()? * 1024 * 1024,
                _ => eprintln!("Unknown configuration option: {}", parts[0]),
            }
        }
    }

    if interface.is_empty() || fingerprints_dir.is_empty() || pcap_dir.is_empty() {
        return Err("Missing required configuration options".into());
    }

    Ok(Config {
        interface,
        fingerprints_dir,
        pcap_dir,
        max_file_size,
    })
}

fn main() {
    println!("MuonFP v.1");

    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Read configuration
    let config = read_config()?;

    // Validate directories
    if !Path::new(&config.fingerprints_dir).is_dir() {
        return Err(format!("Fingerprints directory does not exist: {}", config.fingerprints_dir).into());
    }
    if !Path::new(&config.pcap_dir).is_dir() {
        return Err(format!("PCAP directory does not exist: {}", config.pcap_dir).into());
    }

    // Find the network interface to use
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name == config.interface)
        .ok_or_else(|| format!("Error: Network interface {} not found", config.interface))?;

    // Collect all IP addresses of the local interface
    let local_ips: HashSet<IpAddr> = interface
        .ips
        .iter()
        .map(|ip_network| ip_network.ip())
        .collect();

    // Create a channel to capture packets
    let mut rx = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => return Err("Unhandled channel type".into()),
        Err(e) => return Err(format!("Error creating datalink channel: {}", e).into()),
    };

    // Create rotating writers
    let mut pcap_writer = RotatingFileWriter::new(
        Path::new(&config.pcap_dir).join("packets"),
        config.max_file_size
    )?;
    let mut fingerprint_writer = RotatingFileWriter::new(
        Path::new(&config.fingerprints_dir).join("muonfp"),
        config.max_file_size
    )?;

    // Write the PCAP global header
    let pcap_global_header = pcap_file_header();
    pcap_writer.write(&pcap_global_header)?;

    println!("Listening on interface: {}", config.interface);

    // Capture and log packets
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();

                // Write packet to pcap file with pcap packet header
                let pcap_packet_header = pcap_packet_header(ethernet.packet().len() as u32);
                pcap_writer.write(&pcap_packet_header)?;
                pcap_writer.write(ethernet.packet())?;

                if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                    let source_ip = IpAddr::V4(ip_packet.get_source());
                    let destination_ip = IpAddr::V4(ip_packet.get_destination());

                    // Process packets in both directions
                    let (fingerprint_ip, is_incoming) = if local_ips.contains(&destination_ip) {
                        (source_ip, true) // Incoming connection
                    } else if local_ips.contains(&source_ip) {
                        (destination_ip, false) // Outgoing connection response
                    } else {
                        continue; // Neither source nor destination is local, skip
                    };

                    // Skip broadcast, multicast, or unspecified IPs
                    if let IpAddr::V4(ip) = fingerprint_ip {
                        if ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified() {
                            continue;
                        }
                    }

                    if ip_packet.get_next_level_protocol().0 == 6 { // TCP protocol
                        let tcp_payload = ip_packet.payload();
                        if tcp_payload.len() >= 20 { // Minimum TCP header size
                            let flags = tcp_payload[13];
                            
                            if is_syn_packet(flags, is_incoming) {
                                let window_size = u16::from_be_bytes([tcp_payload[14], tcp_payload[15]]);
                                let (options_str, mss, window_scale) = extract_tcp_options(tcp_payload);

                                let fingerprint = Fingerprint::new(
                                    fingerprint_ip,
                                    window_size,
                                    options_str,
                                    mss,
                                    window_scale
                                );

                                // Write signature to file
                                fingerprint_writer.write(fingerprint.to_string().as_bytes())?;
                                fingerprint_writer.flush()?;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to read packet: {}", e);
            }
        }
    }
}

// Function to create a PCAP global header
fn pcap_file_header() -> [u8; 24] {
    [
        0xd4, 0xc3, 0xb2, 0xa1, // Magic number
        0x02, 0x00, 0x04, 0x00, // Version major and minor
        0x00, 0x00, 0x00, 0x00, // Thiszone (GMT)
        0x00, 0x00, 0x00, 0x00, // Sigfigs
        0xff, 0xff, 0x00, 0x00, // Snaplen
        0x01, 0x00, 0x00, 0x00, // Network (Ethernet)
    ]
}

// Function to create a PCAP packet header
fn pcap_packet_header(packet_length: u32) -> [u8; 16] {
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