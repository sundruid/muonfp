use std::fs::read_to_string;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::env;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;

mod fingerprint;
mod rotating_writer;
mod network_tap;

use fingerprint::{Fingerprint, extract_tcp_options, is_syn_packet};
use rotating_writer::RotatingFileWriter;
use network_tap::{NetworkTap, pcap_global_header, pcap_packet_header};

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
    println!("MuonFP v.1.1");

    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = read_config()?;

    // Validate directories
    if !Path::new(&config.fingerprints_dir).is_dir() {
        return Err(format!("Fingerprints directory does not exist: {}", config.fingerprints_dir).into());
    }
    if !Path::new(&config.pcap_dir).is_dir() {
        return Err(format!("PCAP directory does not exist: {}", config.pcap_dir).into());
    }

    let mut network_tap = NetworkTap::new(&config.interface)?;
    let local_ips = network_tap.local_ips.clone();

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
    let pcap_global_header = pcap_global_header();
    pcap_writer.write_all(&pcap_global_header)?;

    println!("Listening on interface: {}", config.interface);

    // Capture and log packets
    loop {
        match network_tap.next_packet() {
            Ok(ethernet) => {
                // Write packet to pcap file with pcap packet header
                let pcap_packet_header = pcap_packet_header(ethernet.packet().len() as u32);
                pcap_writer.write_all(&pcap_packet_header)?;
                pcap_writer.write_all(ethernet.packet())?;

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

                                // Write JSON line to file
                                writeln!(fingerprint_writer, "{}", fingerprint.to_json())?;
                                fingerprint_writer.flush()?;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }
}