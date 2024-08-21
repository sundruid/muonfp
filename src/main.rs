use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::env;
use std::time::Duration;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use log::{info, error, warn};
use hostname;
use config::{Config, File as ConfigFile, FileFormat};
use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod fingerprint;
mod rotating_writer;
mod network_tap;

use fingerprint::{Fingerprint, extract_tcp_options, is_syn_packet};
use rotating_writer::RotatingFileWriter;
use network_tap::{NetworkTap, pcap_global_header, pcap_packet_header};

struct AppConfig {
    interface: String,
    fingerprints_dir: String,
    pcap_dir: String,
    max_file_size: u64,
}

fn read_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    let config_paths = [
        PathBuf::from("muonfp.conf"),
        PathBuf::from("/etc/muonfp.conf"),
        env::current_exe()?.with_file_name("muonfp.conf"),
    ];

    let mut builder = Config::builder();

    for path in &config_paths {
        if path.exists() {
            builder = builder.add_source(ConfigFile::from(path.as_path()).format(FileFormat::Ini));
            info!("Using config file: {}", path.display());
            break;
        }
    }

    let settings = builder.build()?;

    Ok(AppConfig {
        interface: settings.get_string("interface")?,
        fingerprints_dir: settings.get_string("fingerprints")?,
        pcap_dir: settings.get_string("pcap")?,
        max_file_size: settings.get_int("max_file_size")? as u64 * 1024 * 1024,
    })
}

fn main() {
    env_logger::init();
    info!("MuonFP v.1.3");

    if let Err(e) = run() {
        error!("Error: {}", e);
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
    let pcap_global_header = pcap_global_header();
    let mut pcap_writer = RotatingFileWriter::new(
        Path::new(&config.pcap_dir).join("packets"),
        config.max_file_size,
        "pcap",
        move |file| file.write_all(&pcap_global_header)
    )?;
    let mut fingerprint_writer = RotatingFileWriter::new(
        Path::new(&config.fingerprints_dir).join("muonfp"),
        config.max_file_size,
        "out",
        |_| Ok(())
    )?;

    info!("Listening on interface: {}", config.interface);

    // Setup graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let hostname = hostname::get()?.to_string_lossy().into_owned();

    let flush_interval = Duration::from_secs(60); // Flush every 60 seconds
    let mut last_flush = std::time::Instant::now();

    // Capture and log packets
    while running.load(Ordering::SeqCst) {
        match network_tap.next_packet() {
            Ok(ethernet) => {
                let packet_header = pcap_packet_header(ethernet.packet().len() as u32);
                let mut full_packet = Vec::with_capacity(packet_header.len() + ethernet.packet().len());
                full_packet.extend_from_slice(&packet_header);
                full_packet.extend_from_slice(ethernet.packet());
                pcap_writer.write_packet(&full_packet)?;

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
                                    hostname.clone(),
                                    fingerprint_ip,
                                    window_size,
                                    options_str,
                                    mss,
                                    window_scale
                                );

                                // Write JSON line to file
                                writeln!(fingerprint_writer, "{}", fingerprint.to_json())?;
                            }
                        }
                    }
                }

                // Check if we need to flush the writers
                if last_flush.elapsed() >= flush_interval {
                    fingerprint_writer.flush()?;
                    pcap_writer.flush()?;
                    last_flush = std::time::Instant::now();
                }
            }
            Err(e) => {
                warn!("Error capturing packet: {}", e);
            }
        }
    }

    // Graceful shutdown
    info!("Shutting down...");
    fingerprint_writer.flush_and_close()?;
    pcap_writer.flush_and_close()?;

    Ok(())
}