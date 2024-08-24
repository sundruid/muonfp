use std::fs::File;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::env;
use std::time::Duration;
use pnet::packet::Packet;
use pnet::packet::ipv4::Ipv4Packet;
use log::{info, error, warn, debug, LevelFilter};
use hostname;
use ctrlc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::collections::{HashSet, HashMap};
use env_logger::{Builder, Target};

mod fingerprint;
mod rotating_writer;
mod network_tap;
mod ipblocker;

use fingerprint::{Fingerprint, extract_tcp_options, is_syn_packet};
use rotating_writer::RotatingFileWriter;
use network_tap::{NetworkTap, pcap_global_header, pcap_packet_header};
use ipblocker::IPBlocker;

struct AppConfig {
    interface: String,
    fingerprints_dir: String,
    pcap_dir: String,
    max_file_size: u64,
    blocked_fingerprints: HashSet<String>,
    fpfw_logfile: String,
}


fn read_config() -> Result<AppConfig, Box<dyn std::error::Error>> {
    let config_paths = [
        PathBuf::from("muonfp.conf"),
        PathBuf::from("/etc/muonfp.conf"),
        env::current_exe()?.with_file_name("muonfp.conf"),
    ];
    let mut builder = config::Config::builder();
    for path in &config_paths {
        if path.exists() {
            builder = builder.add_source(config::File::from(path.as_path()).format(config::FileFormat::Ini));
            info!("Using config file: {}", path.display());
            break;
        }
    }
    let settings = builder.build()?;

    // Debug: Print all keys in the configuration
    debug!("Configuration contents:");
    if let Ok(config_map) = settings.get::<HashMap<String, config::Value>>("") {
        for (key, value) in config_map.iter() {
            debug!(" {}: {:?}", key, value);
        }
    } else {
        warn!("Failed to get configuration for debugging");
    }

    let mut blocked_fingerprints = HashSet::new();
    if let Ok(block) = settings.get::<Vec<String>>("block") {
        for fp in block {
            blocked_fingerprints.insert(fp.clone());
            debug!("Loaded blocked fingerprint: {}", fp);
        }
    } else {
        warn!("No 'block' section found in the configuration or it's empty.");
    }
    debug!("Total blocked fingerprints loaded: {}", blocked_fingerprints.len());

    Ok(AppConfig {
        interface: settings.get::<String>("network.interface")?,
        fingerprints_dir: settings.get::<String>("fingerprints.fingerprints_dir")?,
        pcap_dir: settings.get::<String>("network.pcap")?,
        max_file_size: settings.get::<i64>("pcap.max_file_size")? as u64 * 1024 * 1024,
        blocked_fingerprints,
        fpfw_logfile: settings.get::<String>("logging.fpfw_logfile")?,
    })
}

fn main() {
    let config = read_config().expect("Failed to read configuration");

    let log_file = File::create(&config.fpfw_logfile).expect("Could not create log file");

    Builder::new()
        .target(Target::Pipe(Box::new(log_file)))
        .filter(None, LevelFilter::Debug)
        .init();

    info!("MuonFP v.1.3");

    if let Err(e) = run(config) {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    if !Path::new(&config.fingerprints_dir).is_dir() {
        return Err(format!("Fingerprints directory does not exist: {}", config.fingerprints_dir).into());
    }
    if !Path::new(&config.pcap_dir).is_dir() {
        return Err(format!("PCAP directory does not exist: {}", config.pcap_dir).into());
    }

    let mut network_tap = NetworkTap::new(&config.interface)?;
    let local_ips = network_tap.local_ips.clone();

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

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let hostname = hostname::get()?.to_string_lossy().into_owned();

    let flush_interval = Duration::from_secs(60);
    let mut last_flush = std::time::Instant::now();

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

                    let (fingerprint_ip, is_incoming) = if local_ips.contains(&destination_ip) {
                        (source_ip, true) // Incoming connection
                    } else if local_ips.contains(&source_ip) {
                        (destination_ip, false) // Outgoing connection response
                    } else {
                        continue; // Neither source nor destination is local, skip
                    };

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

                                writeln!(fingerprint_writer, "{}", fingerprint.to_json())?;

                                debug!("Checking fingerprint: {}", fingerprint.muonfp_fingerprint);
                                debug!("Blocked fingerprints: {:?}", config.blocked_fingerprints);

                                if config.blocked_fingerprints.contains(&fingerprint.muonfp_fingerprint) {
                                    info!("Blocked fingerprint detected: {} from IP: {}", 
                                          fingerprint.muonfp_fingerprint, fingerprint.ip_address);
                                    IPBlocker::block_ip(fingerprint.ip_address.to_string());
                                } else {
                                    debug!("Fingerprint not blocked: {}", fingerprint.muonfp_fingerprint);
                                    debug!("Blocked list does not contain this fingerprint");
                                }
                            }
                        }
                    }
                }

                if last_flush.elapsed() >= flush_interval {
                    fingerprint_writer.flush()?;
                    pcap_writer.flush()?;
                    debug!("Current blocked fingerprints: {:?}", config.blocked_fingerprints);
                    last_flush = std::time::Instant::now();
                }
            }
            Err(e) => {
                warn!("Error capturing packet: {}", e);
            }
        }
    }

    info!("Shutting down...");
    fingerprint_writer.flush_and_close()?;
    pcap_writer.flush_and_close()?;

    Ok(())
}