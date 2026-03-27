use config::{Config, File as ConfigFile, FileFormat};
use ctrlc;
use hostname;
use log::{error, info, warn};
use pnet::packet::{
    ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet,
};
use std::env;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

mod fingerprint;
mod network_tap;
mod rotating_writer;

use fingerprint::{extract_tcp_options, is_syn_packet, Fingerprint};
use network_tap::{pcap_global_header, pcap_packet_header, NetworkTap};
use rotating_writer::RotatingFileWriter;

const VERSION: &str = "MuonFP v.1.4.rc5";

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

fn process_tcp_payload(
    hostname: &str,
    local_ips: &std::collections::HashSet<IpAddr>,
    fingerprint_writer: &mut RotatingFileWriter,
    stdout_output: bool,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    tcp_payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let (fingerprint_ip, is_incoming) = if local_ips.contains(&destination_ip) {
        (source_ip, true)
    } else if local_ips.contains(&source_ip) {
        (destination_ip, false)
    } else {
        return Ok(());
    };

    let skip_ip = match fingerprint_ip {
        IpAddr::V4(ip) => ip.is_broadcast() || ip.is_multicast() || ip.is_unspecified(),
        IpAddr::V6(ip) => ip.is_multicast() || ip.is_unspecified(),
    };
    if skip_ip || tcp_payload.len() < 20 {
        return Ok(());
    }

    let flags = tcp_payload[13];
    if is_syn_packet(flags, is_incoming) {
        let window_size = u16::from_be_bytes([tcp_payload[14], tcp_payload[15]]);
        let (options_str, mss, window_scale) = extract_tcp_options(tcp_payload);

        let fingerprint = Fingerprint::new(
            hostname.to_string(),
            fingerprint_ip,
            window_size,
            options_str,
            mss,
            window_scale,
        );

        let json_output = fingerprint.to_json();
        writeln!(fingerprint_writer, "{}", json_output)?;

        if stdout_output {
            println!("{}", json_output);
        }
    }

    Ok(())
}

fn main() {
    // Parse command-line arguments
    let args: Vec<String> = env::args().collect();
    let stdout_output = args.iter().any(|arg| arg == "--stdout" || arg == "-s");

    if args.iter().any(|arg| arg == "--version" || arg == "-v") {
        println!("{}", VERSION);
        return;
    }

    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("MuonFP - open-source TCP fingerprinting");
        println!();
        println!("Usage: muonfp [OPTIONS]");
        println!();
        println!("Options:");
        println!("  -v, --version   Show version information");
        println!("  -s, --stdout    Output JSON fingerprints to stdout immediately");
        println!("  -h, --help      Show this help message");
        println!();
        println!("Configuration is read from /etc/muonfp.conf");
        return;
    }

    env_logger::init();
    info!("{}", VERSION);

    if let Err(e) = run(stdout_output) {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(stdout_output: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = read_config()?;

    // Validate directories
    if !Path::new(&config.fingerprints_dir).is_dir() {
        return Err(format!(
            "Fingerprints directory does not exist: {}",
            config.fingerprints_dir
        )
        .into());
    }

    // Special handling for /dev/null - skip PCAP writing entirely
    let skip_pcap = config.pcap_dir == "/dev/null";
    if !skip_pcap && !Path::new(&config.pcap_dir).is_dir() {
        return Err(format!("PCAP directory does not exist: {}", config.pcap_dir).into());
    }

    let mut network_tap = NetworkTap::new(&config.interface)?;
    let local_ips = network_tap.local_ips.clone();

    // Create rotating writers
    let pcap_global_header = pcap_global_header();
    let mut pcap_writer = if skip_pcap {
        None
    } else {
        Some(RotatingFileWriter::new(
            Path::new(&config.pcap_dir).join("packets"),
            config.max_file_size,
            "pcap",
            move |file| file.write_all(&pcap_global_header),
        )?)
    };
    let mut fingerprint_writer = RotatingFileWriter::new(
        Path::new(&config.fingerprints_dir).join("muonfp"),
        config.max_file_size,
        "out",
        |_| Ok(()),
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
                let mut full_packet =
                    Vec::with_capacity(packet_header.len() + ethernet.packet().len());
                full_packet.extend_from_slice(&packet_header);
                full_packet.extend_from_slice(ethernet.packet());

                // Only write PCAP if not skipping
                if let Some(ref mut writer) = pcap_writer {
                    writer.write_packet(&full_packet)?;
                }

                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                            if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                process_tcp_payload(
                                    &hostname,
                                    &local_ips,
                                    &mut fingerprint_writer,
                                    stdout_output,
                                    IpAddr::V4(ip_packet.get_source()),
                                    IpAddr::V4(ip_packet.get_destination()),
                                    ip_packet.payload(),
                                )?;
                            }
                        }
                    }
                    EtherTypes::Ipv6 => {
                        if let Some(ip_packet) = Ipv6Packet::new(ethernet.payload()) {
                            if ip_packet.get_next_header() == IpNextHeaderProtocols::Tcp {
                                process_tcp_payload(
                                    &hostname,
                                    &local_ips,
                                    &mut fingerprint_writer,
                                    stdout_output,
                                    IpAddr::V6(ip_packet.get_source()),
                                    IpAddr::V6(ip_packet.get_destination()),
                                    ip_packet.payload(),
                                )?;
                            }
                        }
                    }
                    _ => {}
                }

                // Check if we need to flush the writers
                if last_flush.elapsed() >= flush_interval {
                    fingerprint_writer.flush()?;
                    if let Some(ref mut writer) = pcap_writer {
                        writer.flush()?;
                    }
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
    if let Some(mut writer) = pcap_writer {
        writer.flush_and_close()?;
    }

    Ok(())
}
