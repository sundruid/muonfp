use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{
    ethernet::EthernetPacket,
    ipv4::Ipv4Packet,
    tcp::TcpFlags,
    Packet,
};
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::net::IpAddr;
use std::process;

fn main() {
    // Parse the command-line arguments to get the network interface
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <network interface>", args[0]);
        process::exit(1);
    }
    let interface_name = &args[1];

    // Find the network interface to use
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .iter()
        .find(|iface| iface.name == *interface_name)
        .unwrap_or_else(|| {
            eprintln!("Error: Network interface {} not found", interface_name);
            process::exit(1);
        });

    // Collect all IP addresses of the local interface
    let local_ips: HashSet<IpAddr> = interface
        .ips
        .iter()
        .map(|ip_network| ip_network.ip())
        .collect();

    // Create a channel to capture packets
    let mut rx = match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => {
            eprintln!("Unhandled channel type");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Error creating datalink channel: {}", e);
            process::exit(1);
        }
    };

    // Create a pcap file to log packets
    let mut pcap_file = File::create("packets.pcap").expect("Failed to create pcap file");
    let mut signatures_file =
        BufWriter::new(File::create("muonfp.out").expect("Failed to create muonfp.out file"));

    // Write the PCAP global header
    let pcap_global_header = pcap_file_header();
    pcap_file
        .write_all(&pcap_global_header)
        .expect("Failed to write global header");

    println!("Listening on interface: {}", interface_name);

    // Capture and log packets
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();

                // Write packet to pcap file with pcap packet header
                let pcap_packet_header = pcap_packet_header(ethernet.packet().len() as u32);
                pcap_file
                    .write_all(&pcap_packet_header)
                    .expect("Failed to write packet header");
                pcap_file
                    .write_all(ethernet.packet())
                    .expect("Failed to write packet data");

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
                            // Extract TCP flags
                            let flags = tcp_payload[13];
                            let is_syn = flags & TcpFlags::SYN as u8 != 0;
                            let is_ack = flags & TcpFlags::ACK as u8 != 0;

                            // Process SYN packets for incoming connections and SYN-ACK for outgoing
                            if (is_incoming && is_syn && !is_ack) || (!is_incoming && is_syn && is_ack) {
                                // Extract TCP window size
                                let window_size = u16::from_be_bytes([tcp_payload[14], tcp_payload[15]]);

                                // Extract TCP options
                                let mut options_str = String::new();
                                let mut mss = String::new();
                                let mut window_scale = String::new();

                                // Calculate the TCP header length
                                let tcp_header_length = ((tcp_payload[12] >> 4) as usize) * 4;
                                let options_slice = &tcp_payload[20..tcp_header_length];

                                let mut i = 0;
                                while i < options_slice.len() {
                                    let kind = options_slice[i];
                                    match kind {
                                        0 => { // End of Options List
                                            options_str.push_str("0-");
                                            break; // End of options
                                        },
                                        1 => { // No Operation
                                            options_str.push_str("1-");
                                            i += 1;
                                        },
                                        2 => { // MSS
                                            if options_slice.len() >= i + 4 {
                                                mss = u16::from_be_bytes([options_slice[i+2], options_slice[i+3]]).to_string();
                                            }
                                            options_str.push_str("2-");
                                            i += 4;
                                        },
                                        3 => { // Window Scale
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
                                                if length < 2 { break; } // Invalid length, stop processing
                                                i += length;
                                            } else {
                                                break; // Not enough data for option length, stop processing
                                            }
                                        },
                                    }
                                }

                                // Remove trailing dash if present
                                options_str = options_str.trim_end_matches('-').to_string();

                                // Format the signature
                                let signature = format!(
                                    "{}:{}:{}:{}:{}\n",
                                    fingerprint_ip,
                                    window_size,
                                    options_str,
                                    mss,
                                    window_scale
                                );

                                // Write signature to file
                                signatures_file
                                    .write_all(signature.as_bytes())
                                    .expect("Failed to write signature");
                                signatures_file.flush().expect("Failed to flush muonfp.out file");
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