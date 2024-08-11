# muonfp
MuonFP is a TCP passive fingerprinter written in Rust that has no external dependencies such as WireShark or other open source software.

Usage

sudo muonfp eth0

The program will create an network tap on the interface specified and log all pcaps to the packets.pcap file. SYN and SYN-ACK packets that can be fingerprinted will be logged in the muonfp.out file.

# Future Development
Create a config file to use instead of CLI flags
Break pcap files out by size and also consider S3 bucket support and specifying file-directory location
add ability to read pcap files already created and fingerprint from that input source (no tap, or bring your own tap)
