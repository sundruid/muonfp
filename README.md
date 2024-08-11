# muonfp
MuonFP is a TCP passive fingerprinter written in Rust that has no external dependencies such as WireShark or other open source software.

Usage:

sudo muonfp eth0

The program will create an network tap on the interface specified and log all pcaps to the packets.pcap file. SYN and SYN-ACK packets that can be fingerprinted will be logged in the muonfp.out file.

# Fingerprint format
The fingerprint is derived from pseudo-unique setting in the TCP configuration during the SYN and SYN-ACK stages. A fingerprint from these packets will yield the following:

192.168.4.80:26847:2-4-8-1-3:1460:8

This is comprised of the following from the TCP packet header provided during connection negotiation:  

- TCP v4 Address that was fingerprinted  
- TCP Window Size  
- TCP Options as found in the KIND settings that include a number and are kept in strict order as this is quasi unique
- TCP Maximum Segment Size (MSS) which can provide interesting info including use of VPNs
- TCP Window Scale, which is a scaling factor used for TCP Window Size and allows for larger TCP windows

# Future Development

- Create a config file to use instead of CLI flags  
- Break pcap files out by size and also consider S3 bucket support and specifying file-directory location  
- Add ability to read pcap files already created and fingerprint from that input source (no tap, or bring your own tap)  
