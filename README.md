# MuonFP
MuonFP is a TCP passive fingerprinter written in Rust that has no external dependencies such as WireShark or other open source software.  

The program will create an network tap on the interface specified and log all pcaps to a rotating file scheme in the directory of your choice. SYN and SYN-ACK packets that can be fingerprinted will be logged in a separate file and directory of your choice.

# Fingerprint Format
The fingerprint is derived from pseudo-unique setting in the TCP configuration during the SYN and SYN-ACK stages. A fingerprint from these packets will yield the following:

192.168.4.80:26847:2-4-8-1-3:1460:8

This is comprised of the following from the TCP packet header provided during connection negotiation:  

- TCP v4 Address that was fingerprinted  
- TCP Window Size  
- TCP Options as found in the KIND settings that include a number and are kept in strict order as this is quasi unique
- TCP Maximum Segment Size (MSS) which can provide interesting info including use of VPNs
- TCP Window Scale, which is a scaling factor used for TCP Window Size and allows for larger TCP windows

# v.1.1 Update

- Uses muonfp.conf to provide configurable file paths for logging with filesize limits
- Rotating logging
- Converted muonfp fingerprinting output to json single line delimited format, added timestamp field
- Refactored code files to ease maintenance

# Install Instructions (example in Debian)

mkdir muonfp  
cd muonfp  
     Download the zip file and extract    
     curl -O -L https://github.com/sundruid/muonfp/releases/download/DebianV.1.1/muonfp_deb_v_1_1.zip  
     tar -xvf muonfp_deb_v_1_1.tar.gz  
   
vi muonfp_deb_v_1_1

    interface=en0      # do an 'ip addr show' to find interface name
    fingerprints=.     # your directory of choice
    pcap=.             # your directory of choice, you can send to /dev/null if you do not want pcaps
    max_file_size=100  # max file size before log rotation occurs in MB

Esc, :, x, Enter. 

    sudo ./muonfp_deb_v_1_1 &       # & on the end will put it into the background. Logging out will kill process. Install as service to keep alive.
