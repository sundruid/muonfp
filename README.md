![muonfp_logo](https://github.com/user-attachments/assets/ec3a4b97-ddd0-4b12-b6bd-d02954d46c64)

MuonFP is a TCP passive fingerprinter written in Rust that has no external dependencies such as WireShark or other open source software.  

The program will create an network tap on the interface specified and log all pcaps to a rotating file scheme in the directory of your choice. SYN and SYN-ACK packets that can be fingerprinted will be logged in a separate file and directory of your choice.

# Fingerprint Format
The fingerprint is generated from the pseudo-unique configurations within the TCP settings, specifically during the SYN and SYN-ACK handshake stages. This fingerprint, shaped by the underlying operating system and software stack of the manufacturer, creates a distinct signature that can be traced and analyzed for various purposes. These purposes may include network security, device identification, and traffic monitoring, offering a relatively unique identifier that can be used to profile and track devices across different networks.  

Example:  

## **26847:2-4-8-1-3:1460:8**  


This fingerprint is composed of the following elements extracted from the TCP packet header during the connection negotiation process:  

- TCP Window Size  
- TCP Options as found in the KIND settings that include a number and are kept in strict order as this is quasi unique
- TCP Maximum Segment Size (MSS) which can provide interesting info including use of VPNs
- TCP Window Scale, which is a scaling factor used for TCP Window Size and allows for larger TCP windows
  

# 0.1.3 Update

- Uses muonfp.conf to provide configurable file paths for logging with filesize limits
- Rotating logging
- Converted muonfp fingerprinting output to json single line delimited format, added timestamp field
- Refactored code files to ease maintenance

# Install Instructions (example in Debian)

      mkdir muonfp  
      cd muonfp   
      curl -O -L https://github.com/sundruid/muonfp/releases/download/0.1.3/muonfp013.tar.gz
      tar -xvf muonfp013.tar.gz
      sudo ./install.sh
   
/etc/muonfp.conf

    interface=en0                          # do an 'ip addr show' to find interface name
    fingerprints=/var/log/fingerprints     # your directory of choice
    pcap=/var/log/pcaps                    # your directory of choice, you can set to /dev/null if you do not want pcaps
    max_file_size=10                       # max file size before log rotation occurs in MB

If you do not want to install as a service, do NOT run the install.sh script and instead adjust the .conf file with the locations you want to store data and execute at the CLI.

# Compile instructions

    Install Rust via their instructions:
    https://www.rust-lang.org/tools/install
    
    Clone the repo: 
    git clone https://github.com/sundruid/muonfp.git

    cd into the directory and execute:
    cargo build --release

    Your binary will be target/release/muonfp
    


Interested in a Firewall for fingerprinting? Checkout sundruid/fpfw that will automatically block based on fingerprint using nftables.

sundruid@protonmail.com
