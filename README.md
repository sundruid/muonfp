![muonfp_logo](https://github.com/user-attachments/assets/ec3a4b97-ddd0-4b12-b6bd-d02954d46c64)

# Overview:  
MuonFP is an open-source tool designed for TCP fingerprinting, enabling the identification and classification of network traffic based on unique TCP packet characteristics. It is particularly useful for network security professionals and researchers aiming to detect and analyze reconnaissance activities, such as port scanning, by generating and analyzing TCP fingerprints. MuonFP is developed to disrupt the reconnaissance phase of cyber attacks, making it harder for adversaries to gather critical information about network infrastructure.

This tool is part of a broader effort to enhance network security by focusing on the TCP layer (Layer 4) of the OSI model, providing a complementary approach to traditional IP-based blocking methods. MuonFP can be integrated with other security tools, such as firewalls, to block traffic based on identified fingerprints, adding an additional layer of defense against malicious activities.

Read the Whitepaper: ["There is No Such Thing as a 'Benign' Internet Scanner"](https://www.kenwebster.com/index.php/2025/01/29/there-is-no-such-thing-as-a-benign-internet-scanner/)  

# Features:  
- TCP Fingerprint Generation: Generates unique fingerprints based on TCP packet attributes, such as TCP options, window sizes, and sequence numbers.  
- Reconnaissance Detection: Identifies patterns indicative of scanning activities, including those from fast scanners targeting large IP ranges.  
- Integration with Firewalls: Compatible with tools like Fingerprint Firewall (fpfw) for blocking traffic based on MuonFP fingerprints.  
- Legacy Data Support: Allows conversion of legacy TCP fingerprint data (e.g., p0f signatures) into MuonFP-compatible formats for enhanced detection capabilities.  
- Customizable Fingerprint Blocking: Supports wildcard matching for blocking specific fingerprint patterns, enhancing flexibility in security configurations.  
- Cross-Platform Compatibility: Designed to run on various operating systems, including Linux, macOS, and Windows, under the GPL license.  

# Fingerprint Format
The fingerprint is generated from the pseudo-unique configurations within the TCP settings, specifically during the SYN and SYN-ACK handshake stages. This fingerprint, shaped by the underlying operating system and software stack of the manufacturer, creates a distinct signature that can be traced and analyzed for various purposes. These purposes may include network security, device identification, and traffic monitoring, offering a relatively unique identifier that can be used to profile and track devices across different networks.  

Example:  

## **26847:2-4-8-1-3:1460:8**  


This fingerprint is composed of the following elements extracted from the TCP packet header during the connection negotiation process:  

- TCP Window Size  
- TCP Options as found in the KIND settings that include a number and are kept in strict order as this is quasi unique
- TCP Maximum Segment Size (MSS) which can provide interesting info including use of VPNs
- TCP Window Scale, which is a scaling factor used for TCP Window Size and allows for larger TCP windows

# 0.1.4 Update

- Fixed how /dev/null handles pcap log writing
- Added a -uninstall to the install.sh script
  
# 0.1.3 Update

- Uses muonfp.conf to provide configurable file paths for logging with filesize limits
- Rotating logging
- Converted muonfp fingerprinting output to json single line delimited format, added timestamp field
- Refactored code files to ease maintenance

# Install Instructions (example in Debian)

      mkdir muonfp  
      cd muonfp   
      curl -O -L https://github.com/sundruid/muonfp/releases/download/v0.1.4_DEB/muonfp_deb_v_1_4.tar.gz
      tar -xvf muonfp_deb_v_1_4.tar.gz
      sudo ./install.sh
   
/etc/muonfp.conf

    interface=eth0                         # do an 'ip addr show' to find interface name
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
