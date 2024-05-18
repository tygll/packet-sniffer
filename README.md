# README for Packet Sniffer #
## Overview ##
This repository contains a Python script for a packet sniffer. A packet sniffer is a tool that captures and analyzes packets that are sent over a network. This script captures Ethernet frames and decodes the IPv4 packets within.

## Features ##
- Capture and decode Ethernet frames.
- Extract and display details of IPv4 packets.
- Decode and display ICMP, TCP, and UDP segments.
- Display the raw data of unknown protocols.

## Prerequisites ##
- Python 3.x
- Root/Administrator privileges (required to create raw sockets)

## Usage ##
1. Clone the repository:
```
git clone https://github.com/yourusername/packet-sniffer.git
cd packet-sniffer
```
2. Run the script with root/administrator privileges:
```
sudo python3 packet_sniffer.py
```

## Script Details ##
### packet_sniffer.py ###
The script consists of the following main parts:
- main(): Sets up a raw socket to capture packets and processes each captured packet.
- ethernet_frame(data): Extracts the Ethernet frame information.
- get_mac_addr(bytes_addr): Converts a MAC address from bytes to a human-readable format.
- ipv4_packet(data): Extracts IPv4 packet information.
- ipv4(addr): Converts an IPv4 address from bytes to a human-readable format.
- icmp_packet(data): Extracts ICMP packet information.
- tcp_segment(data): Extracts TCP segment information.
- udp_segment(data): Extracts UDP segment information.
- format_multiline(prefix, string, size=80): Formats the data for multiline output.
- tab(n, dash=True): Helper function to format tabbed output.

## License ##
This projects is licensed under the MIT License.
