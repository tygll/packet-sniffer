import socket
import struct
import textwrap

def main():
	try:
		conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
		
		while True:
			raw_data, addr = conn.recvfrom(65535)
			dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
			print("\nEthernet Frame:")
			print(tab(1) + "Destination: {}, Source: {}, Protocol: {}".format(dest_mac, src_mac, eth_proto))
			
			# ethernet protocol 8 -> IPv4
			if eth_proto == 8:
				(version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
				print(tab(1) + "IPv4 Packet:")
				print(tab(2) + "Version: {}, Header length: {}, TTL: {},".format(version, header_length, ttl))
				print(tab(2) + "Protocol: {}, Source: {}, Target: {}".format(proto, src, target,))
				
				#ICMP
				if proto == 1:
					icmp_type, code, checksum, data = icmp_packet(data)
					print(tab(1) + "ICMP Packet:")
					print(tab(2) + "Type: {}, Code: {}, Checksum: {},".format(icmp_type, code, checksum))
					print(tab(2) + "Data:")
					print(format_multiline(tab(3,False), data))
				
				#TCP
				elif proto == 6:
					(src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
					print(tab(1) + "TCP Segment:")
					print(tab(2) + "Source port: {}, Destination port: {}".format(src_port, dest_port))
					print(tab(2) + "Sequence: {}, Acknowledgement: {}".format(sequence, ack))
					print(tab(2) + "Flags:")
					print(tab(3) + "URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}".format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
					print(tab(2) + "Data:")
					print(format_multiline(tab(3,False), data))
				
				#UDP
				elif proto == 17:
					src_port, dest_port, size, data = udp_segment(data)
					print(tab(1) + "UDP Segment:")
					print(tab(2) + "Source port: {}, Destination port: {}, Length: {}".format(src_port, dest_port, size))
				
				#other
				else:
					print(tab(1) + "Data:")
					print(format_multiline(tab(2,False), data))
		
			else:
				print("Data:")
				print(format_multiline(tab(1,False), data))
	except KeyboardInterrupt:
		print(" KeyboardInterrupt")
		quit()

def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack("! 6s 6s H", data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
	bytes_str = map("{:02x}".format, bytes_addr)
	return ':'.join(bytes_str).upper()

def ipv4_packet(data):
	ver_hl = data[0]
	version = ver_hl >> 4
	header_length = (ver_hl & 15) * 4
	ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", data[:20])
	return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
	return '.'.join(map(str, addr))

def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack("! B B H", data[:4])
	return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
	(src_port, dest_port, sequence, ack, offset_res_flags) = struct.unpack("! H H L L H", data[:14])
	offset = (offset_res_flags >> 12) * 4
	flag_urg = (offset_res_flags & 32) >> 5
	flag_ack = (offset_res_flags & 16) >> 4
	flag_psh = (offset_res_flags & 8) >> 3
	flag_rst = (offset_res_flags & 4) >> 2
	flag_syn = (offset_res_flags & 2) >> 1
	flag_fin = offset_res_flags & 1
	return src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
	src_port, dest_port, size = struct.unpack("! H H 2x H", data[:8])
	return src_port, dest_port, size, data[8:]

def format_multiline(prefix, string, size=80):
	size -= len(prefix)
	if isinstance(string, bytes):
		string = ''.join(r"\x{:02x}".format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def tab(n, dash=True):
    if dash:
        return '\t' * n + ' - '
    else:
        return '\t' * n + ' '

main()










