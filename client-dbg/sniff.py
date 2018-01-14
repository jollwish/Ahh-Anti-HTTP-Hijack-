import socket, struct, os, array
from scapy.all import ETH_P_ALL
from scapy.all import select
from scapy.all import MTU

def is_local(packed_ip):
	return packed_ip >> 24 == 10

sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
sock.bind(('eth0', ETH_P_ALL))

while 1:
	pkt, sa_ll = sock.recvfrom(MTU)
	if len(pkt) <= 0:
		break
	mac_header = struct.unpack("!6s6sH", pkt[0:14])
	if mac_header[2] != 0x800: 
		continue
	
	ip_header = pkt[14:34]
	fields = struct.unpack("!BBHHHBBHII", ip_header)
	
	packed_ip_src = fields[8]
	if is_local(packed_ip_src):
		continue
	iplen = fields[2]
	ttl = fields[5]
	ip_src = ip_header[12:16]
	ip_dst = ip_header[16:20]
	
	if sa_ll[2] != socket.PACKET_OUTGOING:
		print("incoming - src=%s, dst=%s, frame len = %d, TTL = %d"
		%(socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst), iplen, ttl))