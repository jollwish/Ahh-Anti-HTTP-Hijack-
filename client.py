import os
import struct
import threading
import socket
import select

from scapy.all import ETH_P_ALL
from scapy.all import MTU

PROXY_ADDR = "0.0.0.0"
HTTP_PORT = 1082
PROXY_PORT = 8123
BACKLOG = 50
BIND_ADDR = "0.0.0.0"
BIND_PORT = 0
RECV_SIZE = 65536
SEND_SIZE = 50
TIMEOUT = 10

def ready_recv(sock):
	sock.setblocking(0)
	ready = select.select([sock], [], [], TIMEOUT)
	if ready[0]:
		return sock.recv(RECV_SIZE)

def pipe_recv(peer, remote):
	#print('start recv')
	while 1:
		buffer = ready_recv(remote)
		if not buffer:
			break
		print('received %d bytes' % len(buffer))
		peer.sendall(buffer)
	peer.close()
	remote.close()

def pipe_send(peer, remote):
	#print('start send')
	buffer = peer.recv(RECV_SIZE)
	print('sending %d bytes' % len(buffer))
	for i in range(0, len(buffer), SEND_SIZE):
		remote.sendall(buffer[i : i+SEND_SIZE])
	while 1:
		buffer = ready_recv(peer)
		if not buffer:
			break
		print('sending %d bytes' % len(buffer))
		remote.sendall(buffer)
	peer.close()
	remote.close()
	
def run(peer):
	
	#Authentication
	ver = peer.recv(1)
	nmethods = peer.recv(1)[0]
	for i in range(nmethods):
		method = peer.recv(1)
	peer.sendall(b'\x05\x00')
	
	print('Authentication succeeded.')
	
	#Connection
	ver = peer.recv(1)
	cmd = peer.recv(1)
	rsv = peer.recv(1)
	atyp = peer.recv(1)[0]
	if atyp == 1: 
		dst_addr = '%d.%d.%d.%d' % tuple(peer.recv(4))
	elif atyp == 3:
		len = peer.recv(1)[0]
		domain_name = peer.recv(len).decode('iso-8859-1')
		#print(domain_name)
		dst_addr = socket.gethostbyname(domain_name)
	dst_port = peer.recv(1)[0] << 8 | peer.recv(1)[0]
	
	print('Connecting to %s:%d' % (dst_addr, dst_port))
	
	remote = socket.socket()#(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	remote.bind((BIND_ADDR, BIND_PORT))
	remote.connect((dst_addr,dst_port))
	peer.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
	
	threading.Thread(target = pipe_send, args = (peer, remote)).start()
	pipe_recv(peer, remote)
	
	print('End Connection')
	
def startProxy():
	proxy = socket.socket()
	proxy.bind((PROXY_ADDR, PROXY_PORT))
	proxy.listen(BACKLOG)
	
	sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
	sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
	sniffer.bind(('eth0', ETH_P_ALL))
	
	print('Start listening.')
	while 1:
		thread_proxy = threading.Thread(target = run, args = (proxy.accept()[0],))
		thread_proxy.start()
		standard_ttl = -1
		while thread_proxy.is_alive():
			pkt, sa_ll = sniffer.recvfrom(MTU)
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
			
			if sa_ll[2] != socket.PACKET_OUTGOING and ttl != standard_ttl:
			#	print("incoming - src=%s, dst=%s, frame len = %d, TTL = %d"
			#	%(socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst), iplen, ttl))
				if standard_ttl == -1:
					standard_ttl = ttl
				else:
					print("Hijack dected! TTL should be %d instaed of %d" % (standard_ttl, ttl))

def is_local(packed_ip):
	return packed_ip >> 24 == 10

def main():
	threading.Thread(target = os.system, args = ("polipo socksParentProxy=127.0.0.1:%d proxyPort=%d" % (PROXY_PORT, HTTP_PORT),)).start()
	startProxy()
	
if __name__ == "__main__":
    main()
