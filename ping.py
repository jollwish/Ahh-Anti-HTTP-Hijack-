import socket
import time
from scapy.all import *

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 33336))
s.connect(('', 33334))
while True:
    # pkt = IP(src='127.0.0.1', dst='127.0.0.1') / TCP(sport=2222, dport=3333) / '<html><body></body></html>'
    # s.sendto(bytes(pkt), ('127.0.0.1', 0))
    s.send(bytes('<html><body></body></html>', 'utf-8'))
    time.sleep(1)
s.close()
