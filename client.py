import os
import threading
import socket
import select

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
	sock = socket.socket()
	sock.bind((PROXY_ADDR, PROXY_PORT))
	sock.listen(BACKLOG)
	print('Start listening.')
	while 1:
		threading.Thread(target = run, args = (sock.accept()[0],)).start()

def main():
	threading.Thread(target = os.system, args = ("polipo socksParentProxy=127.0.0.1:%d proxyPort=%d" % (PROXY_PORT, HTTP_PORT),)).start()
	startProxy()
	
if __name__ == "__main__":
    main()
