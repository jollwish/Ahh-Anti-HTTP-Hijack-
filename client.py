import os
import struct
import threading
import socket
import select
import traceback
import re
import path
import xml.etree.ElementTree
from logger import getLogger

from email import message_from_file
from io import StringIO
import requests

from scapy.all import ETH_P_ALL
from scapy.all import MTU

logger = getLogger('client')

PROXY_ADDR = "0.0.0.0"
HTTP_PORT = 1082
PROXY_PORT = 8123
BACKLOG = 50
BIND_ADDR = "0.0.0.0"
BIND_PORT = 0
RECV_SIZE = 65536
SEND_SIZE = 50
TIMEOUT = 10

RULES_DIR = './rules'

class YahewRules(object):
    def __init__(self):
        self.ruleset = {}

    def add(self, xml_rule):
        # logger.info(xml_rule)
        root = xml.etree.ElementTree.fromstring(xml_rule)
        rules = []
        for c in root.getchildren():
            if c.tag == 'target':
                host = c.attrib['host']
                self.ruleset[host] = rules
            elif c.tag == 'exclusion':
                rules.append(['EXCL', re.compile(c.attrib['pattern'])])
            elif c.tag == 'rule':
                from_, to_ = c.attrib['from'], c.attrib['to']
                rules.append(['RULE', re.compile(from_), to_.replace('$', '\\')])

    def apply(self, uri, host):
        if host not in self.ruleset:
            return None
        url = f'http://{host}{uri}'
        for rule in self.ruleset[host]:
            if rule[0] == 'EXCL':
                reg = rule[1]
                if reg.match(url):
                    return None
            elif rule[0] == 'RULE':
                from_, to_ = rule[1:]
                url_ = from_.sub(to_, url)
                if url_ != url:
                    logger.info('URL replaced: from %s to %s', url, url_)
                    return url_
        return None

rules = YahewRules()

def ready_recv(sock):
    sock.setblocking(0)
    ready = select.select([sock], [], [], TIMEOUT)
    if ready[0]:
        return sock.recv(RECV_SIZE)

def pipe_recv(peer, remote):
    #logger.info('start recv')
    while 1:
        buffer = ready_recv(remote)
        if not buffer:
            break
        logger.info('received %d bytes', len(buffer))
        peer.sendall(buffer)

def make_HTTPS_request(http_req):
    if http_req[:3] != b'GET':
        return None
    logger.info(http_req)
    req = http_req.decode('utf-8')
    req, headers = req.split('\r\n', 1)
    verb, uri = req.split(' ')[:2]
    headers = message_from_file(StringIO(headers))

    url = rules.apply(uri, headers['Host'])
    if url != None:
        r = requests.request(verb, url, headers=headers)
        # logger.info("verb = %s, url = %s, headers = %s", verb, url, headers)
        # logger.info("r.headers = %s", r.headers)
        content = r.content
        if 'Transfer-Encoding' in r.headers and r.headers['Transfer-Encoding'] == 'chunked':
            content = bytes(hex(len(r.content))[2:].upper(), 'utf-8') + b'\r\n' + content + b'\r\n'
            logger.info('Transfer-Encoding: chunked...')
        response = bytes("HTTP/1.1 %d %s\r\n" % (r.status_code, r.reason) + "".join(["%s: %s\r\n" % (k, v) for k, v in r.headers.items()]) + "\r\n", 'utf-8') + content
        return response
    return None

def pipe_send(peer, remote, buffer):
    #logger.info('start send')
    logger.info('sending %d bytes' % len(buffer))
    for i in range(0, len(buffer), SEND_SIZE):
        remote.sendall(buffer[i : i+SEND_SIZE])
    while 1:
        buffer = ready_recv(peer)
        if not buffer:
            break
        logger.info('sending %d bytes' % len(buffer))
        remote.sendall(buffer)
    

def run(peer):
    
    #Authentication
    ver = peer.recv(1)
    nmethods = peer.recv(1)[0]
    for i in range(nmethods):
        method = peer.recv(1)
    peer.sendall(b'\x05\x00')
    
    logger.info('Authentication succeeded.')
    
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
        #logger.info(domain_name)
        dst_addr = socket.gethostbyname(domain_name)
    dst_port = peer.recv(1)[0] << 8 | peer.recv(1)[0]
    
    
    peer.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
    buffer = peer.recv(RECV_SIZE)

    https_res = make_HTTPS_request(buffer)

    if https_res != None:
        # logger.info('https_res = %s', https_res)
        logger.warning("HTTPS available. Switch to HTTPS...")
        peer.sendall(https_res)
    else:
        logger.info('Connecting to %s:%d' % (dst_addr, dst_port))
        remote = socket.socket()#(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        remote.bind((BIND_ADDR, BIND_PORT))
        remote.connect((dst_addr,dst_port))

        thread = threading.Thread(target = pipe_send, args = (peer, remote, buffer))
        thread.start()
        pipe_recv(peer, remote)

        thread.join()
        remote.close()

    peer.close()
    
    logger.info('End Connection')
    
def startProxy():
    proxy = socket.socket()
    proxy.bind((PROXY_ADDR, PROXY_PORT))
    proxy.listen(BACKLOG)
    
    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sniffer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    sniffer.bind(('eth0', ETH_P_ALL))
    
    logger.info('Start listening.')
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
            #    logger.info("incoming - src=%s, dst=%s, frame len = %d, TTL = %d"
            #    %(socket.inet_ntoa(ip_src), socket.inet_ntoa(ip_dst), iplen, ttl))
                if standard_ttl == -1:
                    standard_ttl = ttl
                else:
                    logger.warning("Hijack dected! TTL should be %d instaed of %d" % (standard_ttl, ttl))

def is_local(packed_ip):
    return packed_ip >> 24 == 10

def main():
    logger.warning('RULE initializing...')
    for fn in os.listdir(RULES_DIR):
        if fn[-4:] != '.xml':
            continue
        fp = os.path.join(RULES_DIR, fn)
        with open(fp) as fd:
            rules.add(fd.read())
    logger.warning('RULE initialized')

    threading.Thread(target = os.system, args = ("polipo socksParentProxy=127.0.0.1:%d proxyPort=%d" % (PROXY_PORT, HTTP_PORT),)).start()
    startProxy()
    
if __name__ == "__main__":
    main()
