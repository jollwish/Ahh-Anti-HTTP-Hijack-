from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import traceback
import string
import time
from logger import getLogger

logger = getLogger(__name__)

PROTO_TCP = 6
PORT_WWW_HTTP = 80
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_PSH = 0x08
TCP_ACK = 0x10

ENABLE = True

SCRIPT = b'<script>alert("PHP is the best language!");</script>'
SCRIPT_LEN = len(SCRIPT)


sessions = {}
conf.L3socket = L3RawSocket

PKT_ACCEPT = 'accept'
PKT_MODIFY = 'modify'
PKT_REJECT = 'reject'

class Modifier(object):
    def __init__(self):
        pass

    @staticmethod
    def is_http_request(s):
        return s[:3] == b'GET' and s.find(b' HTTP/1.1') != -1

    @staticmethod
    def is_http_response(s):
        return s[:9] == b'HTTP/1.1 '
    
    def send(self, data, sess):
        console.warning('empty handler: send')

    def recv(self, data, sess):
        console.warning('empty handler: recv')

class Redirector(Modifier):
    REDIRECT = b'HTTP/1.1 302 Found\r\nLocation: http://www.google.com\r\n'

    def __init__(self):
        self.drop_PSH = False
        self.monitored = False

    def send(self, data, sess):
        return PKT_REJECT

    def recv(self, data, sess):
        pkt_status = PKT_ACCEPT
        raw = bytes(data[TCP].payload)
        if Modifier.is_http_response(raw):
            pkt_status = PKT_MODIFIED
            data[TCP].payload = Redirector.REDIRECT
            self.drop_PSH = True
        elif self.drop_PSH and data[TCP].flags & TCP_PSH:
            pass
            # send a fake response to server
            
        return pkt_status

class Insertor(Modifier):
    def __init__(self):
        self.offset = 0
        self.threshold = 10**10
        self.monitored = False

    def send(self, data, sess):
        pkt_status = PKT_ACCEPT
        if data[TCP].flags == TCP_ACK | TCP_PSH and Modifier.is_http_request(bytes(data[TCP].payload)):
            self.monitored = True
        logger.info("summary = %s, seq = %s, ack = %s", data.summary(), data.seq - sess['ack_'], data.ack - sess['seq_'])
        # logger.info('send %s', bytes(data[TCP].payload))
        if data[TCP].ack >= self.threshold + len(data[TCP].payload):
            if ENABLE:
                data[TCP].ack -= self.offset
            logger.info(f'modify ack, delta = {-self.offset}, modified results = ({data[TCP].seq- sess["ack_"]}, {data[TCP].ack - sess["seq_"]})')
            pkt_status = PKT_MODIFY
        return pkt_status

    def recv(self, data, sess):
        pkt_status = PKT_ACCEPT
        if data[TCP].seq >= self.threshold:
            if ENABLE:
                data[TCP].seq += self.offset
            logger.info(f'modify seq, delta = {self.offset}, modified results = ({data[TCP].seq - sess["seq_"]}, {data[TCP].ack - sess["ack_"]})')
            pkt_status = PKT_MODIFY

        if self.monitored:
            raw = bytes(data[TCP].payload)
            logger.info("raw = %s", raw)
            
            loc = raw.lower().find(b'</body>')
            if raw:
                logger.info('original data size = %s', len(raw))
            if loc != -1 and self.monitored: # didn't consider the case where '</body>' itself is a string, e.g., "var x = '</body>';".
        
                # find the enclosing </body>
                # should insert script before </body>
                raw = raw[:loc] + SCRIPT + raw[loc:]
                self.offset = SCRIPT_LEN
                self.threshold = data[TCP].seq + self.offset
        
                logger.warning('forging fake packet')
                if ENABLE:
                    data[TCP].payload = raw
                pkt_status = PKT_MODIFY
        
            if raw.find(b'Content-Length:') != -1 and self.monitored:
                loc = raw.find(b'Content-Length:')
                start = loc + 16
                end = start
                length = 0
                while end < len(raw) and 48 <= raw[end] <= 57:
                    length = length * 10 + raw[end] - 48
                    end += 1
                logger.info('length = %s', length)
                length = bytes(str(length + SCRIPT_LEN), 'utf-8')
                if ENABLE:
                    data[TCP].payload = raw[:start] + length + raw[end:]
                pkt_status = PKT_MODIFY
                logger.warning('modified HTTP header')
        return pkt_status

def get_new_modifier():
    return Insertor()

def get_session(ip, port): 
    S = (ip, port) 
    if S in sessions:
        sess = sessions[S]
        # logger.info("recorded time = %s, current = %s", sess['time'], time.perf_counter())
        if sess['time'] < time.perf_counter() - 5:
            del sessions[S]
            logger.warning('invalidate session: %s', S)
            return None
        return sess
    return None

def add_session(ip, port):
    S = (ip, port)
    logger.warning('new session')
    sess = {'FIN_count': 0, 'seq_': 0, 'ack_': 0, 'time': time.perf_counter(), 'modifier': get_new_modifier()}
    sessions[S] = sess

def callback(pkt):
    result = PKT_ACCEPT
    try:
        data = IP(pkt.get_payload())
        if data.proto == PROTO_TCP and data.sport == PORT_WWW_HTTP: # incoming
            # data.show()
            sess = get_session(data.src, data.dport)
            if sess != None and data[TCP].flags == TCP_SYN | TCP_ACK:
                sess['seq_'] = data[TCP].seq
                sess['ack_'] = data[TCP].ack

            if sess != None:

                logger.info("summary = %s, seq = %s, ack = %s", data.summary(), data.seq - sess['seq_'], data.ack - sess['ack_'])
                result = sess['modifier'].recv(data, sess)

                if data[TCP].flags & TCP_FIN:
                    sess['FIN_count'] += 1

        elif data.proto == PROTO_TCP and data.dport == PORT_WWW_HTTP: # outgoing, client -> server
            if data[TCP].flags == TCP_SYN:
               add_session(data.dst, data.sport)
            sess = get_session(data.dst, data.sport)
            if sess != None:
                result = sess['modifier'].send(data, sess)
            
    except:
        logger.info('error')
        traceback.print_exc()
    
    if ENABLE:
        if result == PKT_MODIFY:
            del data[TCP].chksum
            del data.len
            del data[IP].chksum
            pkt.set_payload(bytes(data))
            pkt.accept()
        elif result == PKT_REJECT:
            pkt.reject()
        else:
            pkt.accept()
    else:
        pkt.accept()


def main():
    os.system('iptables -F')
    os.system('iptables -X')

    Qnum = 1
    rules = [
        f'iptables -I INPUT -j NFQUEUE ! -s 127.0.0.1 ! -d 127.0.0.1 --queue-num {Qnum} --queue-bypass',
        f'iptables -I OUTPUT -j NFQUEUE ! -s 127.0.0.1 ! -d 127.0.0.1 --queue-num {Qnum} --queue-bypass',
        # f'iptables -I FORWARD -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        # f'iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP',
    ]
    for rule in rules:
        logger.info(f'setting rule: {rule}')
        os.system(rule)

    os.system("sysctl net.ipv4.ip_forward=1")

    q = NetfilterQueue()
    q.bind(Qnum, callback)
    try:
        q.run()
    except KeyboardInterrupt:
        pass
    q.unbind()

if __name__ == "__main__":
    main()
