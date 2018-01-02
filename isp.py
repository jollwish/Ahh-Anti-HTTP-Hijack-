from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

PROTO_TCP = 6
PORT_WWW_HTTP = 80
TCP_FIN = 0x01
TCP_SYN = 0x02

MARK = ' ' * 1420

sessions = {}

def callback(pkt):
    try:
        data = IP(pkt.get_payload())
        if data.proto == PROTO_TCP and data.sport == PORT_WWW_HTTP: # incoming
            print(data.summary())
            S = (data.dst, data.dport)
            if data[TCP].flags & TCP_FIN and S in sessions:
                del sessions[S]
            if S in sessions and isinstance(data[TCP].payload, Raw):
               print(len(bytes(data[TCP].payload)))
               data[TCP].payload = bytes(bytes(data[TCP].payload).decode('utf-8').replace('soon', 'sabn'), 'utf-8')
               del data[TCP].chksum
               del data[IP].chksum
               # print(bytes(data))
               pkt.set_payload(bytes(data))
        elif data.proto == PROTO_TCP and data.dport == PORT_WWW_HTTP: # outgoing
            print(data.summary())
            S = (data.src, data.sport)
            if data[TCP].flags == TCP_SYN:
                sessions[S] = 0
            
    except Exception as e:
        print('error')
        print(e)

    pkt.accept()

def main():
    Qnum = 1
    rules = [
        f'iptables -I INPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
        f'iptables -I OUTPUT -j NFQUEUE --queue-num {Qnum} --queue-bypass',
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
