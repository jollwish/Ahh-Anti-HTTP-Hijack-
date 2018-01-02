from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

def callback1(pkt):
    try:
        data = IP(pkt.get_payload())
        if data.proto == 6 and data[TCP].sport == 80 and isinstance(data[TCP].payload, Raw): # 6 => TCP
           # print(bytes(data))
           data[TCP].payload = bytes(bytes(data[TCP].payload).decode('utf-8').replace('soon', 'sabn'), 'utf-8')
           del data[TCP].chksum
           del data[IP].chksum
           # print(bytes(data))
           pkt.set_payload(bytes(data))
    except Exception as e:
        print('error')
        print(e)

    pkt.accept()

def callback(pkt):
    try:
        data = IP(pkt.get_payload())
        if data.proto == 6 and data.sport != 22 and data.dport != 22:
            print(data.summary())
    except Exception as e:
        print('error', e)
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
