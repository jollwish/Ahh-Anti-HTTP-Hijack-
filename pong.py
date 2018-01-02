import socket
import datetime

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# s.bind((host, 0))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('', 33334))
s.listen(1)
conn, addr = s.accept()
while 1:
    data = conn.recv(1024)
    if not data: break
    T = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S,%f')
    print(f'{T}: {data.decode("utf-8")}')
conn.close()
