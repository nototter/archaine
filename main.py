"""
PLEASE use this for educational purposes ONLY
i am not responsible for your bad deeds
- otter

DEV BRANCH
"""
import modules.plugin as plugin
from os import system
import threading
import logging
from time import sleep
from sys import exit, stdout

log = logging.getLogger('werkzeug')
log.disabled = True

"""
TODO: make wifi hacking plugin (maybe)
TODO: make routersploit type plugin
TODO: make CVE viewer plugin (maybe)
TODO: make vulnerability finder in network plugin (highly doubt but maybe)

>>> TODO: bruteforce suite
"""

class colors:
    """
    Module made by @venaxyt on Github
    https://github.com/venaxyt/gratient
    """

    def bold(text):
        return f"\033[1;m{text}\033[0m"

    def sunset(text):

        # due to scapy messing with ansi colors it will stay like this
        return text 

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

class modules:
    """
    built in scripts and stuff
    """
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
                print("[!] not enough arguments; cloneSite (url) (output file) (proxy (0 for none))")

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
            "help": "download a site's HTML; cloneSite (domain)"
        },
    }

    runnable_plugins = [] # variable name
    rsSite = False # site running bool
    rsAllow = False # allow shutdown
    rsSitePort = None # set previously given site port
    rsSiteNotified = False # for the shutdown thing
    activeThreads = [] # variable name
    TCP_IP = None
    TCP_PORT = None # set our reverse shell vars

if __name__ == "__main__":
    plugins = plugin.load(folder="modules") # load

    print(colors.bold(r"""
                      __                                      
                     /\ \                __                   
    __     _ __   ___\ \ \___      __   /\_\    ___      __   
  /'__`\  /\`'__\/'___\ \  _ `\  /'__`\ \/\ \ /' _ `\  /'__`\ 
 /\ \L\.\_\ \ \//\ \__/\ \ \ \ \/\ \L\.\_\ \ \/\ \/\ \/\  __/ 
 \ \__/.\_\\ \_\\ \____\\ \_\ \_\ \__/.\_\\ \_\ \_\ \_\ \____\
  \/__/\/_/ \/_/ \/____/ \/_/\/_/\/__/\/_/ \/_/\/_/\/_/\/____/
                                                                                    

    a more user friendly (but worse) version of metasploit
                "All for one and one for all!"
    """))

    # to prevent plugins to do funny stuff

    save_stdout = stdout
    stdout = None

    for p in plugins[1]: # for plugin in plugins list
        if len(plugins[1][p][1]) == 0: continue # sanity check
        for executable in plugins[1][p][1]: # for every executable in the plugin's executable list
            sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])] = {} # create dict

            try:
                sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["help"] = plugins[1][p][1][executable].strip() # define help
            except KeyError: # command's help not in configurationfile
                raise KeyError("{}'s command {} doesn't have a help key pair in it's configuration".format(plugins[1][p][0], executable))
            sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["module"] = None # set module as None to show it's not ours

    stdout = save_stdout

    while True:
        c = essensials.sanitized_input("\narchaine#> ", q=False) # q=True to quit if ctrl+c

        if c == False:
            print("\nuse \"exit\" to leave archaine")
            continue

        elif c == "help":
            for module in sysVar.modules: # cycle through each
                a = sysVar.modules[module]['help'] # get all help from modules
                print(f"{module}: {a}")
                continue # go back to input

        elif c == "exit" or c == "quit": exit(0)

        try:
            f = sysVar.modules[c.split(" ")[0]]["module"] # try getting it from built in modules
            args = (c.split(" "),) # set our args

            a = threading.Thread(target=f, args=args, daemon=True) # generate in new thread to prevent errors on main thread
            a.start() # start said thread

            try:
                a.join() # wait for thread to finish
            except KeyboardInterrupt:
                print("ctrl+c") # ctrl+c caught while plugin was running

            continue # back to input

        except KeyError: # if not in modules:
            for p in plugins[1]: # for plugin in plugins list
                for executable in plugins[1][p][1]: # for every executable in the plugin's executable list
                    if c.split(' ')[0] == executable: # if our choice in plugin's executable path
                        plg = plugins[1][p][2] # chosen plugin
                        args = (c.split(' ')[0], c.split(' '), plg) # generate function args

                        a = threading.Thread(target=plugin.function, args=args, daemon=True) # generate in new thread to prevent errors on main thread
                        a.start() # start said thread

                        try:
                            a.join() # wait for thread to finish
                        except KeyboardInterrupt:
                            print("ctrl+c") # ctrl+c caught while plugin was running
