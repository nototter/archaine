import modules.plugin as plugin
from os import system
import sys

class colors:
    """
    Module made by @venaxyt on Github
    https://github.com/venaxyt/gratient
    """
    def black(text):
        system(""); faded = ""
        for line in text.splitlines():
            red = 0; green = 0; blue = 0
            for character in line:
                red += 3; green += 3; blue += 3
                if red > 255 and green > 255 and blue > 255:
                    red = 255; green = 255; blue = 255
                faded += (f"\033[38;2;{red};{green};{blue}m{character}\033[0m")
            faded += "\n"
        return faded

    def green(text):
        system(""); faded = ""
        for line in text.splitlines():
            blue = 100
            for character in line:
                blue += 2
                if blue > 255:
                    blue = 255
                faded += (f"\033[38;2;0;255;{blue}m{character}\033[0m")
            faded += "\n"
        return faded

    def blue(text):
        system(""); faded = ""
        for line in text.splitlines():
            green = 0
            for character in line:
                green += 3
                if green > 255:
                    green = 255
                faded += (f"\033[38;2;0;{green};255m{character}\033[0m")
            faded += "\n"
        return faded

    def purple(text):
        system(""); faded = ""
        for line in text.splitlines():
            red = 35
            for character in line:
                red += 3
                if red > 255:
                    red = 255
                faded += (f"\033[38;2;{red};0;220m{character}\033[0m")
            faded += "\n"
        return faded

    def yellow(text):
        system(""); faded = ""
        for line in text.splitlines():
            red = 0
            for character in line:
                if not red > 200:
                    red += 3
                faded += (f"\033[38;2;{red};255;0m{character}\033[0m")
            faded += "\n"
        return faded

    def red(text):
        system(""); faded = ""
        for line in text.splitlines():
            green = 250
            for character in line:
                green -= 5
                if green < 0:
                    green = 0
                faded += (f"\033[38;2;255;{green};0m{character}\033[0m")
            faded += "\n"
        return faded

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
            if q: print("\nctrl+c"); quit()
            else: return False
        return a

class modules:
    """
    built in scripts and stuff
    """
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
        }
    }

    runnable_plugins = []

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
