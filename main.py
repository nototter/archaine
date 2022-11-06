"""
PLEASE use this for educational purposes ONLY
i am not responsible for your bad deeds
- otter
"""
import modules.plugin as plugin
from os import system
import threading
import logging
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


class sysVar:
    """
    system variables
    """
    modules = {}

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
                sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["help"] = (plugins[1][p][1][executable].strip(), plugins[1][p][0]) # define help
            except KeyError: # command's help not in configurationfile
                raise KeyError("{}'s command {} doesn't have a help key pair in it's configuration".format(plugins[1][p][0], executable))
            sysVar.modules["{} ({}'s plugin)".format(executable, plugins[1][p][0])]["module"] = None # set module as None to show it's not ours

    stdout = save_stdout

    while True:
        c = essensials.sanitized_input("\narchaine#> ", q=False) # q=True to quit if ctrl+c

        if c == False:
            print("\nuse \"exit\" to leave archaine")
            continue

        elif c.split(" ")[0] == "help":
            try:
                abc = c.split(" ")[1] # try to get first arg
            except IndexError:
                abc = None # no args given

            if abc is None:
                for module in sysVar.modules: # cycle through each
                    a = sysVar.modules[module]['help'][0] # get all help from modules
                    print(f"{module}: {a}")
                    continue # go back to input
            else:
                for module in sysVar.modules: # cycle through each
                    help = sysVar.modules[module]['help'][0] # get all help from modules
                    parent = sysVar.modules[module]['help'][1] # get all help from modules

                    if c.split(" ")[1] == parent: # if its what we're looking for
                        print(f"{module}: {help}")
                        continue
                    else:
                        if c.split(" ")[1].strip(".py") == parent.strip(".py"): # if its what we're looking for but just without the .py
                            print(f"{module}: {help}")
                            continue
                        else:
                            pass # no exist

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
