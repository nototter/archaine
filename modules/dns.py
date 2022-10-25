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

    def closeThread(thread):
        try:
            thread.exit()
            return True
        except:
            return False

def dnsStart(args:list):
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

def dnsEntry(args:list):
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

def functions(): 
    return {
        "dnsStart": "start DNSMasq",
        "dnsEntry": "add DNS entry to DNSMasq",
    }