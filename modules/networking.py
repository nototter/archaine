import ipaddress
from re import X
import datetime
import logging
import time
from concurrent.futures.thread import ThreadPoolExecutor
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# importing scapy messes cololr up
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1, ICMP, RandShort, sr, RandMAC, RandIP

"""
stolen from my evolute program
might come up on github eventually
"""

class stats:
    hostsUP = []
    threadsActive = True
    portsClosed = []
    portsOpen = []
    portsFiltered = []

class _Getch:
    """
    Gets a single character from standard input.  Does not echo to the screen.
    also stolen but idk where i got it from
    """
    def __init__(self):
        try:
            self.impl = _GetchWindows()
        except ImportError:
            self.impl = _GetchUnix()

    def __call__(self): return self.impl()


class _GetchUnix:
    def __init__(self):
        import tty, sys

    def __call__(self):
        import sys, tty, termios
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch


class _GetchWindows:
    def __init__(self):
        import msvcrt

    def __call__(self):
        import msvcrt
        return msvcrt.getch()


class essensials:
    def handler():
        """handle enter and ctrl+c"""

        while True:
            getch = _Getch() # getch for enter
            x = getch()

            if x == b'\x03': # ctrl+c
                print("ctrl+c; intterrupting scan...")
                stats.threadsActive = False
                return

class network:
    """
    class of networking stuffs

    !!! EVERYTHING IS FOR LOCAL USE ONLY !!!
    """

    def get_mac(ip):
        # stolen from https://www.geeksforgeeks.org/python-how-to-create-an-arp-spoofer-using-scapy/
        arp_request = ARP(pdst = ip)
        broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc

    class attacks:
        """
        networking attack methods

        TODO: arp man in the middle >> moved to wifi hacking plugin
        TODO: syn, pod, tcp, udp local packet flood (starts getting illegal) >> moved to wifi hacking plugin
        """
            
    class scan:
        class hosts:
            def arp(ip_list:list, spoof, v=True):
                """ARP network scanning"""
                alive = []

                s_ip, s_mac = spoof[0], spoof[1]

                resp = []
                
                for ip in ip_list:
                    if not stats.threadsActive: return False

                    resp.append(time.time())
                    pkt = Ether(dst ="ff:ff:ff:ff:ff:ff", src=s_mac) / ARP(pdst = ip)
                    mac = srp(pkt, timeout = 0.5, verbose = False)
                    resp.append(time.time())

                    try:
                        mac = mac[0][0][1].hwsrc
                        mac = True
                    except:
                        mac = None

                    if mac == None:
                        pass
                    else:
                        print(f"{ip} is active [{str(round(float(resp[1] - resp[0]), 6))}s latency]")
                        alive.append(ip)

                    stats.hostsUP += alive
                    alive = []
                    resp = []

                return alive
            

            def syn(ip_list, spoof, ports=[443, 80, 53, 22, 21], v=False):
                """3-way handshake TCP-SYN network scanning"""

                alive = []
                resp = []

                s_ip, s_mac = spoof[0], spoof[1]

                for ip in ip_list:
                    for port in ports:
                        if not stats.threadsActive: return False

                        resp.append(time.time())
                        try:
                            p = IP(dst=ip, src=s_ip) / TCP(sport=RandShort(), dport=port, flags="S")
                            SYNACK = sr1(p, verbose=0, timeout=0.25)
                        except KeyboardInterrupt:
                            return False
                        resp.append(time.time())

                        if SYNACK == None:
                            continue
                        else:
                            print(f"{ip}:{port} is active [{str(round(float(resp[1] - resp[0]), 6))}s latency]") 
                            alive.append(ip)

                        stats.hostsUP += alive
                        alive.clear()

                return alive
            

            def udp(ip_list, spoof, ports=[443], seq=1888, v=False):
                """UDP network scanning"""
                s_ip, s_mac = spoof[0], spoof[1]

                alive = []
                resp = []

                for ip in ip_list:
                    for port in ports:
                        if not stats.threadsActive: return False

                        resp.append(time.time())
                        pkt = sr1(IP(dst=ip, src=s_ip)/UDP(dport=port), timeout=0.25, verbose=0)
                        resp.append(time.time())

                        if pkt == None:
                            pass
                        else:
                            print(f"{ip}:{port} is active [{str(round(float(resp[1] - resp[0]), 6))}s latency]")
                            alive.append(ip)            

                        stats.hostsUP += alive
                        alive.clear()

                return alive

            def ping(ip_list, spoof, v=False):
                """ICMP network scanning"""
        
                alive = []
                resp = []

                s_ip, s_mac = spoof[0], spoof[1]

                for ip in ip_list:
                    if not stats.threadsActive: return False

                    resp.append(time.time())
                    icmp = IP(ttl=10, dst=ip, src=s_ip)/ICMP()
                    resp.append(time.time())


                    pkt = sr1(icmp, timeout=0.1, verbose=0)
                    
                    if pkt == None:
                        continue
                    else:
                        print(f"{ip} is active [{str(round(float(resp[1] - resp[0]), 6))}s latency]")
                        alive.append(ip)

                    stats.hostsUP += alive
                    alive.clear()

                return alive

        class port:
            def udp(ip, spoof, ports:list):
                """UDP port scanning"""

                open, closed = [], []

                s_ip, s_mac = spoof[0], spoof[1]

                for port in ports:
                    if not stats.threadsActive: return False

                    pkt = sr1(IP(dst=ip, src=s_ip)/UDP(dport=port), timeout=0.25, verbose=0)

                    if pkt == None:
                        closed.append(port)
                    else:
                        print(f"{ip}:{port}/UDP is open")
                        open.append(port)

                    stats.portsOpen += open
                    stats.portsClosed += closed

                    open, closed = [], []

                return open

            def stealth(ip, spoof, ports:list):
                """SYN-STEALTH port scanning"""

                s_ip, s_mac = spoof[0], spoof[1]

                open, closed, filtered = [], [], []

                for port in ports:
                    if not stats.threadsActive: return False

                    x = sr1(IP(dst=ip, src=None)/TCP(sport=RandShort(),dport=port,flags="S"),timeout=1, verbose=0) # main SYN packet

                    if x == None:
                        #print(f"{ip}:{port} is filtered")
                        #filtered.append(port)
                        continue

                    elif x.haslayer(TCP):
                        if x.getlayer(TCP).flags == 0x12:
                            sr(IP(dst=ip, src=None)/TCP(sport=RandShort(),dport=port,flags="R"),timeout=1, verbose=0) # SYN-RST
                            print(f"{ip}:{port}/SYN-TCP is open")
                            open.append(port)

                        elif x.getlayer(TCP).flags == 0x14:
                            closed.append(port)

                    elif x.haslayer(ICMP):
                        if(int(x.getlayer(ICMP).type)==3 and int(x.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                            print(f"{ip}:{port} is filtered")
                            filtered.append(port)

                stats.portsOpen += open
                stats.portsClosed += closed
                stats.portsFiltered += filtered

                open, closed, filtered = [], [], []

                return open

                        

            def tcp(ip, spoof, ports:list):
                """TCP port scanning"""

                open, closed, filtered = [], [], []

                s_ip, s_mac = spoof[0], spoof[1]

                for port in ports:
                    if not stats.threadsActive: return False

                    pkt = sr1(IP(dst=ip, src=s_ip)/TCP(sport=RandShort(), dport=port, flags="S"), timeout=0.075, verbose=0)

                    if pkt == None:
                        closed.append(port)
                    elif pkt.haslayer(TCP):
                        if pkt.getlayer(TCP).flags == 0x12:
                            print(f"{ip}:{port}/TCP is open")

                            sr(IP(dst=ip, src=s_ip)/TCP(sport=RandShort(),dport=port,flags="AR"),timeout=0.075, verbose=0)

                            open.append(port)
                        else:
                            closed.append(port)

                    stats.portsOpen += open
                    stats.portsClosed += closed

                    open, closed = [], []

                return open

            def xmas(ip, spoof, ports:list):
                """XMAS port scanning (reccomended and used by NMAP)"""

                open, closed, filtered = [], [], []

                s_ip, s_mac = spoof[0], spoof[1]

                for port in ports:
                    if not stats.threadsActive: return False

                    x = sr1(IP(dst=ip, src=s_ip)/TCP(dport=port,flags="FPU"),timeout=0.5, verbose=0)

                    if x == None:
                        print(f"{ip}:{port}/TCP is open")
                        open.append(port)

                    elif x.haslayer(TCP):
                        if x.getlayer(TCP).flags == 0x14:
                            closed.append(port)

                        elif x.haslayer(ICMP):
                            if int(x.getlayer(ICMP).type) == 3 and int(X.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                                print(f"{ip}:{port}/TCP is filtered")
                                filtered.append(port)

                    stats.portsOpen += open
                    stats.portsClosed += closed
                    stats.portsFiltered += filtered

                    open, closed, filtered = [], [], []


                return open

            def fin(ip, spoof, ports:list):
                """FIN port scanning (reccomended and used by NMAP)"""

                open, closed, filtered = [], [], []

                s_ip, s_mac = spoof[0], spoof[1]

                for port in ports:
                    if not stats.threadsActive: return False

                    x = sr1(IP(dst=ip, src=s_ip)/TCP(dport=port,flags="F"),timeout=0.5, verbose=0)

                    if x == None:
                        print(f"{ip}:{port}/TCP is open")
                        open.append(port)

                    elif x.haslayer(TCP):
                        if x.getlayer(TCP).flags == 0x14:
                            closed.append(port)
                        
                    elif x.haslayer(ICMP):
                        if int(x.getlayer(ICMP).type)==3 and int(x.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                            print(f"{ip}:{port} is filtered")
                            filtered.append(port)

                    stats.portsOpen += open
                    stats.portsClosed += closed
                    stats.portsFiltered += filtered

                    open, closed, filtered = [], [], []

                return open

            def tcp_window(ip, spoof, ports:list):

                open, closed, filtered = [], [], []
                
                s_ip, s_mac = spoof[0], spoof[1]

                for port in ports:
                    if not stats.threadsActive: return False

                    x = sr1(IP(dst=ip, src=s_ip)/TCP(dport=port,flags="A"),timeout=0.5, verbose=0)

                    if x == None:
                        continue

                    elif x.haslayer(TCP):
                        if x.getlayer(TCP).window == 0:
                            closed.append(port)

                    elif x.getlayer(TCP).window > 0:
                        print(f"{port}/TCP is open")
                        open.append(port)

                    stats.portsOpen += open
                    stats.portsClosed += closed
                    stats.portsFiltered += filtered

                    open, closed, filtered = [], [], []

                return open

def arpHostScan(args:list):

    subnet = [str(ip) for ip in ipaddress.IPv4Network(args[1], False)]
    chunks = []
    threads = int(args[2])
    
    start = datetime.datetime.now()

    print("{} IP addresses to scan (approx. {}s)".format(len(subnet), len(subnet) * 0.125))

    for i in range(0, len(subnet), round(len(subnet) / threads)):
        chunks.append(subnet[i:i+round(len(subnet) / threads)]) # generate ip chunks for each thread

    print("approx. {} IP(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.hosts.arp, l, randomized)

    print("{} hosts up ({}s)".format(len(stats.hostsUP), datetime.datetime.now() - start))

    stats.hostsUP.clear()

def synHostScan(args:list):

    subnet = [str(ip) for ip in ipaddress.IPv4Network(args[1], False)]
    chunks = []
    threads = int(args[2])
    
    start = datetime.datetime.now()

    print("{} IP addresses to scan (approx. {}s)".format(len(subnet), len(subnet) * 0.125))

    for i in range(0, len(subnet), round(len(subnet) / threads)):
        chunks.append(subnet[i:i+round(len(subnet) / threads)]) # generate ip chunks for each thread

    print("approx. {} IP(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.hosts.syn, l, randomized)

    print("{} hosts up ({}s)".format(len(stats.hostsUP), datetime.datetime.now() - start))
    
    stats.hostsUP.clear()

def udpHostScan(args:list):

    subnet = [str(ip) for ip in ipaddress.IPv4Network(args[1], False)]
    chunks = []
    threads = int(args[2])
    
    start = datetime.datetime.now()

    print("{} IP addresses to scan (approx. {}s)".format(len(subnet), len(subnet) * 0.125))

    for i in range(0, len(subnet), round(len(subnet) / threads)):
        chunks.append(subnet[i:i+round(len(subnet) / threads)]) # generate ip chunks for each thread

    print("approx. {} IP(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.hosts.udp, l, randomized)

    print("{} hosts up ({}s)".format(len(stats.hostsUP), datetime.datetime.now() - start))
    
    stats.hostsUP.clear()

def pingHostScan(args:list):

    subnet = [str(ip) for ip in ipaddress.IPv4Network(args[1], False)]
    chunks = []
    threads = int(args[2])
    
    start = datetime.datetime.now()

    print("{} IP addresses to scan (approx. {}s)".format(len(subnet), len(subnet) * 0.125))

    for i in range(0, len(subnet), round(len(subnet) / threads)):
        chunks.append(subnet[i:i+round(len(subnet) / threads)]) # generate ip chunks for each thread

    print("approx. {} IP(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.hosts.ping, l, randomized)

    print("{} hosts up ({}s)".format(len(stats.hostsUP), datetime.datetime.now() - start))
    
    stats.hostsUP.clear()


# ports

def synPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.stealth, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def udpPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.udp, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def tcpPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.tcp, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def xmasPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.xmas, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def finPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.fin, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def tcpWinPortScan(args:list):

    ip = args[1]
    if "-" in args[2]:
        ports = range(int(args[2].split("-")[0]), int(args[2].split("-")[1]) + 1)
    else:
        ports = [int(args[2])]

    chunks = []
    threads = int(args[3])
    
    start = datetime.datetime.now()

    print("{} ports to scan (approx. max {}s)".format(len(ports), len(ports) * 1.375))

    for i in range(0, len(ports), round(len(ports) / threads)):
        chunks.append(ports[i:i+round(len(ports) / threads)]) # generate port chunks for each thread

    print("approx. {} port(s) to check per thread ({} threads)".format(len(chunks[0]), threads))

    randomized = (RandIP(), RandMAC())

    #threading.Thread(target=essensials.handler, daemon=True).start() # start ctrl + c handler

    with ThreadPoolExecutor(max_workers=threads) as executor:
        for l in chunks: executor.submit(network.scan.port.tcp_window, ip, randomized, l)

    print("{} ports up, {} ports closed, {} ports filtered ({}s)".format(len(stats.portsOpen), 
                                                                        len(stats.portsClosed), 
                                                                        len(stats.portsFiltered), 
                                                                        datetime.datetime.now() - start))
    
    stats.portsOpen.clear()
    stats.portsClosed.clear()
    stats.portsFiltered.clear()

def functions():
    """
    put your executable functions here and your configuration
    basically like a if name == main
    put ur imports here maybe
    """

    return (
        [ # executable
            'arpHostScan',
            'synHostScan',
            'udpHostScan',
            'pingHostScan',
            'synPortScan',
            'tcpWinPortScan',
            'finPortScan',
            'xmasPortScan',
            'tcpPortScan',
            'udpPortScan'
        ],  

        { # config
        "arpHostScan": "ARP scan subnet; arpHostScan (subnet) (threads)",
        "synHostScan": "SYN scan subnet; synHostScan (subnet) (threads)",
        "udpHostScan": "UDP scan subnet; udpHostScan (subnet) (threads)",
        "pingHostScan": "ICMP scan subnet; pingHostScan (subnet) (threads)",
        "synPortScan": "SYN-STEALTH port scan IP address; synPortScan (ip) (1-65535 or 80) (threads)",
        'tcpWinPortScan': "TCP-WINDOW port scan IP address; tcpWinPortScan (ip) (1-65535 or 80) (threads)",
        'finPortScan': "TCP-FIN port scan IP address; finPortScan (ip) (1-65535 or 80) (threads)",
        'xmasPortScan': "TCP-XMAS port scan IP address; xmasPortScan (ip) (1-65535 or 80) (threads)",
        'tcpPortScan': "TCP-RAW port scan IP address; tcpPortScan (ip) (1-65535 or 80) (threads)",
        'udpPortScan': "UDP-RAW port scan IP address; udpPortScan (ip) (1-65535 or 80) (threads)",
        }
        )