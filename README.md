# NOTICE
only use for educational purposes or networks you are allowed to "hack" in
everything is a work in progress right now

# alpine
a more user friendly (but slightly worse) version of metasploit made in python3

optional modules:
HTTPX (for replicate site function)
flask (for reverse shell download)

# features
WIP fyi
TCP reverse shell w/ a flask server to curl python script
kinda useless cloneSite function to get an endpoint's HTML
also kinda uselss dns + dns-entry function to run a dns server to redirect victims
ARP, SYN, UDP, ICMP-PING host scanning w/ provided subnet
SYN-STEALTH, TCP-WINDOW, TCP-FIN, TCP-XMAS, TCP and UDP port scanning *!LOCAL!* IPv4 address

16 commands (18 if you count the example plugin)

# plugins
follow example.py in the modules folder to make your own plugin
not the best plugin system fyi

# reporting errors
the issue must be with alpine, not a plugin

refer to a plugin's github/developer for issues
1. include what you did
2. show the error (TimeoutError, ConnectionRefusedError, KeyError)
3. what line is it on

to simplify this, just copy and paste the python error and submit it as an issue