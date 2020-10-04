from scapy.all import *

build_filter = "host de origem %s e porta de origem 21"
sniff(iface=iface, prn=callback, filter=build_filter)
