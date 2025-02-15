from scapy.all import sniff

# Function to process captured packets
def packet_callback(packet):
    print(packet.summary())  

# Sniff packets (first 10 packets)
sniff(prn=packet_callback, count=10)

def packet_callback(packet):
    if packet.haslayer('IP'):
        print(f"Source: {packet['IP'].src} -> Destination: {packet['IP'].dst} | Protocol: {packet['IP'].proto}")

sniff(prn=packet_callback, count=10)