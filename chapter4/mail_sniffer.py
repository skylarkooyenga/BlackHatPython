# basic mail sniffer tool that uses scapy tool to capture messages sent over mail protocols
# Skylar Kooyenga | 5/15/2023 | Python 3.10

from scapy.all import sniff, TCP, IP

# The packet callback
def packet_callback(packet):
    if packet[TCP].payload:
        mypacket= str(packet[TCP].payload)
        if 'user' in mypacket.lower() or 'pass' in mypacket.lower():
            print(f"[*] Destination: {packet[IP].dst}")
            print(f"[*] {str(packet[TCP].payload)}")

def main():
    # start the sniffer
    sniff(filter='tcp port 110 or tcp port 25 or tcp port 143',
          prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
