# Sniffer that sends out UDP packets and either receives a response or doesn't
# Skylar Kooyenga | 4/4/2023 | Python 3.10

import socket
import os

# IP of host we want to listen on
HOST = '192.168.0.1'

# Main function that creates connection to host, and then enters promiscuous mode
# to sniff packets and prints out the data 
def main():
    # Create raw socket, bin to public interface
    # Check to see if host is Windows or Linux
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_ICMP

    # Establish connection
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((HOST, 0))

    # Include the IP header in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Turn on promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    # Read one packet
    print(sniffer.recvfrom(65565))

    # If we're on Windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

# Execute script if run in command line
if __name__ == '__main__':
    main()
