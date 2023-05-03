# IP decoder that uses the struct module
# Skylar Kooyenga | 5/3/2023 | Python 3.10

import ipaddress
import struct

# IP class that finds the high and low order nybble of the packet and saves the relevant IP information to variables
class IP:
    def __init__(self, buff=None):
        header = struct.unpack('BBHHHBBH4s4s', buff)

        # shift bits
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF

        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol = header[6]
        self.sum = header[7]
        self.src = header[8]
        self.dst = header[9]

        # make IP addresses human-readable
        self.src_address = ipaddress.ip_address(self.src)
        self.dst_address = ipaddress.ip_address(self.dst)

        # map protocol constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
