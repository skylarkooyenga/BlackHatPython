# Basic UDP client
# Skylar Kooyenga | 2/7/2023 | Python 3.9
import socket

# choose target and port
target_host = "127.0.0.1"
target_port = 9997

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send data
client.sendto(b"AAABBBCCC",(target_host, target_port))

# receive data
data, addr = client.recvfrom(1024)

print(data.decode())

# close connection
client.close()
