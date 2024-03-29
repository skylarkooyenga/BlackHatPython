# Basic TCP client
# Skylar Kooyenga | 2/7/2023 | Python 3.9
import socket

# choose target and port
target_host = "www.google.com"
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# establish connection
client.connect((target_host, target_port))

# send data
client.send(b"Get / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# receive data
response = client.recv(4096)

print(response.decode())

# close connection
client.close()
