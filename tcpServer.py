# Basic multithreaded TCP server
# Skylar Kooyenga 2/16/2023
import socket
import threading

ip = '0.0.0.0'
port = 9998

# begin listening and let up to 5 users queue
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(5)
    print(f'[*] Listening on {ip}:{port}')
# establish connection
    while True:
        client, address = server.accept()
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()

# function to receive connection and send acknowledgment
def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACK')

# run the script if it is executed
if __name__ == '_main_':
    main()
