import socket
import threading
import struct
from colorama import Fore, Style
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class Communication:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def handle_client(self, client_socket):        
        while True:
            # Read header
            header = client_socket.recv(5)
            if not header:
                break

            msg_type, length = struct.unpack('!BI', header)
            
            # Read the message
            message = client_socket.recv(length).decode()
            
            # Process the message based on its type
            self.handle_bytes(msg_type, message, client_socket)

    def handle_bytes(self, msg_type, message, client_socket):
        if msg_type == 1:
            print(f"{Fore.GREEN}[*] Received greeting message: {message}{Style.RESET_ALL}")
        elif msg_type == 2:
            print(f"{Fore.GREEN}[*] Received status request: {message}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Unknown message type: {msg_type}{Style.RESET_ALL}")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 9999))
    server_socket.listen(1)
    print(f"[*] Server running on '127.0.0.1:9999'")

    comms = Communication()

    while True:
        client_socket, addr = server_socket.accept()
        print(f"{Fore.GREEN}[*] Connected by {addr}{Style.RESET_ALL}")
        client_thread = threading.Thread(target=comms.handle_client, args=(client_socket,))
        client_thread.start()

if __name__ == "__main__":
    main()
