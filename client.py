import socket
import struct
from colorama import Fore, Style
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa

class Encryption:
    def __init__(self):
        # Placeholder for key loading; typically you would load this from the server
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def encrypt_message(self, public_key, message):
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_message(self, private_key, encrypted_message):
        return private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

def send_message(sock, msg_type, message):
    message_encoded = message.encode()
    header = struct.pack('!BI', msg_type, len(message_encoded))
    sock.sendall(header + message_encoded)

def main():
    while True:
        try:
            port = input(f"[+] Enter the port to attempt a connection: ")
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('127.0.0.1', int(port)))
        except Exception:
            print(f"{Fore.RED}[-] Port is either wrong, or the server is offline.{Style.RESET_ALL}")
            continue

        print(f"{Fore.GREEN}[*] Connected to the server!{Style.RESET_ALL}")
        username = input(f"[+] Enter a username: ")
        client_socket.sendall(username.encode())
        input("[+] Press ENTER to exit")

if __name__ == "__main__":
    main()
